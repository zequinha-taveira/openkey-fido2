//! PIN/UV auth protocol (CTAP 2.1 §6.5.6/§6.5.7) — criptografia de PIN.
//!
//! Implementa os dois protocolos de autenticação de PIN do CTAP 2.1:
//!
//! - **Protocolo 1**: `kdf(Z) = SHA-256(Z)`, AES-256-CBC com IV zero e
//!   autenticação por HMAC-SHA-256 truncado aos primeiros 16 bytes.
//! - **Protocolo 2**: `kdf(Z) = HKDF(hmac) || HKDF(aes)` (64 bytes, infos
//!   `CTAP2 HMAC key` / `CTAP2 AES key`, salt de 32 bytes zero), AES-256-CBC
//!   com IV aleatório prefixado ao ciphertext e HMAC-SHA-256 completo.
//!
//! Ambos usam acordo de chaves P-256 (ECDH) via `ring`; o segredo efêmero `Z`
//! é a coordenada x do ponto compartilhado (32 bytes, big-endian).

use aes::cipher::generic_array::typenum::U16;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes256;
use alloc::vec;
use alloc::vec::Vec;
use cbc::{Decryptor, Encryptor};
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{compiler_fence, Ordering};
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256};
use ring::digest;
use ring::hkdf::{self, HKDF_SHA256};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

extern crate alloc;

/// Tamanho da coordenada x do ponto compartilhado ECDH (P-256).
pub const ECDH_SHARED_SECRET_LEN: usize = 32;
/// Tamanho do bloco AES e do IV usado pelo protocolo.
pub const AES_BLOCK_LEN: usize = 16;
/// Tamanho do plaintext preenchido de PINs (máx. 63 bytes + 1 de padding).
pub const PIN_PAD_LEN: usize = 64;

type Error = Box<dyn std::error::Error>;

/// Wrapper que zera o conteúdo sensível ao ser dropado.
pub struct Zeroizing<T: AsMut<[u8]>>(T);

impl<T: AsMut<[u8]>> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        for byte in self.0.as_mut() {
            *byte = 0;
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl<T: AsMut<[u8]>> Deref for Zeroizing<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: AsMut<[u8]>> DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: AsMut<[u8]>> Zeroizing<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }
}

/// Chave efêmera de acordo P-256 gerada pelo autenticador por request.
///
/// Nunca deve ser reutilizada entre requests: cada transação de
/// `authenticatorClientPIN` exige um par novo (CTAP 2.1 §6.5.5.4).
pub struct PinAgreementKey(EphemeralPrivateKey);

impl core::fmt::Debug for PinAgreementKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PinAgreementKey([redacted])")
    }
}

impl PinAgreementKey {
    /// Gera um par de chaves P-256 fresco via `ring`.
    pub fn generate() -> Result<Self, Error> {
        let rng = SystemRandom::new();
        let private_key = EphemeralPrivateKey::generate(&ECDH_P256, &rng)
            .map_err(|e| format!("Failed to generate P-256 agreement key: {:?}", e))?;
        Ok(Self(private_key))
    }

    /// Retorna a chave pública em formato SEC1 não-comprimido
    /// (`0x04 || x || y`, 65 bytes), como esperado por `ring`.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, Error> {
        let public_key = self
            .0
            .compute_public_key()
            .map_err(|e| format!("Failed to compute P-256 public key: {:?}", e))?;
        Ok(public_key.as_ref().to_vec())
    }

    /// Computa ECDH com a chave pública do par (SEC1 não-comprimido, 65 bytes)
    /// e retorna `Z`: a coordenada x do ponto compartilhado (32 bytes).
    ///
    /// Consome a chave privada, forçando um par novo a cada transação
    /// (CTAP 2.1 §6.5.5.4: nunca reutilizar a chave de acordo entre requests).
    pub fn agree(self, peer_public_key: &[u8]) -> Result<Vec<u8>, Error> {
        if peer_public_key.len() != 65 {
            return Err(format!(
                "P-256 public key must be 65 bytes (uncompressed), got {}",
                peer_public_key.len()
            )
            .into());
        }
        let peer_key = UnparsedPublicKey::new(&ECDH_P256, peer_public_key);
        agreement::agree_ephemeral(self.0, &peer_key, |key_material| key_material.to_vec())
            .map_err(|e| format!("ECDH agreement failed: {:?}", e).into())
    }
}

/// Instância concreta de um protocolo PIN/UV (1 ou 2).
///
/// Encapsula KDF, cifra e autenticação conforme CTAP 2.1 §6.5.6/§6.5.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinUvProtocol {
    version: u8,
}

impl PinUvProtocol {
    /// Cria a instância do protocolo `version`; falha se não suportado (1 ou 2).
    pub fn new(version: u8) -> Result<Self, Error> {
        match version {
            1 | 2 => Ok(Self { version }),
            other => Err(format!("Unsupported pinUvAuthProtocol: {}", other).into()),
        }
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    /// Aplica o KDF do protocolo a `Z` (coordenada x do ECDH).
    ///
    /// - Protocolo 1: SHA-256(Z) → 32 bytes (chave de cifra e de HMAC).
    /// - Protocolo 2: HKDF(hmac, 32B) || HKDF(aes, 32B) → 64 bytes.
    pub fn kdf(&self, z: &[u8]) -> Result<Vec<u8>, Error> {
        if self.version == 1 {
            Ok(digest::digest(&digest::SHA256, z).as_ref().to_vec())
        } else {
            let hmac_key = hkdf_sha256(z, &[0u8; 32], b"CTAP2 HMAC key", 32)?;
            let aes_key = hkdf_sha256(z, &[0u8; 32], b"CTAP2 AES key", 32)?;
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&hmac_key);
            combined.extend_from_slice(&aes_key);
            Ok(combined)
        }
    }

    /// Cifra `plaintext` (múltiplo de 16 bytes, sem padding automático).
    ///
    /// - Protocolo 1: AES-256-CBC com chave `shared_secret` e IV zero.
    /// - Protocolo 2: AES-256-CBC com a metade AES de `shared_secret`
    ///   (64 bytes) e IV aleatório de 16 bytes prefixado ao ciphertext.
    pub fn encrypt(&self, shared_secret: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        if plaintext.len() % AES_BLOCK_LEN != 0 {
            return Err(format!(
                "Plaintext must be a multiple of {} bytes, got {}",
                AES_BLOCK_LEN,
                plaintext.len()
            )
            .into());
        }
        if self.version == 1 {
            if shared_secret.len() != 32 {
                return Err("Protocol 1 shared secret must be 32 bytes".into());
            }
            aes256_cbc_encrypt(shared_secret, &[0u8; AES_BLOCK_LEN], plaintext)
        } else {
            if shared_secret.len() != 64 {
                return Err("Protocol 2 shared secret must be 64 bytes".into());
            }
            let rng = SystemRandom::new();
            let mut iv = [0u8; AES_BLOCK_LEN];
            rng.fill(&mut iv)
                .map_err(|e| format!("Failed to generate IV: {:?}", e))?;
            let mut ciphertext = Vec::with_capacity(AES_BLOCK_LEN + plaintext.len());
            ciphertext.extend_from_slice(&iv);
            ciphertext.extend_from_slice(&aes256_cbc_encrypt(
                &shared_secret[32..],
                &iv,
                plaintext,
            )?);
            Ok(ciphertext)
        }
    }

    /// Decifra um ciphertext produzido por [`PinUvProtocol::encrypt`].
    pub fn decrypt(&self, shared_secret: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if self.version == 1 {
            if shared_secret.len() != 32 {
                return Err("Protocol 1 shared secret must be 32 bytes".into());
            }
            aes256_cbc_decrypt(shared_secret, &[0u8; AES_BLOCK_LEN], ciphertext)
        } else {
            if shared_secret.len() != 64 {
                return Err("Protocol 2 shared secret must be 64 bytes".into());
            }
            if ciphertext.len() < AES_BLOCK_LEN {
                return Err("Protocol 2 ciphertext too short to contain an IV".into());
            }
            let (iv, ct) = ciphertext.split_at(AES_BLOCK_LEN);
            aes256_cbc_decrypt(&shared_secret[32..], iv, ct)
        }
    }

    /// Computa o MAC de autenticação do protocolo.
    ///
    /// - Protocolo 1: primeiros 16 bytes de HMAC-SHA-256(key, message).
    /// - Protocolo 2: HMAC-SHA-256 completo; se `key` tiver mais de 32 bytes,
    ///   apenas a primeira metade (chave HMAC) é usada.
    pub fn authenticate(&self, key: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
        let (hmac_key, truncate) = if self.version == 1 {
            if key.len() != 32 {
                return Err("Protocol 1 authentication key must be 32 bytes".into());
            }
            (key, true)
        } else {
            if key.len() < 32 {
                return Err("Protocol 2 authentication key too short".into());
            }
            (&key[..32], false)
        };
        let signing_key = hmac::Key::new(hmac::HMAC_SHA256, hmac_key);
        let tag = hmac::sign(&signing_key, message);
        let tag = tag.as_ref();
        if truncate {
            Ok(tag[..16].to_vec())
        } else {
            Ok(tag.to_vec())
        }
    }

    /// Verifica um MAC em tempo constante (CTAP 2.1 §6.5.6/§6.5.7 `verify`).
    pub fn verify(&self, key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, Error> {
        let expected = self.authenticate(key, message)?;
        Ok(crate::crypto::constant_time_eq(&expected, signature))
    }
}

/// Deriva bytes com HKDF-SHA256 (RFC 5869), encapsulando `ring::hkdf`.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, Error> {
    let salt = hkdf::Salt::new(HKDF_SHA256, salt);
    let prk = salt.extract(ikm);
    let infos = [info];
    let okm = prk
        .expand(&infos, OkmLen(len))
        .map_err(|e| format!("HKDF expand failed: {:?}", e))?;
    let mut out = vec![0u8; len];
    okm.fill(&mut out)
        .map_err(|e| format!("HKDF fill failed: {:?}", e))?;
    Ok(out)
}

/// Comprimento de saída solicitado ao HKDF.
struct OkmLen(usize);

impl hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// AES-256-CBC bruto (sem padding) — o protocolo CTAP2 exige plaintexts
/// múltiplos do bloco e nunca adiciona padding (CTAP 2.1 §6.5.6/§6.5.7).
pub fn aes256_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != 32 {
        return Err("AES-256 key must be 32 bytes".into());
    }
    if iv.len() != AES_BLOCK_LEN {
        return Err("AES IV must be 16 bytes".into());
    }
    if data.len() % AES_BLOCK_LEN != 0 {
        return Err("AES-CBC input must be a multiple of 16 bytes".into());
    }
    let mut buf = data.to_vec();
    let mut cipher =
        Encryptor::<Aes256>::new(GenericArray::from_slice(key), GenericArray::from_slice(iv));
    for chunk in buf.chunks_exact_mut(AES_BLOCK_LEN) {
        let block: &mut GenericArray<u8, U16> = GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block_mut(block);
    }
    Ok(buf)
}

/// AES-256-CBC bruto (sem padding), decifrando dados de
/// [`aes256_cbc_encrypt`].
pub fn aes256_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != 32 {
        return Err("AES-256 key must be 32 bytes".into());
    }
    if iv.len() != AES_BLOCK_LEN {
        return Err("AES IV must be 16 bytes".into());
    }
    if data.len() % AES_BLOCK_LEN != 0 {
        return Err("AES-CBC input must be a multiple of 16 bytes".into());
    }
    let mut buf = data.to_vec();
    let mut cipher =
        Decryptor::<Aes256>::new(GenericArray::from_slice(key), GenericArray::from_slice(iv));
    for chunk in buf.chunks_exact_mut(AES_BLOCK_LEN) {
        let block: &mut GenericArray<u8, U16> = GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block_mut(block);
    }
    Ok(buf)
}

/// Preenche `data` à direita com zeros até 64 bytes (formato `paddedPin`
/// do CTAP 2.1 §6.5.5.5). `data` não pode exceder 64 bytes.
pub fn zero_pad_to_64(data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() > PIN_PAD_LEN {
        return Err(format!("PIN is {} bytes, exceeding the 63-byte limit", data.len()).into());
    }
    let mut padded = vec![0u8; PIN_PAD_LEN];
    padded[..data.len()].copy_from_slice(data);
    Ok(padded)
}

/// Remove zeros à direita de um plaintext decifrado (inverso do padding do
/// CTAP 2.1). Retorna `Err` se o input estiver vazio (sem conteúdo real).
pub fn strip_zero_padding(data: &[u8]) -> Result<Vec<u8>, Error> {
    let end = data
        .iter()
        .rposition(|b| *b != 0)
        .map(|i| i + 1)
        .ok_or("Plaintext is entirely zero padding")?;
    Ok(data[..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vetores de teste determinísticos gerados com python-fido2 2.2.1
    // (`fido2.ctap2.pin.PinProtocolV1`/`V2` + `cryptography`):
    //
    //   z = bytes(range(1, 33))
    //   v1 kdf        = sha256(z)                        (hex abaixo)
    //   v2 hmac key   = HKDF-SHA256(salt=0*32, ikm=z, info="CTAP2 HMAC key")
    //   v2 aes key    = HKDF-SHA256(salt=0*32, ikm=z, info="CTAP2 AES key")
    //   msg = b"test message"
    const Z: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    const V1_KDF_EXPECTED: [u8; 32] = [
        0xae, 0x21, 0x6c, 0x2e, 0xf5, 0x24, 0x7a, 0x37, 0x82, 0xc1, 0x35, 0xef, 0xa2, 0x79, 0xa3,
        0xe4, 0xcd, 0xc6, 0x10, 0x94, 0x27, 0x0f, 0x5d, 0x2b, 0xe5, 0x8c, 0x62, 0x04, 0xb7, 0xa6,
        0x12, 0xc9,
    ];
    const V2_HMAC_KEY_EXPECTED: [u8; 32] = [
        0x9e, 0xb6, 0x85, 0xea, 0x1b, 0xd7, 0x95, 0xe0, 0x5c, 0xbf, 0xbe, 0x28, 0xf0, 0xef, 0x46,
        0xf1, 0xb8, 0x9a, 0xe3, 0xa7, 0x31, 0x61, 0xc4, 0xd6, 0x4d, 0x11, 0x81, 0x08, 0x2e, 0x82,
        0xdb, 0x67,
    ];
    const V2_AES_KEY_EXPECTED: [u8; 32] = [
        0xe5, 0x6b, 0x82, 0x39, 0x8c, 0xbb, 0x09, 0xe2, 0xa1, 0xb5, 0x46, 0x80, 0x8a, 0x71, 0x6b,
        0xef, 0xa7, 0x90, 0x7d, 0x17, 0x97, 0x6b, 0x72, 0x19, 0x3c, 0x6f, 0x90, 0x94, 0x13, 0xc7,
        0x31, 0x84,
    ];

    #[test]
    fn test_v1_kdf_vector() {
        let proto = PinUvProtocol::new(1).unwrap();
        assert_eq!(proto.kdf(&Z).unwrap(), V1_KDF_EXPECTED);
    }

    #[test]
    fn test_v2_kdf_vector() {
        let proto = PinUvProtocol::new(2).unwrap();
        let kdf = proto.kdf(&Z).unwrap();
        assert_eq!(kdf.len(), 64);
        assert_eq!(&kdf[..32], &V2_HMAC_KEY_EXPECTED[..]);
        assert_eq!(&kdf[32..], &V2_AES_KEY_EXPECTED[..]);
    }

    #[test]
    fn test_hkdf_sha256_vector() {
        let out = hkdf_sha256(&Z, &[0u8; 32], b"CTAP2 HMAC key", 32).unwrap();
        assert_eq!(out, V2_HMAC_KEY_EXPECTED);
    }

    #[test]
    fn test_authenticate_v1_truncates_16() {
        let proto = PinUvProtocol::new(1).unwrap();
        let mac = proto
            .authenticate(&V1_KDF_EXPECTED, b"test message")
            .unwrap();
        assert_eq!(mac.len(), 16);
        // Vetor externo: HMAC-SHA256(key=v1_kdf, "test message")[:16]
        assert_eq!(
            mac,
            [
                0x05, 0x60, 0xb4, 0xab, 0xa4, 0x9d, 0x97, 0x64, 0xee, 0x7d, 0x62, 0xcc, 0x07, 0x07,
                0x27, 0xf9,
            ]
        );
        assert!(proto
            .verify(&V1_KDF_EXPECTED, b"test message", &mac)
            .unwrap());
        assert!(!proto.verify(&V1_KDF_EXPECTED, b"tampered", &mac).unwrap());
    }

    #[test]
    fn test_authenticate_v2_full_hmac_uses_first_32_key_bytes() {
        let proto = PinUvProtocol::new(2).unwrap();
        let mut key64 = [0u8; 64];
        key64[..32].copy_from_slice(&V2_HMAC_KEY_EXPECTED);
        key64[32..].copy_from_slice(&V2_AES_KEY_EXPECTED);
        let mac = proto.authenticate(&key64, b"test message").unwrap();
        assert_eq!(mac.len(), 32);
        // Vetor externo: HMAC-SHA256(key=v2_hmac_key, "test message")
        assert_eq!(
            mac,
            [
                0xcc, 0x0b, 0x10, 0x53, 0x6a, 0xf5, 0x40, 0x30, 0x5e, 0xf2, 0x06, 0x70, 0xdf, 0xd9,
                0x1b, 0xfa, 0xf2, 0x30, 0x4f, 0x7d, 0xe9, 0x67, 0x0a, 0xd0, 0x38, 0x37, 0x18, 0xf3,
                0xe7, 0xd7, 0xf3, 0x93,
            ]
        );
        assert_eq!(
            mac,
            proto
                .authenticate(&V2_HMAC_KEY_EXPECTED, b"test message")
                .unwrap()
        );
        assert!(proto.verify(&key64, b"test message", &mac).unwrap());
    }

    #[test]
    fn test_encrypt_decrypt_v1_roundtrip_zero_iv() {
        let proto = PinUvProtocol::new(1).unwrap();
        let plaintext = b"0123456789abcdef";
        let ct = proto.encrypt(&V1_KDF_EXPECTED, plaintext).unwrap();
        assert_eq!(ct.len(), 16);
        // Vetor externo: AES-256-CBC(key=v1_kdf, iv=0*16, "0123456789abcdef")
        let expected = [
            0x5b, 0x43, 0x93, 0x57, 0xd9, 0x92, 0x99, 0x4c, 0x20, 0x43, 0xd5, 0xc2, 0x05, 0xb2,
            0x1e, 0xa6,
        ];
        assert_eq!(ct, expected);
        assert_eq!(proto.decrypt(&V1_KDF_EXPECTED, &ct).unwrap(), plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_v2_roundtrip_iv_prefix() {
        let proto = PinUvProtocol::new(2).unwrap();
        let mut key64 = [0u8; 64];
        key64[..32].copy_from_slice(&V2_HMAC_KEY_EXPECTED);
        key64[32..].copy_from_slice(&V2_AES_KEY_EXPECTED);
        let plaintext = b"0123456789abcdef";
        let ct = proto.encrypt(&key64, plaintext).unwrap();
        assert_eq!(ct.len(), 32);
        // IV é prefixo aleatório: decifrar com IV fixo do ciphertext deve
        // reproduzir o plaintext.
        assert_eq!(proto.decrypt(&key64, &ct).unwrap(), plaintext);
    }

    #[test]
    fn test_encrypt_rejects_non_block_multiple() {
        let proto = PinUvProtocol::new(1).unwrap();
        assert!(proto.encrypt(&V1_KDF_EXPECTED, b"short").is_err());
    }

    #[test]
    fn test_decrypt_rejects_non_block_multiple() {
        let proto = PinUvProtocol::new(1).unwrap();
        assert!(proto.decrypt(&V1_KDF_EXPECTED, b"short").is_err());
    }

    #[test]
    fn test_zero_pad_and_strip_roundtrip() {
        let pin = b"1234";
        let padded = zero_pad_to_64(pin).unwrap();
        assert_eq!(padded.len(), 64);
        assert_eq!(&padded[..4], pin);
        assert!(padded[4..].iter().all(|b| *b == 0));
        assert_eq!(strip_zero_padding(&padded).unwrap(), pin);
    }

    #[test]
    fn test_zero_pad_rejects_over_64() {
        assert!(zero_pad_to_64(&[7u8; 65]).is_err());
    }

    #[test]
    fn test_agreement_key_symmetry() {
        let a = PinAgreementKey::generate().unwrap();
        let b = PinAgreementKey::generate().unwrap();
        let pub_a = a.public_key_bytes().unwrap();
        let pub_b = b.public_key_bytes().unwrap();
        let za = a.agree(&pub_b).unwrap();
        let zb = b.agree(&pub_a).unwrap();
        assert_eq!(za.len(), ECDH_SHARED_SECRET_LEN);
        assert_eq!(za, zb);
        assert_ne!(za, [0u8; ECDH_SHARED_SECRET_LEN]);
    }

    #[test]
    fn test_agreement_rejects_bad_public_key() {
        let a = PinAgreementKey::generate().unwrap();
        assert!(a.agree(&[0u8; 32]).is_err());
        let a = PinAgreementKey::generate().unwrap();
        assert!(a.agree(&[0u8; 65]).is_err());
    }

    #[test]
    fn test_unsupported_protocol_rejected() {
        assert!(PinUvProtocol::new(0).is_err());
        assert!(PinUvProtocol::new(3).is_err());
    }
}
