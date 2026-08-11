//! Criptografia híbrida (ECIES) sobre X25519 + ChaCha20-Poly1305.
//!
//! O esquema é um **sealed box efêmero**: o remetente gera um par de chaves
//! efêmero, faz ECDH com a chave pública do destinatário, deriva uma chave
//! simétrica via HKDF-SHA256 e cifra o payload com ChaCha20-Poly1305.
//!
//! NOTA: `ring` 0.17 não permite importar chaves privadas X25519 estáticas —
//! `EphemeralPrivateKey` só pode ser criada via `generate()`. Por isso
//! `hybrid_decrypt` recebe a `EphemeralPrivateKey` **por valor** em vez de
//! bytes, e o par de chaves do destinatário precisa ser criado no processo
//! (via `hybrid_generate_keypair`) e mantido vivo até a decifragem. Isso
//! restringe o módulo a cenários dentro de um mesmo processo (ex.: sessões em
//! memória), não a chaves persistidas em flash.

use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{compiler_fence, Ordering};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::hkdf::{self, HKDF_SHA256};
use ring::rand::{SecureRandom, SystemRandom};

extern crate alloc;

/// Tamanho de uma chave pública/privada X25519 em bytes.
pub const X25519_KEY_LEN: usize = 32;
/// Tamanho do nonce do ChaCha20-Poly1305 em bytes.
pub const NONCE_LEN: usize = 12;
/// Tamanho da tag de autenticação do ChaCha20-Poly1305 em bytes.
pub const TAG_LEN: usize = 16;

/// Overhead fixo de um ciphertext ECIES serializado:
/// chave pública efêmera + nonce + tag.
pub const ECIES_OVERHEAD: usize = X25519_KEY_LEN + NONCE_LEN + TAG_LEN;

/// Rótulo de domínio do KDF. Alterá-lo quebra compatibilidade.
const HKDF_INFO: &[u8] = b"openkey-ecies-v1";

type Error = Box<dyn std::error::Error>;

/// Wrapper que zera o material sensível ao ser dropado.
///
/// NOTA: sem a crate `zeroize` (dependência proibida) e sem `unsafe`, a
/// melhor garantia disponível é escrever zeros e emitir um `compiler_fence`
/// para desencorajar a eliminação da escrita morta pelo otimizador.
struct Zeroizing<T: AsMut<[u8]>>(T);

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

/// Comprimento de saída solicitado ao HKDF.
struct OkmLen(usize);

impl hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[derive(Debug)]
pub struct HybridCiphertext {
    pub ephemeral_public_key: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl HybridCiphertext {
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(X25519_KEY_LEN + NONCE_LEN + self.ciphertext.len());
        result.extend_from_slice(&self.ephemeral_public_key);
        result.extend_from_slice(&self.nonce);
        result.extend_from_slice(&self.ciphertext);
        result
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, Error> {
        if data.len() < ECIES_OVERHEAD {
            return Err(format!(
                "Data too short for hybrid ciphertext: got {} bytes, need at least {}",
                data.len(),
                ECIES_OVERHEAD
            )
            .into());
        }

        let ephemeral_public_key = data[..X25519_KEY_LEN].to_vec();
        let nonce: [u8; NONCE_LEN] = data[X25519_KEY_LEN..X25519_KEY_LEN + NONCE_LEN]
            .try_into()
            .map_err(|_| "Invalid nonce")?;
        let ciphertext = data[X25519_KEY_LEN + NONCE_LEN..].to_vec();

        Ok(Self {
            ephemeral_public_key,
            nonce,
            ciphertext,
        })
    }
}

/// Deriva a chave simétrica via HKDF-SHA256.
///
/// O salt é `ephemeral_pk || recipient_pk` — idêntico nos dois lados, o que
/// vincula a chave derivada a ambas as partes do handshake.
fn derive_symmetric_key(
    shared_secret: &[u8],
    ephemeral_pk: &[u8],
    recipient_pk: &[u8],
) -> Result<[u8; 32], Error> {
    let mut salt_bytes = Vec::with_capacity(ephemeral_pk.len() + recipient_pk.len());
    salt_bytes.extend_from_slice(ephemeral_pk);
    salt_bytes.extend_from_slice(recipient_pk);

    let salt = hkdf::Salt::new(HKDF_SHA256, &salt_bytes);
    let prk = salt.extract(shared_secret);
    let okm = prk
        .expand(&[HKDF_INFO], OkmLen(32))
        .map_err(|e| format!("HKDF expand failed: {:?}", e))?;

    let mut derived_key = [0u8; 32];
    okm.fill(&mut derived_key)
        .map_err(|e| format!("HKDF fill failed: {:?}", e))?;
    Ok(derived_key)
}

/// Gera um par de chaves X25519 efêmero para uso como destinatário.
///
/// Retorna a chave privada (que deve ser consumida por `hybrid_decrypt`) e os
/// 32 bytes da chave pública correspondente.
pub fn hybrid_generate_keypair() -> Result<(EphemeralPrivateKey, Vec<u8>), Error> {
    let rng = SystemRandom::new();
    let private_key = EphemeralPrivateKey::generate(&X25519, &rng)
        .map_err(|e| format!("Failed to generate X25519 key pair: {:?}", e))?;
    let public_key = private_key
        .compute_public_key()
        .map_err(|e| format!("Failed to compute X25519 public key: {:?}", e))?;
    Ok((private_key, public_key.as_ref().to_vec()))
}

pub fn hybrid_encrypt(
    recipient_public_key: &[u8],
    plaintext: &[u8],
) -> Result<HybridCiphertext, Error> {
    if recipient_public_key.len() != X25519_KEY_LEN {
        return Err(format!(
            "Recipient public key must be {} bytes, got {}",
            X25519_KEY_LEN,
            recipient_public_key.len()
        )
        .into());
    }

    let rng = SystemRandom::new();

    let ephemeral_private = EphemeralPrivateKey::generate(&X25519, &rng)
        .map_err(|e| format!("Failed to generate ephemeral key: {:?}", e))?;

    let ephemeral_public = ephemeral_private
        .compute_public_key()
        .map_err(|e| format!("Failed to compute ephemeral public key: {:?}", e))?;
    let ephemeral_public_bytes = ephemeral_public.as_ref().to_vec();

    let recipient_key = UnparsedPublicKey::new(&X25519, recipient_public_key);

    let shared_secret = Zeroizing(
        agreement::agree_ephemeral(ephemeral_private, &recipient_key, |key_material| {
            key_material.to_vec()
        })
        .map_err(|e| format!("ECDH agreement failed: {:?}", e))?,
    );

    let symmetric_key = Zeroizing(derive_symmetric_key(
        &shared_secret,
        &ephemeral_public_bytes,
        recipient_public_key,
    )?);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|e| format!("Failed to generate nonce: {:?}", e))?;

    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &*symmetric_key)
        .map_err(|e| format!("Failed to create cipher key: {:?}", e))?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    // A chave pública efêmera é autenticada como AAD: adulterá-la invalida a tag.
    let mut ciphertext = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::from(&ephemeral_public_bytes), &mut ciphertext)
        .map_err(|e| format!("Encryption failed: {:?}", e))?;

    Ok(HybridCiphertext {
        ephemeral_public_key: ephemeral_public_bytes,
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decifra um `HybridCiphertext`.
///
/// `recipient_private` é consumida (limitação do `ring`, ver nota do módulo).
/// `recipient_public` é validada contra a chave pública derivada da privada;
/// a derivada é a usada no KDF, garantindo simetria com `hybrid_encrypt`.
pub fn hybrid_decrypt(
    recipient_private: EphemeralPrivateKey,
    recipient_public: &[u8],
    ciphertext: &HybridCiphertext,
) -> Result<Vec<u8>, Error> {
    if recipient_public.len() != X25519_KEY_LEN {
        return Err(format!(
            "Recipient public key must be {} bytes, got {}",
            X25519_KEY_LEN,
            recipient_public.len()
        )
        .into());
    }

    if ciphertext.ephemeral_public_key.len() != X25519_KEY_LEN {
        return Err(format!(
            "Ephemeral public key must be {} bytes, got {}",
            X25519_KEY_LEN,
            ciphertext.ephemeral_public_key.len()
        )
        .into());
    }

    if ciphertext.ciphertext.len() < TAG_LEN {
        return Err("Ciphertext too short to contain an authentication tag".into());
    }

    let derived_public = recipient_private
        .compute_public_key()
        .map_err(|e| format!("Failed to compute recipient public key: {:?}", e))?;
    let recipient_public_bytes = derived_public.as_ref().to_vec();

    if recipient_public_bytes != recipient_public {
        return Err("Recipient public key does not match the provided private key".into());
    }

    let ephemeral_key = UnparsedPublicKey::new(&X25519, &ciphertext.ephemeral_public_key);

    let shared_secret = Zeroizing(
        agreement::agree_ephemeral(recipient_private, &ephemeral_key, |key_material| {
            key_material.to_vec()
        })
        .map_err(|e| format!("ECDH agreement failed: {:?}", e))?,
    );

    let symmetric_key = Zeroizing(derive_symmetric_key(
        &shared_secret,
        &ciphertext.ephemeral_public_key,
        &recipient_public_bytes,
    )?);

    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &*symmetric_key)
        .map_err(|e| format!("Failed to create cipher key: {:?}", e))?;
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(ciphertext.nonce);

    let mut in_out = ciphertext.ciphertext.clone();
    let plaintext = key
        .open_in_place(
            nonce,
            Aad::from(&ciphertext.ephemeral_public_key),
            &mut in_out,
        )
        .map_err(|e| format!("Decryption failed: {:?}", e))?;

    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_serialization_roundtrip() {
        let ct = HybridCiphertext {
            ephemeral_public_key: vec![1u8; 32],
            nonce: [2u8; 12],
            ciphertext: vec![3u8; 44],
        };

        let serialized = ct.serialize();
        let deserialized = HybridCiphertext::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.ephemeral_public_key, ct.ephemeral_public_key);
        assert_eq!(deserialized.nonce, ct.nonce);
        assert_eq!(deserialized.ciphertext, ct.ciphertext);
    }

    #[test]
    fn test_hybrid_deserialize_too_short() {
        let data = vec![0u8; 10];
        let result = HybridCiphertext::deserialize(&data);
        assert!(result.is_err());

        let data = vec![0u8; ECIES_OVERHEAD - 1];
        assert!(HybridCiphertext::deserialize(&data).is_err());

        let data = vec![0u8; ECIES_OVERHEAD];
        assert!(HybridCiphertext::deserialize(&data).is_ok());
    }

    #[test]
    fn test_hybrid_encrypt_produces_valid_ciphertext() {
        let (_private, public) = hybrid_generate_keypair().unwrap();

        let plaintext = b"Hello, ECIES Hybrid Encryption!";

        let ct = hybrid_encrypt(&public, plaintext).unwrap();
        assert_eq!(ct.ephemeral_public_key.len(), 32);
        assert_eq!(ct.nonce.len(), 12);
        assert_eq!(ct.ciphertext.len(), plaintext.len() + TAG_LEN);

        let serialized = ct.serialize();
        let deserialized = HybridCiphertext::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.ephemeral_public_key, ct.ephemeral_public_key);
    }

    #[test]
    fn test_hybrid_roundtrip() {
        let (private, public) = hybrid_generate_keypair().unwrap();
        let plaintext = b"mensagem secreta do autenticador";

        let ct = hybrid_encrypt(&public, plaintext).unwrap();
        let recovered = hybrid_decrypt(private, &public, &ct).unwrap();

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_hybrid_roundtrip_via_serialization() {
        let (private, public) = hybrid_generate_keypair().unwrap();
        let plaintext = b"payload que atravessa a serializacao";

        let ct = hybrid_encrypt(&public, plaintext).unwrap();
        let wire = ct.serialize();
        assert_eq!(wire.len(), plaintext.len() + ECIES_OVERHEAD);

        let parsed = HybridCiphertext::deserialize(&wire).unwrap();
        let recovered = hybrid_decrypt(private, &public, &parsed).unwrap();

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_hybrid_decrypt_wrong_key() {
        let (_private_a, public_a) = hybrid_generate_keypair().unwrap();
        let (private_b, public_b) = hybrid_generate_keypair().unwrap();

        let ct = hybrid_encrypt(&public_a, b"apenas para A").unwrap();
        let result = hybrid_decrypt(private_b, &public_b, &ct);

        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_decrypt_mismatched_public_key() {
        let (private_a, public_a) = hybrid_generate_keypair().unwrap();
        let (_private_b, public_b) = hybrid_generate_keypair().unwrap();

        let ct = hybrid_encrypt(&public_a, b"apenas para A").unwrap();
        let result = hybrid_decrypt(private_a, &public_b, &ct);

        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_decrypt_tampered_ciphertext() {
        let (private, public) = hybrid_generate_keypair().unwrap();

        let mut ct = hybrid_encrypt(&public, b"integridade importa").unwrap();
        ct.ciphertext[0] ^= 0x01;

        assert!(hybrid_decrypt(private, &public, &ct).is_err());
    }

    #[test]
    fn test_hybrid_decrypt_tampered_ephemeral_key() {
        let (private, public) = hybrid_generate_keypair().unwrap();

        let mut ct = hybrid_encrypt(&public, b"a AAD protege a chave efemera").unwrap();
        ct.ephemeral_public_key[0] ^= 0x01;

        assert!(hybrid_decrypt(private, &public, &ct).is_err());
    }

    #[test]
    fn test_hybrid_decrypt_tampered_nonce() {
        let (private, public) = hybrid_generate_keypair().unwrap();

        let mut ct = hybrid_encrypt(&public, b"nonce autenticado pela tag").unwrap();
        ct.nonce[0] ^= 0x01;

        assert!(hybrid_decrypt(private, &public, &ct).is_err());
    }

    #[test]
    fn test_hybrid_empty_plaintext() {
        let (private, public) = hybrid_generate_keypair().unwrap();

        let ct = hybrid_encrypt(&public, b"").unwrap();
        assert_eq!(ct.ciphertext.len(), TAG_LEN);

        let recovered = hybrid_decrypt(private, &public, &ct).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn test_hybrid_large_plaintext() {
        let (private, public) = hybrid_generate_keypair().unwrap();
        let plaintext: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();

        let ct = hybrid_encrypt(&public, &plaintext).unwrap();
        let recovered = hybrid_decrypt(private, &public, &ct).unwrap();

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_hybrid_ciphertexts_diferentes() {
        let (_private, public) = hybrid_generate_keypair().unwrap();
        let plaintext = b"mesmo texto, cifras distintas";

        let ct1 = hybrid_encrypt(&public, plaintext).unwrap();
        let ct2 = hybrid_encrypt(&public, plaintext).unwrap();

        assert_ne!(ct1.ephemeral_public_key, ct2.ephemeral_public_key);
        assert_ne!(ct1.nonce, ct2.nonce);
        assert_ne!(ct1.ciphertext, ct2.ciphertext);
    }

    #[test]
    fn test_hybrid_encrypt_rejeita_public_key_invalida() {
        assert!(hybrid_encrypt(&[], b"x").is_err());
        assert!(hybrid_encrypt(&[0u8; 31], b"x").is_err());
        assert!(hybrid_encrypt(&[0u8; 33], b"x").is_err());
    }

    #[test]
    fn test_hybrid_kdf_deterministic() {
        let secret = b"shared secret value here!!!";
        let ephemeral_pk = vec![1u8; 32];
        let recipient_pk = vec![2u8; 32];

        let key1 = derive_symmetric_key(secret, &ephemeral_pk, &recipient_pk).unwrap();
        let key2 = derive_symmetric_key(secret, &ephemeral_pk, &recipient_pk).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_hybrid_kdf_different_inputs() {
        let secret1 = b"shared secret value one!!!!!";
        let secret2 = b"shared secret value two!!!!!";

        let ephemeral_pk = vec![1u8; 32];
        let recipient_pk = vec![2u8; 32];

        let key1 = derive_symmetric_key(secret1, &ephemeral_pk, &recipient_pk).unwrap();
        let key2 = derive_symmetric_key(secret2, &ephemeral_pk, &recipient_pk).unwrap();

        assert_ne!(key1, key2);

        let key3 = derive_symmetric_key(secret1, &recipient_pk, &ephemeral_pk).unwrap();
        assert_ne!(key1, key3);
    }
}
