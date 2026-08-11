use alloc::vec::Vec;
use core::fmt::Debug;
use num_bigint_dig::BigUint;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::digest;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{
    EcdsaKeyPair, Ed25519KeyPair, KeyPair, RsaKeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_ASN1_SIGNING, ED25519, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256,
};
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};

extern crate alloc;

/// RSA modulus size used for RS256 credentials.
const RSA_KEY_BITS: usize = 2048;

/// RSA key pair material: (PKCS#8 private key, modulus `n`, exponent `e`).
pub type RsaKeyMaterial = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Motor criptográfico do autenticador.
///
/// Mantém uma chave-mestra de 32 bytes usada para encryption at rest
/// (ChaCha20-Poly1305) e derivação de chaves. A chave nunca é exposta:
/// a implementação de [`Debug`] a substitui por `[redacted]` para evitar
/// vazamento acidental em logs.
pub struct CryptoEngine {
    key: [u8; 32],
}

impl Clone for CryptoEngine {
    fn clone(&self) -> Self {
        Self { key: self.key }
    }
}

fn ed25519_key_pair_from_seed(seed: &[u8]) -> Result<Ed25519KeyPair, Box<dyn std::error::Error>> {
    if seed.len() != 32 {
        return Err("Ed25519 private key must be 32 bytes".into());
    }
    Ed25519KeyPair::from_seed_unchecked(seed)
        .map_err(|e| format!("Invalid Ed25519 private key: {:?}", e).into())
}

impl CryptoEngine {
    /// Cria um motor com chave-mestra aleatória obtida de `SystemRandom`.
    ///
    /// Cada instância gera uma chave nova: credenciais cifradas por um motor
    /// não são legíveis por outro. Use [`CryptoEngine::from_key`] quando a
    /// chave precisar sobreviver a reinícios (storage persistente).
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key)
            .map_err(|e| format!("Failed to generate engine key: {:?}", e))?;

        log::info!("Crypto engine initialized");
        Ok(Self { key })
    }

    /// Cria um motor a partir de uma chave-mestra existente.
    ///
    /// Necessário para storage persistente: sem reusar a chave, os dados
    /// cifrados em execuções anteriores tornam-se indecifráveis.
    pub fn from_key(key: [u8; 32]) -> Self {
        log::info!("Crypto engine initialized with provided key");
        Self { key }
    }

    /// Deriva uma subchave de 32 bytes a partir da chave-mestra.
    ///
    /// Evita reutilizar a chave-mestra diretamente em contextos distintos;
    /// `salt` e `iterations` compõem o domínio de separação.
    pub fn derive_key(
        &self,
        salt: &[u8],
        iterations: u32,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.key);
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(salt);
        ctx.update(&iterations.to_be_bytes());
        Ok(ctx.sign().as_ref().to_vec())
    }

    /// Calcula HMAC-SHA256 de `data` usando `key_id` como chave.
    pub fn compute_hmac(
        &self,
        data: &[u8],
        key_id: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key_id);
        let tag = hmac::sign(&key, data);
        Ok(tag.as_ref().to_vec())
    }

    /// Verifica um HMAC-SHA256 em tempo constante.
    ///
    /// Retorna `Err` (em vez de `Ok(false)`) quando o MAC não confere, para
    /// que o chamador não trate silenciosamente uma falha de autenticação.
    pub fn verify_hmac(
        &self,
        data: &[u8],
        mac_data: &[u8],
        key_id: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, key_id);
        hmac::verify(&key, data, mac_data)
            .map(|_| true)
            .map_err(|e| format!("HMAC verification failed: {:?}", e).into())
    }

    /// Calcula SHA-256 de `data`. Usado para `rpIdHash` no authData CTAP2.
    pub fn sha256(&self, data: &[u8]) -> Vec<u8> {
        digest::digest(&digest::SHA256, data).as_ref().to_vec()
    }

    /// Gera `len` bytes aleatórios via `SystemRandom` (CSPRNG do SO).
    ///
    /// # Panics
    ///
    /// Entra em pânico se o RNG do sistema falhar — continuar com entropia
    /// degradada comprometeria nonces e credential IDs.
    pub fn random_bytes(&self, len: usize) -> Vec<u8> {
        let rng = SystemRandom::new();
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf)
            .expect("SystemRandom failed to generate random bytes");
        buf
    }

    /// Gera um par de chaves Ed25519 (EdDSA, alg -8), o algoritmo padrão.
    ///
    /// Retorna `(seed de 32 bytes, chave pública de 32 bytes)`. A seed é
    /// armazenada em vez do PKCS#8 por ocupar menos espaço em flash.
    pub fn generate_key_pair(&self) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let rng = SystemRandom::new();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed)
            .map_err(|e| format!("Failed to generate key pair seed: {:?}", e))?;
        let key_pair = ed25519_key_pair_from_seed(&seed)?;
        let public_key = key_pair.public_key().as_ref().to_vec();
        Ok((seed.to_vec(), public_key))
    }

    /// Generate a P-256 key pair, returning (PKCS#8 private key, raw public key).
    /// The public key is 65 bytes: 0x04 + x (32 bytes) + y (32 bytes).
    pub fn generate_p256_key_pair(&self) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|e| format!("Failed to generate P-256 PKCS#8: {:?}", e))?;
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .map_err(|e| format!("Failed to parse P-256 PKCS#8: {:?}", e))?;
        let public_key = key_pair.public_key().as_ref().to_vec();
        Ok((pkcs8.as_ref().to_vec(), public_key))
    }

    /// Sign with P-256, returning a DER-encoded signature.
    pub fn sign_p256(
        &self,
        private_key: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let rng = SystemRandom::new();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, private_key, &rng)
            .map_err(|e| format!("Failed to parse P-256 private key: {:?}", e))?;
        let signature = key_pair
            .sign(&rng, message)
            .map_err(|e| format!("P-256 signing failed: {:?}", e))?;
        Ok(signature.as_ref().to_vec())
    }

    /// Verify a P-256 DER-encoded signature.
    pub fn verify_p256(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let verifying_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key);
        verifying_key
            .verify(message, signature)
            .map_err(|e| format!("P-256 verification failed: {:?}", e).into())
    }

    /// Generate an RSA-2048 key pair for RS256 (alg -257).
    /// Returns (PKCS#8 private key, modulus `n` big-endian, exponent `e` big-endian).
    pub fn generate_rsa_key_pair(&self) -> Result<RsaKeyMaterial, Box<dyn std::error::Error>> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS)
            .map_err(|e| format!("RSA key generation failed: {:?}", e))?;
        let public_key = RsaPublicKey::from(&private_key);
        let pkcs8 = private_key
            .to_pkcs8_der()
            .map_err(|e| format!("RSA PKCS#8 encoding failed: {:?}", e))?
            .as_bytes()
            .to_vec();
        let n = public_key.n().to_bytes_be();
        let e = public_key.e().to_bytes_be();
        Ok((pkcs8, n, e))
    }

    /// Encode an RSA public key (`n`, `e` big-endian) as a DER `RSAPublicKey`
    /// (PKCS#1), the format expected by `ring` for RSA verification.
    pub fn rsa_public_key_der(n: &[u8], e: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let public_key = RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e))
            .map_err(|e| format!("Invalid RSA public key: {:?}", e))?;
        let der = public_key
            .to_pkcs1_der()
            .map_err(|e| format!("RSA public key encoding failed: {:?}", e))?
            .as_bytes()
            .to_vec();
        Ok(der)
    }

    /// Extract (`n`, `e`) big-endian components from a DER `RSAPublicKey`.
    pub fn rsa_public_key_parts(
        public_key_der: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        let public_key = RsaPublicKey::from_pkcs1_der(public_key_der)
            .map_err(|e| format!("Invalid RSA public key DER: {:?}", e))?;
        Ok((public_key.n().to_bytes_be(), public_key.e().to_bytes_be()))
    }

    /// Sign with RSA PKCS#1 v1.5 over SHA-256 (RS256).
    pub fn sign_rsa(
        &self,
        private_key: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let key_pair = RsaKeyPair::from_pkcs8(private_key)
            .map_err(|e| format!("Failed to parse RSA private key: {:?}", e))?;
        let rng = SystemRandom::new();
        let mut signature = vec![0u8; key_pair.public().modulus_len()];
        key_pair
            .sign(&RSA_PKCS1_SHA256, &rng, message, &mut signature)
            .map_err(|e| format!("RSA signing failed: {:?}", e))?;
        Ok(signature)
    }

    /// Verify an RS256 signature against a DER SubjectPublicKeyInfo public key.
    pub fn verify_rsa(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let verifying_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key);
        verifying_key
            .verify(message, signature)
            .map_err(|e| format!("RSA verification failed: {:?}", e).into())
    }

    /// Assina `data` com Ed25519, a partir da seed de 32 bytes.
    pub fn sign(
        &self,
        data: &[u8],
        private_key: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let key_pair = ed25519_key_pair_from_seed(private_key)?;
        Ok(key_pair.sign(data).as_ref().to_vec())
    }

    /// Verifica uma assinatura Ed25519. Retorna `Err` quando inválida.
    pub fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let verifying_key = UnparsedPublicKey::new(&ED25519, public_key);
        verifying_key
            .verify(data, signature)
            .map(|_| true)
            .map_err(|e| format!("Signature verification failed: {:?}", e).into())
    }

    /// Cifra `plaintext` com ChaCha20-Poly1305 usando a chave-mestra.
    ///
    /// O `nonce` deve ter exatamente 12 bytes e **nunca** ser reutilizado com
    /// a mesma chave — use [`CryptoEngine::random_bytes`] para gerá-lo.
    /// A saída inclui a tag de autenticação de 16 bytes ao final.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &self.key)
            .map_err(|e| format!("Failed to create cipher key: {:?}", e))?;
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key(
            nonce
                .try_into()
                .map_err(|_| "Nonce must be exactly 12 bytes")?,
        );
        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| format!("Encryption failed: {:?}", e))?;
        Ok(in_out)
    }

    /// Decifra dados produzidos por [`CryptoEngine::encrypt`].
    ///
    /// Falha se a tag de autenticação não conferir (dado adulterado) ou se a
    /// chave-mestra for diferente da usada na cifragem.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &self.key)
            .map_err(|e| format!("Failed to create cipher key: {:?}", e))?;
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key(
            nonce
                .try_into()
                .map_err(|_| "Nonce must be exactly 12 bytes")?,
        );
        let mut in_out = ciphertext.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|e| format!("Decryption failed: {:?}", e))?;
        Ok(plaintext.to_vec())
    }
}

impl Debug for CryptoEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CryptoEngine")
            .field("key", &"[redacted]")
            .finish()
    }
}

impl Default for CryptoEngine {
    fn default() -> Self {
        Self::new().expect("Failed to initialize default CryptoEngine")
    }
}

/// Compares two byte slices in constant time.
///
/// Returns `true` if `a` and `b` are equal, `false` otherwise.
/// The time taken is proportional to the length of `b` and does not
/// depend on the content of `a` or `b`, making it suitable for comparing
/// secrets such as PIN hashes or authentication tokens.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_rsa_key_pair() {
        let engine = CryptoEngine::new().unwrap();
        let (pkcs8, n, e) = engine.generate_rsa_key_pair().unwrap();

        assert!(!pkcs8.is_empty());
        assert_eq!(n.len(), RSA_KEY_BITS / 8);
        assert!(!e.is_empty());
        assert!(e.len() <= 3);
    }

    #[test]
    fn test_rsa_sign_verify() {
        let engine = CryptoEngine::new().unwrap();
        let (pkcs8, n, e) = engine.generate_rsa_key_pair().unwrap();
        let pub_der = CryptoEngine::rsa_public_key_der(&n, &e).unwrap();

        let message = b"openkey rs256 test message";
        let signature = engine.sign_rsa(&pkcs8, message).unwrap();
        assert_eq!(signature.len(), RSA_KEY_BITS / 8);

        engine.verify_rsa(&pub_der, message, &signature).unwrap();

        let mut tampered = signature.clone();
        tampered[0] ^= 0xFF;
        assert!(engine.verify_rsa(&pub_der, message, &tampered).is_err());
        assert!(engine
            .verify_rsa(&pub_der, b"other message", &signature)
            .is_err());
    }

    #[test]
    fn test_rsa_public_key_der_roundtrip() {
        let engine = CryptoEngine::new().unwrap();
        let (_, n, e) = engine.generate_rsa_key_pair().unwrap();
        let pub_der = CryptoEngine::rsa_public_key_der(&n, &e).unwrap();
        let (n2, e2) = CryptoEngine::rsa_public_key_parts(&pub_der).unwrap();

        assert_eq!(n, n2);
        assert_eq!(e, e2);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"hell", b"hello"));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"a", b""));

        let mut a = vec![0u8; 32];
        let mut b = vec![0u8; 32];
        assert!(constant_time_eq(&a, &b));

        a[0] = 0x01;
        assert!(!constant_time_eq(&a, &b));

        b[0] = 0x01;
        b[31] = 0xFF;
        assert!(!constant_time_eq(&a, &b));
    }
}
