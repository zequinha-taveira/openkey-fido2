//! Primitivas criptográficas do openkey-fido2.
//!
//! Encapsula `ring` (ADR-0001) atrás de uma API estável, de forma que trocar o
//! provedor criptográfico não exija mudanças nas camadas CTAP2/storage.

/// Motor criptográfico principal (Ed25519, P-256, RSA, HMAC, ChaCha20-Poly1305).
pub mod crypto;
/// Encriptação híbrida (ECIES X25519 + ChaCha20-Poly1305).
pub mod hybrid;
/// Protocolo PIN/UV (CTAP 2.1 §6.5.6/§6.5.7): ECDH P-256, AES-CBC, HKDF, HMAC.
pub mod pin_protocol;

pub use crypto::{constant_time_eq, CryptoEngine};
pub use hybrid::{
    hybrid_decrypt, hybrid_encrypt, hybrid_generate_keypair, HybridCiphertext, ECIES_OVERHEAD,
    NONCE_LEN, TAG_LEN, X25519_KEY_LEN,
};
pub use pin_protocol::{
    aes256_cbc_decrypt, aes256_cbc_encrypt, hkdf_sha256, strip_zero_padding, zero_pad_to_64,
    PinAgreementKey, PinUvProtocol, Zeroizing,
};
