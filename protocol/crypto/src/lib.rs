//! Primitivas criptográficas do openkey-fido2.
//!
//! Encapsula `ring` (ADR-0001) atrás de uma API estável, de forma que trocar o
//! provedor criptográfico não exija mudanças nas camadas CTAP2/storage.

/// Motor criptográfico principal (Ed25519, P-256, RSA, HMAC, ChaCha20-Poly1305).
pub mod crypto;
/// Encriptação híbrida (ECIES X25519 + ChaCha20-Poly1305).
pub mod hybrid;

pub use crypto::CryptoEngine;
pub use hybrid::{
    hybrid_decrypt, hybrid_encrypt, hybrid_generate_keypair, HybridCiphertext, ECIES_OVERHEAD,
    NONCE_LEN, TAG_LEN, X25519_KEY_LEN,
};
