//! Armazenamento de credenciais com encryption at rest.
//!
//! Chaves privadas nunca são persistidas em claro: o [`StorageEngine`] as cifra
//! com o `CryptoEngine` antes de gravar e só as decifra sob demanda.

/// Motor de armazenamento e backends de persistência.
pub mod storage;

pub use storage::{
    Credential, FileStorageBackend, FlashDevice, FlashStorageBackend, SimulatedFlash,
    StorageBackend, StorageEngine, StorageError, StoredCredential,
};
