//! Armazenamento de credenciais com encryption at rest.
//!
//! Chaves privadas nunca são persistidas em claro: o [`StorageEngine`] as cifra
//! com o `CryptoEngine` antes de gravar e só as decifra sob demanda.
//!
//! Compila tanto em host (`std`, padrão — inclui o backend de arquivos)
//! quanto em alvos bare-metal (`no_std` + `alloc`) via a feature `std`.

#![cfg_attr(not(feature = "std"), no_std)]

/// Motor de armazenamento e backends de persistência.
pub mod storage;

pub use storage::{
    Credential, FlashDevice, FlashStorageBackend, SimulatedFlash, StorageBackend, StorageEngine,
    StorageError, StoredCredential, CRED_PROTECT_UV_REQUIRED, MAX_LARGE_BLOBS_SIZE,
};

/// Backend de arquivos JSON — disponível apenas em host (usa `std::fs`).
#[cfg(feature = "std")]
pub use storage::FileStorageBackend;
