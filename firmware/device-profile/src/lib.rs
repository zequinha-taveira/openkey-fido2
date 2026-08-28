//! Configuração de produto e descoberta de capabilities.
//!
//! Separa o que é hardware (`board-generic`) do que é decisão de produto
//! (nome, versão, política de PIN, extensões), evitando recompilar o firmware
//! inteiro para variar apenas o perfil comercial.
//!
//! Compila tanto em host (`std`, padrão) quanto em alvos bare-metal
//! (`no_std` + `alloc`) via a feature `std`.

#![cfg_attr(not(feature = "std"), no_std)]

/// Relato de capabilities em runtime.
pub mod capability;
/// Perfil de produto e seu builder.
pub mod profile;

pub use capability::{Capabilities, CapabilityDiscovery};
pub use profile::{
    AttestationType, DeviceProfile, DeviceProfileBuilder, Extension, PinPolicy, Protocol,
    Transport, TransportConfig, TransportType, UsbIdentity,
};

// Re-export attestation types for convenience
pub use ctap2::{AttestationCertificate, AttestationFormat};
