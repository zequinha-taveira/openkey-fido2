//! Configuração de produto e descoberta de capabilities.
//!
//! Separa o que é hardware (`board-generic`) do que é decisão de produto
//! (nome, versão, política de PIN, extensões), evitando recompilar o firmware
//! inteiro para variar apenas o perfil comercial.

/// Relato de capabilities em runtime.
pub mod capability;
/// Perfil de produto e seu builder.
pub mod profile;

pub use capability::{Capabilities, CapabilityDiscovery};
pub use profile::{
    AttestationType, DeviceProfile, DeviceProfileBuilder, Extension, PinPolicy, Protocol,
    Transport, TransportConfig, TransportType,
};

// Re-export attestation types for convenience
pub use ctap2::{AttestationCertificate, AttestationFormat};
