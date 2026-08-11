use crate::profile::{AttestationType, DeviceProfile, Extension, PinPolicy, Protocol, Transport};
use alloc::vec::Vec;
use board_generic::SecurityFeatures;
use log::debug;

extern crate alloc;

/// Runtime snapshot of what the authenticator can do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    /// AAGUID reportado no GetInfo.
    pub aaguid: [u8; 16],
    /// Nome comercial do produto.
    pub product_name: &'static str,
    /// Nome do fabricante.
    pub vendor_name: &'static str,
    /// Versão do firmware.
    pub firmware_version: &'static str,
    /// Versão do hardware.
    pub hardware_version: &'static str,
    /// Transportes físicos disponíveis.
    pub transports: Vec<Transport>,
    /// Versões de protocolo suportadas.
    pub protocols: Vec<Protocol>,
    /// Formato de attestation anunciado.
    pub attestation: AttestationType,
    /// Política de PIN do produto.
    pub pin_policy: PinPolicy,
    /// Suporte a resident keys (discoverable credentials).
    pub rk: bool,
    /// Suporte a user verification.
    pub uv: bool,
    /// Suporte a user presence.
    pub up: bool,
    /// Derivado de `pin_policy`: `clientPin` só é anunciado se não desabilitado.
    pub client_pin_available: bool,
    /// Indica encryption at rest ativa.
    pub storage_encrypted: bool,
    /// Indica acelerador criptográfico em hardware.
    pub crypto_accelerator: bool,
    /// Extensões WebAuthn suportadas.
    pub extensions: Vec<Extension>,
    /// Número máximo de credenciais residentes.
    pub max_credentials: u16,
    /// Tamanho máximo de um credential ID.
    pub max_credential_id_length: u16,
    /// Tamanho máximo do `credBlob`.
    pub max_cred_blob_length: u32,
    /// Número de relying parties registrados.
    pub rp_count: u32,
    /// Recursos de segurança do silício.
    pub security: SecurityFeatures,
}

/// Reports runtime capabilities derived from a [`DeviceProfile`].
#[derive(Debug)]
pub struct CapabilityDiscovery {
    profile: DeviceProfile,
}

impl CapabilityDiscovery {
    /// Assume a posse do perfil que será traduzido em capabilities.
    pub fn new(profile: DeviceProfile) -> Self {
        debug!(
            "Capability discovery initialized for {}",
            profile.product_name
        );
        Self { profile }
    }

    /// Perfil de origem, sem transformações.
    pub fn profile(&self) -> &DeviceProfile {
        &self.profile
    }

    /// Projeta o perfil em [`Capabilities`], resolvendo campos derivados.
    pub fn capabilities(&self) -> Capabilities {
        Capabilities {
            aaguid: self.profile.aaguid,
            product_name: self.profile.product_name,
            vendor_name: self.profile.vendor_name,
            firmware_version: self.profile.firmware_version,
            hardware_version: self.profile.hardware_version,
            transports: self.profile.transports.clone(),
            protocols: self.profile.protocols.clone(),
            attestation: self.profile.attestation,
            pin_policy: self.profile.pin_policy,
            rk: self.profile.rk_support,
            uv: self.profile.uv_support,
            up: self.profile.up_support,
            client_pin_available: self.profile.pin_policy != PinPolicy::Disabled,
            storage_encrypted: self.profile.storage_encrypted,
            crypto_accelerator: self.profile.crypto_accelerator,
            extensions: self.profile.extensions.clone(),
            max_credentials: self.profile.max_credentials,
            max_credential_id_length: self.profile.max_credential_id_length,
            max_cred_blob_length: self.profile.max_cred_blob_length,
            rp_count: self.profile.rp_count,
            security: self.profile.security,
        }
    }
}
