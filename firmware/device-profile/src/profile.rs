use alloc::vec::Vec;
use board_generic::BoardDefinition;
use board_generic::{
    SecurityFeatures, TRANSPORT_BLE, TRANSPORT_NFC, TRANSPORT_USB_CCID, TRANSPORT_USB_HID,
};
use ctap2::{AttestationCertificate, AttestationFormat};

extern crate alloc;

/// Transporte ativo instanciado pelo `EmbeddedAuthenticator`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportType {
    /// USB-HID (CTAPHID).
    UsbHid,
    /// USB-CCID (smartcard).
    UsbCcid,
    /// NFC ISO/IEC 14443.
    Nfc,
    /// BLE GATT (FIDO Bluetooth Service).
    BleGatt,
}

/// Configuração do transporte ativo de um [`DeviceProfile`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransportConfig {
    /// Transporte selecionado para o produto.
    pub transport_type: TransportType,
}

impl TransportConfig {
    /// Cria a configuração para o transporte informado.
    pub fn new(transport_type: TransportType) -> Self {
        Self { transport_type }
    }

    /// Atalho para USB-HID.
    pub fn usb_hid() -> Self {
        Self::new(TransportType::UsbHid)
    }

    /// Atalho para USB-CCID.
    pub fn usb_ccid() -> Self {
        Self::new(TransportType::UsbCcid)
    }

    /// Atalho para NFC.
    pub fn nfc() -> Self {
        Self::new(TransportType::Nfc)
    }

    /// Atalho para BLE GATT.
    pub fn ble_gatt() -> Self {
        Self::new(TransportType::BleGatt)
    }
}

/// Physical transports a product can expose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// USB-CCID (smartcard).
    UsbCcid,
    /// USB-HID (CTAPHID).
    UsbHid,
    /// NFC ISO/IEC 14443.
    Nfc,
    /// Bluetooth Low Energy.
    Ble,
}

/// Supported protocol versions, mapped to CTAP2/WebAuthn wire versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// CTAP 2.0.
    Ctap2,
    /// CTAP 2.1.
    Ctap21,
    /// U2F / CTAP1 (legado).
    U2f,
    /// WebAuthn Level 2.
    WebAuthn,
}

/// Attestation format advertised by the authenticator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttestationType {
    /// Sem attestation (`fmt: "none"`).
    None,
    /// Formato `packed` com certificado do lote.
    Packed,
    /// Self-attestation com a própria chave da credencial.
    SelfAttested,
}

/// PIN policy for user verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PinPolicy {
    /// ClientPIN não é anunciado nem aceito.
    Disabled,
    /// PIN pode ser configurado pelo usuário.
    Optional,
    /// PIN obrigatório para operações sensíveis.
    Required,
}

/// WebAuthn extensions supported by the authenticator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Extension {
    /// `credProtect` — política de proteção da credencial.
    CredProtect,
    /// `credBlob` — blob opaco associado à credencial.
    CredBlob,
    /// `minPinLength` — expõe o tamanho mínimo de PIN ao relying party.
    MinPinLength,
    /// `hmac-secret` — derivação de segredo simétrico por credencial.
    HmacSecret,
}

/// Product-level configuration that combines a board definition with
/// product-specific settings (vendor, firmware, enabled features).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceProfile {
    /// Nome comercial do produto.
    pub product_name: &'static str,
    /// Nome do fabricante.
    pub vendor_name: &'static str,
    /// AAGUID do modelo — deve ser único por produto.
    pub aaguid: [u8; 16],
    /// Versão do firmware.
    pub firmware_version: &'static str,
    /// Versão do hardware.
    pub hardware_version: &'static str,
    /// Transportes anunciados no GetInfo.
    pub transports: Vec<Transport>,
    /// Versões de protocolo suportadas.
    pub protocols: Vec<Protocol>,
    /// Tipo de attestation do produto.
    pub attestation: AttestationType,
    /// Formato concreto de attestation usado no MakeCredential.
    pub attestation_format: AttestationFormat,
    /// Certificado de attestation, exigido pelo formato `packed`.
    pub attestation_cert: Option<AttestationCertificate>,
    /// Política de PIN.
    pub pin_policy: PinPolicy,
    /// Suporte a resident keys.
    pub rk_support: bool,
    /// Suporte a user verification.
    pub uv_support: bool,
    /// Suporte a user presence.
    pub up_support: bool,
    /// Encryption at rest habilitada.
    pub storage_encrypted: bool,
    /// Acelerador criptográfico disponível.
    pub crypto_accelerator: bool,
    /// Extensões WebAuthn habilitadas.
    pub extensions: Vec<Extension>,
    /// Limite de credenciais residentes.
    pub max_credentials: u16,
    /// Tamanho máximo de credential ID.
    pub max_credential_id_length: u16,
    /// Tamanho máximo do `credBlob`.
    pub max_cred_blob_length: u32,
    /// Número de relying parties registrados.
    pub rp_count: u32,
    /// Transporte que o autenticador instancia em runtime.
    pub transport_config: Option<TransportConfig>,
    /// Recursos de segurança herdados do board.
    pub security: SecurityFeatures,
}

/// Builder that derives sensible defaults from a [`BoardDefinition`]
/// and allows product-level overrides.
#[derive(Debug, Clone)]
pub struct DeviceProfileBuilder {
    product_name: &'static str,
    vendor_name: &'static str,
    aaguid: [u8; 16],
    firmware_version: &'static str,
    hardware_version: &'static str,
    transports: Vec<Transport>,
    protocols: Vec<Protocol>,
    attestation: AttestationType,
    attestation_format: AttestationFormat,
    attestation_cert: Option<AttestationCertificate>,
    pin_policy: PinPolicy,
    rk_support: bool,
    uv_support: bool,
    up_support: bool,
    storage_encrypted: bool,
    crypto_accelerator: bool,
    extensions: Vec<Extension>,
    max_credentials: u16,
    max_credential_id_length: u16,
    max_cred_blob_length: u32,
    rp_count: u32,
    transport_config: Option<TransportConfig>,
    security: SecurityFeatures,
}

impl DeviceProfileBuilder {
    /// Generic defaults for a device without a board definition.
    pub fn new() -> Self {
        Self {
            product_name: "OpenKey FIDO2",
            vendor_name: "OpenKey",
            aaguid: [0u8; 16],
            firmware_version: "0.1.0",
            hardware_version: "1.0.0",
            transports: Vec::new(),
            protocols: vec![Protocol::Ctap2, Protocol::Ctap21, Protocol::WebAuthn],
            attestation: AttestationType::None,
            attestation_format: AttestationFormat::None,
            attestation_cert: None,
            pin_policy: PinPolicy::Disabled,
            rk_support: true,
            uv_support: true,
            up_support: true,
            storage_encrypted: false,
            crypto_accelerator: false,
            extensions: vec![
                Extension::CredProtect,
                Extension::CredBlob,
                Extension::MinPinLength,
                Extension::HmacSecret,
            ],
            max_credentials: 10,
            max_credential_id_length: 64,
            max_cred_blob_length: 32,
            rp_count: 0,
            transport_config: None,
            security: SecurityFeatures::none(),
        }
    }

    /// Derives defaults from a board definition (hardware layer).
    pub fn from_board(board: &BoardDefinition) -> Self {
        let mut builder = Self::new();
        builder.product_name = board.name;
        builder.aaguid = board.aaguid;
        builder.storage_encrypted = board.has_secure_storage;
        builder.crypto_accelerator = board.has_crypto_accelerator;
        builder.security = board.security;
        builder.transports.clear();
        if board.has_transport(TRANSPORT_USB_CCID) {
            builder.transports.push(Transport::UsbCcid);
        }
        if board.has_transport(TRANSPORT_USB_HID) {
            builder.transports.push(Transport::UsbHid);
        }
        if board.has_transport(TRANSPORT_NFC) {
            builder.transports.push(Transport::Nfc);
        }
        if board.has_transport(TRANSPORT_BLE) {
            builder.transports.push(Transport::Ble);
        }
        builder
    }

    /// Define o nome comercial do produto.
    pub const fn product_name(mut self, name: &'static str) -> Self {
        self.product_name = name;
        self
    }
    /// Define o nome do fabricante.
    pub const fn vendor_name(mut self, name: &'static str) -> Self {
        self.vendor_name = name;
        self
    }
    /// Define a versão do firmware.
    pub const fn firmware_version(mut self, version: &'static str) -> Self {
        self.firmware_version = version;
        self
    }
    /// Define a versão do hardware.
    pub const fn hardware_version(mut self, version: &'static str) -> Self {
        self.hardware_version = version;
        self
    }
    /// Define o tipo de attestation anunciado.
    pub const fn attestation(mut self, attestation: AttestationType) -> Self {
        self.attestation = attestation;
        self
    }
    /// Define o formato de attestation usado no MakeCredential.
    pub const fn attestation_format(mut self, format: AttestationFormat) -> Self {
        self.attestation_format = format;
        self
    }
    /// Define o certificado de attestation (necessário para `packed`).
    pub fn attestation_cert(mut self, cert: AttestationCertificate) -> Self {
        self.attestation_cert = Some(cert);
        self
    }
    /// Define a política de PIN.
    pub const fn pin_policy(mut self, policy: PinPolicy) -> Self {
        self.pin_policy = policy;
        self
    }
    /// Habilita ou desabilita resident keys.
    pub const fn rk_support(mut self, enabled: bool) -> Self {
        self.rk_support = enabled;
        self
    }
    /// Habilita ou desabilita user verification.
    pub const fn uv_support(mut self, enabled: bool) -> Self {
        self.uv_support = enabled;
        self
    }
    /// Habilita ou desabilita user presence.
    pub const fn up_support(mut self, enabled: bool) -> Self {
        self.up_support = enabled;
        self
    }
    /// Define o limite de credenciais residentes.
    pub const fn max_credentials(mut self, count: u16) -> Self {
        self.max_credentials = count;
        self
    }
    /// Define o tamanho máximo de credential ID.
    pub const fn max_credential_id_length(mut self, len: u16) -> Self {
        self.max_credential_id_length = len;
        self
    }
    /// Define o tamanho máximo do `credBlob`.
    pub const fn max_cred_blob_length(mut self, len: u32) -> Self {
        self.max_cred_blob_length = len;
        self
    }
    /// Define o número de relying parties registrados.
    pub const fn rp_count(mut self, count: u32) -> Self {
        self.rp_count = count;
        self
    }

    /// Define o transporte ativo instanciado pelo autenticador.
    pub fn transport_config(mut self, config: TransportConfig) -> Self {
        self.transport_config = Some(config);
        self
    }

    /// Substitui os recursos de segurança herdados do board.
    pub const fn security(mut self, features: SecurityFeatures) -> Self {
        self.security = features;
        self
    }

    /// Adiciona um transporte anunciado, ignorando duplicatas.
    pub fn transport(mut self, transport: Transport) -> Self {
        if !self.transports.contains(&transport) {
            self.transports.push(transport);
        }
        self
    }

    /// Adiciona uma versão de protocolo, ignorando duplicatas.
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        if !self.protocols.contains(&protocol) {
            self.protocols.push(protocol);
        }
        self
    }

    /// Adiciona uma extensão WebAuthn, ignorando duplicatas.
    pub fn extension(mut self, extension: Extension) -> Self {
        if !self.extensions.contains(&extension) {
            self.extensions.push(extension);
        }
        self
    }

    /// Materializa o [`DeviceProfile`] final.
    pub fn build(self) -> DeviceProfile {
        DeviceProfile {
            product_name: self.product_name,
            vendor_name: self.vendor_name,
            aaguid: self.aaguid,
            firmware_version: self.firmware_version,
            hardware_version: self.hardware_version,
            transports: self.transports,
            protocols: self.protocols,
            attestation: self.attestation,
            attestation_format: self.attestation_format,
            attestation_cert: self.attestation_cert,
            pin_policy: self.pin_policy,
            rk_support: self.rk_support,
            uv_support: self.uv_support,
            up_support: self.up_support,
            storage_encrypted: self.storage_encrypted,
            crypto_accelerator: self.crypto_accelerator,
            extensions: self.extensions,
            max_credentials: self.max_credentials,
            max_credential_id_length: self.max_credential_id_length,
            max_cred_blob_length: self.max_cred_blob_length,
            rp_count: self.rp_count,
            transport_config: self.transport_config,
            security: self.security,
        }
    }
}

impl Default for DeviceProfileBuilder {
    fn default() -> Self {
        Self::new()
    }
}
