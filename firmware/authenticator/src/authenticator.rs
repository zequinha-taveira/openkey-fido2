use board_generic::{
    BoardDefinition, BootselButton, Rp2350Qspi, UserPresenceButton, UserPresenceSource,
};
use core::fmt;
use crypto::CryptoEngine;
use device_profile::{
    Capabilities, CapabilityDiscovery, DeviceProfile, DeviceProfileBuilder, Extension, Protocol,
    TransportConfig, TransportType,
};
use log::info;
use std::path::PathBuf;
use storage::{FileStorageBackend, StorageEngine};
use transport::{BleGattTransport, NfcTransport, Transport, UsbCcidTransport, UsbHidTransport};
use webauthn::WebAuthnAuthenticator;

fn derive_key_from_path(path: &std::path::Path) -> [u8; 32] {
    use ring::digest;
    let path_bytes = path.to_string_lossy();
    let hash = digest::digest(&digest::SHA256, path_bytes.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_ref());
    key
}

extern crate alloc;

/// Autenticador FIDO2 completo, pronto para uso por um host ou transporte.
///
/// Reúne validação WebAuthn, estado CTAP2, criptografia, storage e o
/// transporte derivado do [`DeviceProfile`]. É a única API que integradores
/// precisam conhecer.
pub struct EmbeddedAuthenticator {
    webauthn: WebAuthnAuthenticator,
    discovery: CapabilityDiscovery,
    transport: Option<Box<dyn Transport>>,
}

impl EmbeddedAuthenticator {
    /// Cria um autenticador com o perfil genérico e storage em memória.
    ///
    /// Adequado a testes; produtos reais devem usar
    /// [`EmbeddedAuthenticator::new_with_board`] ou `new_with_profile`.
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_with_profile(DeviceProfileBuilder::new().build())
    }

    /// Cria um autenticador derivando o perfil de uma definição de board.
    ///
    /// AAGUID, transportes e features de segurança vêm do hardware.
    pub fn new_with_board(board: &BoardDefinition) -> Result<Self, Box<dyn std::error::Error>> {
        let profile = DeviceProfileBuilder::from_board(board).build();
        let mut auth = Self::new_with_profile(profile)?;
        auth.set_board_user_presence(board);
        Ok(auth)
    }

    /// Cria um autenticador a partir de um perfil de produto explícito.
    ///
    /// As capabilities do perfil são traduzidas para o formato do CTAP2
    /// GetInfo, mantendo perfil e resposta de protocolo em sincronia.
    pub fn new_with_profile(profile: DeviceProfile) -> Result<Self, Box<dyn std::error::Error>> {
        let crypto = CryptoEngine::new()?;
        let storage = StorageEngine::new()?;
        let authenticator = Self::from_profile_and_storage(profile, crypto, storage, None)?;

        info!("FIDO2 Embedded Authenticator initialized");
        Ok(authenticator)
    }

    /// Cria um autenticador com um perfil e um transporte fornecidos pelo chamador.
    ///
    /// O transporte injetado substitui o stub derivado de
    /// `profile.transport_config`. Ele não é inicializado implicitamente;
    /// controle o ciclo de vida por [`EmbeddedAuthenticator::transport_mut`].
    /// Isso permite compor um adaptador USB-HID com um backend de host ou de
    /// hardware sem alterar os construtores existentes.
    pub fn new_with_profile_and_transport(
        profile: DeviceProfile,
        transport: Box<dyn Transport>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let crypto = CryptoEngine::new()?;
        let storage = StorageEngine::new()?;
        let authenticator =
            Self::from_profile_and_storage(profile, crypto, storage, Some(transport))?;

        info!("FIDO2 Embedded Authenticator initialized with injected transport");
        Ok(authenticator)
    }

    /// Cria um autenticador com credenciais persistidas em arquivo.
    ///
    /// A chave-mestra é derivada do caminho do arquivo, de modo que reabrir o
    /// mesmo storage recupere as credenciais. Isso é adequado ao simulador e
    /// a testes — **não** a produtos, onde a chave deve vir de secure element.
    pub fn new_with_storage_path(
        path: PathBuf,
        profile: DeviceProfile,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let key = derive_key_from_path(&path);
        let crypto = CryptoEngine::from_key(key);
        let backend = FileStorageBackend::new(path)?;
        let storage = StorageEngine::with_backend(Box::new(backend));
        let authenticator = Self::from_profile_and_storage(profile, crypto, storage, None)?;

        info!("FIDO2 Embedded Authenticator initialized with persistent storage");
        Ok(authenticator)
    }

    fn from_profile_and_storage(
        profile: DeviceProfile,
        crypto: CryptoEngine,
        storage: StorageEngine,
        injected_transport: Option<Box<dyn Transport>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut webauthn = WebAuthnAuthenticator::new(profile.aaguid, crypto, storage)?;
        let transport = injected_transport.or_else(|| init_transport(&profile.transport_config));
        let discovery = CapabilityDiscovery::new(profile);
        webauthn.set_capabilities(ctap2_capabilities(&discovery.capabilities()));

        Ok(Self {
            webauthn,
            discovery,
            transport,
        })
    }

    /// Transporte configurado no perfil ou injetado pelo chamador, quando houver.
    pub fn transport(&self) -> Option<&dyn Transport> {
        self.transport.as_deref()
    }

    /// Acesso mutável ao transporte, para `init`/`send`/`recv`/`close`.
    pub fn transport_mut(&mut self) -> Option<&mut Box<dyn Transport>> {
        self.transport.as_mut()
    }

    /// Acesso à camada WebAuthn, para inspeção em testes e ferramentas.
    pub fn get_webauthn_authenticator(&self) -> &WebAuthnAuthenticator {
        &self.webauthn
    }

    /// Acesso mutável à camada WebAuthn (ajuste de capabilities, attestation).
    pub fn get_webauthn_authenticator_mut(&mut self) -> &mut WebAuthnAuthenticator {
        &mut self.webauthn
    }

    /// Runtime capability report derived from the device profile.
    pub fn capabilities(&self) -> Capabilities {
        self.discovery.capabilities()
    }

    /// Perfil de produto que originou este autenticador.
    pub fn profile(&self) -> &DeviceProfile {
        self.discovery.profile()
    }

    /// Define a fonte de user presence aplicada ao check de `up` no CTAP2.
    ///
    /// `None` (padrão) considera o usuário presente — adequado a simulação e
    /// testes sem botão físico.
    pub fn set_user_presence(&mut self, presence: Option<Box<dyn ctap2::UserPresence>>) {
        self.webauthn.set_user_presence(presence);
    }

    /// Injeta um botão de user presence do board (ex.: BOOTSEL do RP2350).
    pub fn set_user_presence_button<B>(&mut self, button: B)
    where
        B: UserPresenceButton + core::fmt::Debug + 'static,
    {
        self.set_user_presence(Some(Box::new(ButtonPresence(button))));
    }

    /// Aplica a fonte de user presence declarada no board ao check de `up`.
    ///
    /// Boards com [`UserPresenceSource::Bootsel`] (RP2350) ganham o sensor
    /// BOOTSEL automaticamente, sem chamada manual a
    /// [`EmbeddedAuthenticator::set_user_presence_button`].
    fn set_board_user_presence(&mut self, board: &BoardDefinition) {
        match board.presence_source {
            UserPresenceSource::Bootsel => {
                self.set_user_presence_button(BootselButton::new(Rp2350Qspi::new()));
            }
            UserPresenceSource::None => {}
        }
    }

    /// Registra uma nova credencial (CTAP2 `authenticatorMakeCredential`).
    pub fn make_credential(
        &mut self,
        request: ctap2::MakeCredentialRequest,
    ) -> Result<ctap2::MakeCredentialResponse, Box<dyn std::error::Error>> {
        self.webauthn.make_credential(request)
    }

    /// Autentica com uma credencial existente (CTAP2 `authenticatorGetAssertion`).
    pub fn get_assertion(
        &mut self,
        request: ctap2::GetAssertionRequest,
    ) -> Result<ctap2::GetAssertionResponse, Box<dyn std::error::Error>> {
        self.webauthn.get_assertion(request)
    }

    /// Reporta versões, extensões e opções suportadas (CTAP2 `getInfo`).
    pub fn get_info(&self) -> Result<ctap2::GetInfoResponse, Box<dyn std::error::Error>> {
        self.webauthn.get_info()
    }

    /// Reporta versão, commit e build do firmware (comando de vendor).
    pub fn get_version(&self) -> Result<ctap2::GetVersionResponse, Box<dyn std::error::Error>> {
        self.webauthn.get_version()
    }

    /// Processa um comando CTAP2 bruto em CBOR.
    ///
    /// Fronteira do protocolo: qualquer erro interno já chega ao chamador
    /// mapeado para um [`ctap2::Ctap2Error`] com código de status válido.
    pub fn process_command(
        &mut self,
        cmd: u8,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, ctap2::Ctap2Error> {
        self.webauthn.process_command(cmd, data)
    }
}

/// Adapta um [`UserPresenceButton`] do HAL para o [`ctap2::UserPresence`]
/// consumido pelo autenticador.
struct ButtonPresence<B>(B);

impl<B> core::fmt::Debug for ButtonPresence<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ButtonPresence").finish_non_exhaustive()
    }
}

impl<B: UserPresenceButton> ctap2::UserPresence for ButtonPresence<B> {
    fn is_present(&mut self) -> bool {
        self.0.is_pressed()
    }
}

impl fmt::Debug for EmbeddedAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmbeddedAuthenticator")
            .field("webauthn", &"...")
            .field("discovery", &self.discovery)
            .field("transport", &self.transport.is_some())
            .finish()
    }
}

fn init_transport(config: &Option<TransportConfig>) -> Option<Box<dyn Transport>> {
    let config = config.as_ref()?;
    match config.transport_type {
        TransportType::UsbHid => {
            info!("Transport configured: USB-HID (stub)");
            Some(Box::new(UsbHidTransport::new()))
        }
        TransportType::UsbCcid => {
            info!("Transport configured: USB-CCID (stub)");
            Some(Box::new(UsbCcidTransport::new()))
        }
        TransportType::Nfc => {
            info!("Transport configured: NFC (stub)");
            Some(Box::new(NfcTransport::new()))
        }
        TransportType::BleGatt => {
            info!("Transport configured: BLE GATT (stub)");
            Some(Box::new(BleGattTransport::new()))
        }
    }
}

/// Maps runtime capabilities to the CTAP2 GetInfo wire format.
fn ctap2_capabilities(caps: &Capabilities) -> ctap2::Ctap2Capabilities {
    let mut versions = alloc::vec::Vec::new();
    if caps.protocols.contains(&Protocol::Ctap2) {
        versions.push("2.0".to_string());
    }
    if caps.protocols.contains(&Protocol::Ctap21) {
        versions.push("2.1".to_string());
    }
    if versions.is_empty() {
        versions.push("2.0".to_string());
    }

    let mut extensions = alloc::vec::Vec::new();
    if caps.extensions.contains(&Extension::CredProtect) {
        extensions.push("credProtect".to_string());
    }
    if caps.extensions.contains(&Extension::CredBlob) {
        extensions.push("credBlob".to_string());
    }
    if caps.extensions.contains(&Extension::MinPinLength) {
        extensions.push("minPinLength".to_string());
    }
    if caps.extensions.contains(&Extension::HmacSecret) {
        extensions.push("hmac-secret".to_string());
    }

    let mut options = alloc::vec::Vec::new();
    if caps.rk {
        options.push("rk".to_string());
    }
    if caps.up {
        options.push("up".to_string());
    }
    if caps.uv {
        options.push("uv".to_string());
    }
    if caps.client_pin_available {
        options.push("clientPin".to_string());
        options.push("pinUvAuthToken".to_string());
    }
    // Credential Management é implementado pela máquina CTAP2 e precisa ser
    // anunciado para permitir tokens PIN com escopo CM.
    options.push("credMgmt".to_string());

    let pin_uv_auth_protocols = if caps.client_pin_available || caps.uv {
        alloc::vec![1, 2]
    } else {
        alloc::vec::Vec::new()
    };

    ctap2::Ctap2Capabilities {
        aaguid: caps.aaguid,
        versions,
        extensions,
        options,
        rp_count: caps.rp_count,
        max_cred_blob_length: caps.max_cred_blob_length,
        max_credential_id_length: caps.max_credential_id_length,
        max_credential_count: caps.max_credentials,
        firmware_version: caps.firmware_version.to_string(),
        min_pin_length: Some(4),
        pin_uv_auth_protocols,
        security: ctap2::SecurityFeatures {
            secure_boot: caps.security.secure_boot,
            trust_zone: caps.security.trust_zone,
            hardware_rng: caps.security.hardware_rng,
            sha256_accelerator: caps.security.sha256_accelerator,
            debug_disable: caps.security.debug_disable,
            otp_memory: caps.security.otp_memory,
            unique_id: caps.security.unique_id,
            tamper_detection: caps.security.tamper_detection,
        },
        max_large_blob_data_size: Some(4096),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_with_up(up: bool) -> ctap2::MakeCredentialRequest {
        ctap2::MakeCredentialRequest {
            client_data_hash: b"test".to_vec(),
            rp: ctap2::RelyingParty {
                id: "example.com".to_string(),
                name: None,
                icon: None,
            },
            user: ctap2::User {
                id: b"user123".to_vec(),
                name: None,
                display_name: None,
                icon_url: None,
            },
            pub_key_cred_params: vec![ctap2::PublicKeyCredParams {
                r#type: "public-key".to_string(),
                algorithms: -7,
            }],
            exclude_list: vec![],
            extensions: None,
            options: ctap2::MakeCredentialOptions {
                rk: false,
                uv: false,
                up,
                extended: false,
            },
            pin_uv_auth_param: None,
            pin_protocol: None,
            enterprise_protections: None,
        }
    }

    #[test]
    fn test_bootsel_user_presence_denied_when_not_pressed() {
        let mut auth = EmbeddedAuthenticator::new().unwrap();
        // BOOTSEL não pressionado (padrão: CS em nível alto) => up negado.
        auth.set_user_presence_button(BootselButton::new(Rp2350Qspi::new()));

        match auth.make_credential(request_with_up(true)) {
            Err(e) => assert_eq!(
                e.downcast_ref::<ctap2::Ctap2Error>(),
                Some(&ctap2::Ctap2Error::OperationDenied)
            ),
            Ok(_) => panic!("expected OperationDenied for BOOTSEL not pressed"),
        }
    }

    #[test]
    fn test_bootsel_user_presence_allowed_when_pressed() {
        let mut qspi = Rp2350Qspi::new();
        qspi.set_cs_level(false); // BOOTSEL pressionado (CS -> GND)
        let mut auth = EmbeddedAuthenticator::new().unwrap();
        auth.set_user_presence_button(BootselButton::new(qspi));

        assert!(auth.make_credential(request_with_up(true)).is_ok());
    }

    #[test]
    fn test_new_with_board_rp2350_auto_wires_bootsel_and_denies_up() {
        let mut auth = EmbeddedAuthenticator::new_with_board(&board_generic::RP2350).unwrap();
        // BOOTSEL idle (não pressionado) => up negado, sem chamada manual.
        match auth.make_credential(request_with_up(true)) {
            Err(e) => assert_eq!(
                e.downcast_ref::<ctap2::Ctap2Error>(),
                Some(&ctap2::Ctap2Error::OperationDenied)
            ),
            Ok(_) => panic!("expected OperationDenied for RP2350 auto-wired BOOTSEL"),
        }
    }

    #[test]
    fn test_new_with_board_generic_allows_up() {
        let mut auth = EmbeddedAuthenticator::new_with_board(&board_generic::GENERIC).unwrap();
        // Sem fonte automática => user presence ausente => up satisfeito.
        assert!(auth.make_credential(request_with_up(true)).is_ok());
    }
}
