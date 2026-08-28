extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use crypto::CryptoEngine;
use ctap2::{
    Ctap2Authenticator, Ctap2Error, GetAssertionRequest, GetAssertionResponse,
    MakeCredentialRequest, MakeCredentialResponse,
};
use log::debug;

/// Errors produced by the WebAuthn protocol layer before delegating to CTAP2.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WebAuthnError {
    #[error("client_data_hash must not be empty")]
    EmptyClientDataHash,
    #[allow(dead_code)]
    #[error("client_data_json must not be empty")]
    EmptyClientDataJson,
    #[error("rp_id must not be empty")]
    EmptyRpId,
}

fn validate_make_credential(request: &MakeCredentialRequest) -> Result<(), WebAuthnError> {
    if request.rp.id.trim().is_empty() {
        return Err(WebAuthnError::EmptyRpId);
    }
    if request.client_data_hash.is_empty() {
        return Err(WebAuthnError::EmptyClientDataHash);
    }
    Ok(())
}

fn validate_get_assertion(request: &GetAssertionRequest) -> Result<(), WebAuthnError> {
    if request.rp_id.trim().is_empty() {
        return Err(WebAuthnError::EmptyRpId);
    }
    if request.client_data_hash.is_empty() {
        return Err(WebAuthnError::EmptyClientDataHash);
    }
    Ok(())
}

/// Autenticador WebAuthn que valida requests e delega ao CTAP2.
///
/// Mantém um [`Ctap2Authenticator`] interno e expõe métodos de alto nível
/// com validação de campos obrigatórios.
#[derive(Debug)]
pub struct WebAuthnAuthenticator {
    ctap: Ctap2Authenticator,
}

impl WebAuthnAuthenticator {
    /// Cria um autenticador WebAuthn com crypto e storage fornecidos.
    pub fn new(
        aaguid: [u8; 16],
        crypto: CryptoEngine,
        storage: storage::StorageEngine,
    ) -> Result<Self, Box<dyn core::error::Error>> {
        debug!("WebAuthn authenticator initialized");
        let ctap = Ctap2Authenticator::new(aaguid, crypto, storage)?;
        Ok(Self { ctap })
    }

    /// Validates the request and creates a credential, returning the
    /// authenticator data and (currently empty) attestation statement.
    pub fn make_credential(
        &mut self,
        request: MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Box<dyn core::error::Error>> {
        debug!("Processing WebAuthn MakeCredential request");
        validate_make_credential(&request)?;
        let response = self.ctap.make_credential(request)?;
        Ok(response)
    }

    /// Validates the request and produces an assertion for the selected
    /// credential, bumping and persisting the sign counter.
    pub fn get_assertion(
        &mut self,
        request: GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Box<dyn core::error::Error>> {
        debug!("Processing WebAuthn GetAssertion request");
        validate_get_assertion(&request)?;
        let response = self.ctap.get_assertion(request)?;
        Ok(response)
    }

    /// Retorna capacidades do autenticador via GetInfo.
    pub fn get_info(&self) -> Result<ctap2::GetInfoResponse, Box<dyn core::error::Error>> {
        debug!("Processing WebAuthn GetInfo request");
        let response = self.ctap.get_info()?;
        Ok(response)
    }

    /// Retorna metadados do firmware via GetVersion.
    pub fn get_version(&self) -> Result<ctap2::GetVersionResponse, Box<dyn core::error::Error>> {
        debug!("Processing WebAuthn GetVersion request");
        let response = self.ctap.get_version()?;
        Ok(response)
    }

    /// Processa um comando CTAP2 bruto (byte + payload CBOR).
    pub fn process_command(&mut self, cmd: u8, data: Vec<u8>) -> Result<Vec<u8>, Ctap2Error> {
        self.ctap.process_command(cmd, data)
    }

    /// Define capacidades do autovicador reportadas no GetInfo.
    pub fn set_capabilities(&mut self, capabilities: ctap2::Ctap2Capabilities) {
        self.ctap.set_capabilities(capabilities);
    }

    /// Define a fonte de user presence (check de `up`) no CTAP2 subjacente.
    pub fn set_user_presence(&mut self, presence: Option<Box<dyn ctap2::UserPresence>>) {
        self.ctap.set_user_presence(presence);
    }

    /// Retorna referência imutável às capacidades configuradas.
    pub fn capabilities(&self) -> &ctap2::Ctap2Capabilities {
        self.ctap.capabilities()
    }

    /// Retorna referência imutável ao autenticador CTAP2 interno.
    pub fn get_ctap(&self) -> &Ctap2Authenticator {
        &self.ctap
    }

    /// Retorna referência mutável ao autenticador CTAP2 interno.
    pub fn get_ctap_mut(&mut self) -> &mut Ctap2Authenticator {
        &mut self.ctap
    }
}
