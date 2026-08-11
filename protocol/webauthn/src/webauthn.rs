use crypto::CryptoEngine;
use ctap2::{
    Ctap2Authenticator, Ctap2Error, GetAssertionRequest, GetAssertionResponse,
    MakeCredentialRequest, MakeCredentialResponse,
};
use log::debug;

/// Errors produced by the WebAuthn protocol layer before delegating to CTAP2.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WebAuthnError {
    #[error("client_data_hash must not be empty")]
    EmptyClientDataHash,
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

#[derive(Debug)]
pub struct WebAuthnAuthenticator {
    ctap: Ctap2Authenticator,
}

impl WebAuthnAuthenticator {
    pub fn new(
        aaguid: [u8; 16],
        crypto: CryptoEngine,
        storage: storage::StorageEngine,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        debug!("WebAuthn authenticator initialized");
        let ctap = Ctap2Authenticator::new(aaguid, crypto, storage)?;
        Ok(Self { ctap })
    }

    /// Validates the request and creates a credential, returning the
    /// authenticator data and (currently empty) attestation statement.
    pub fn make_credential(
        &mut self,
        request: MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Box<dyn std::error::Error>> {
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
    ) -> Result<GetAssertionResponse, Box<dyn std::error::Error>> {
        debug!("Processing WebAuthn GetAssertion request");
        validate_get_assertion(&request)?;
        let response = self.ctap.get_assertion(request)?;
        Ok(response)
    }

    pub fn get_info(&self) -> Result<ctap2::GetInfoResponse, Box<dyn std::error::Error>> {
        debug!("Processing WebAuthn GetInfo request");
        let response = self.ctap.get_info()?;
        Ok(response)
    }

    pub fn get_version(&self) -> Result<ctap2::GetVersionResponse, Box<dyn std::error::Error>> {
        debug!("Processing WebAuthn GetVersion request");
        let response = self.ctap.get_version()?;
        Ok(response)
    }

    pub fn process_command(&mut self, cmd: u8, data: Vec<u8>) -> Result<Vec<u8>, Ctap2Error> {
        self.ctap.process_command(cmd, data)
    }

    pub fn set_capabilities(&mut self, capabilities: ctap2::Ctap2Capabilities) {
        self.ctap.set_capabilities(capabilities);
    }

    pub fn capabilities(&self) -> &ctap2::Ctap2Capabilities {
        self.ctap.capabilities()
    }

    pub fn get_ctap(&self) -> &Ctap2Authenticator {
        &self.ctap
    }

    pub fn get_ctap_mut(&mut self) -> &mut Ctap2Authenticator {
        &mut self.ctap
    }
}
