use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::ctap2::Ctap2Authenticator;
use crate::ctap2::Ctap2Error;

extern crate alloc;

/// Request do comando ClientPIN (CTAP2 0x06).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPinRequest {
    /// Subcomando solicitado (ver [`ClientPinSubCommand`]).
    #[serde(rename = "subCommand")]
    pub sub_command: u8,
    /// Versão do pinUvAuthProtocol usada pelo cliente.
    #[serde(rename = "pinProtocol", skip_serializing_if = "Option::is_none")]
    pub pin_protocol: Option<u8>,
    /// Chave pública efêmera do cliente para o acordo de chaves.
    #[serde(rename = "keyAgreement", skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<Vec<u8>>,
    /// MAC que autentica os parâmetros do subcomando.
    #[serde(rename = "pinAuth", skip_serializing_if = "Option::is_none")]
    pub pin_auth: Option<Vec<u8>>,
    /// Novo PIN cifrado com o segredo compartilhado.
    #[serde(rename = "newPinEnc", skip_serializing_if = "Option::is_none")]
    pub new_pin_enc: Option<Vec<u8>>,
    /// Hash do PIN atual, cifrado com o segredo compartilhado.
    #[serde(rename = "pinHashEnc", skip_serializing_if = "Option::is_none")]
    pub pin_hash_enc: Option<Vec<u8>>,
}

/// Response do comando ClientPIN. Campos ausentes são omitidos do CBOR.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientPinResponse {
    /// Chave pública efêmera do autenticador.
    #[serde(rename = "keyAgreement", skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<Vec<u8>>,
    /// Token que autoriza operações subsequentes na mesma sessão.
    #[serde(rename = "pinUvAuthToken", skip_serializing_if = "Option::is_none")]
    pub pin_uv_auth_token: Option<Vec<u8>>,
    /// Tentativas de PIN restantes.
    #[serde(rename = "retries", skip_serializing_if = "Option::is_none")]
    pub retries: Option<u8>,
    /// `true` quando é preciso reenergizar o dispositivo para novas tentativas.
    #[serde(rename = "powerCycleState", skip_serializing_if = "Option::is_none")]
    pub power_cycle_state: Option<bool>,
}

/// Subcomandos do ClientPIN, conforme os códigos da especificação CTAP2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClientPinSubCommand {
    /// Define o PIN inicial.
    SetPIN = 0x01,
    /// Troca um PIN existente.
    ChangePIN = 0x02,
    /// Consulta tentativas restantes.
    GetPINRetries = 0x03,
    /// Obtém um pinUvAuthToken.
    GetPINToken = 0x05,
    /// Obtém o hash do PIN cifrado.
    GetPINHashEnc = 0x06,
}

impl ClientPinSubCommand {
    /// Converte o código do wire em subcomando; `None` se desconhecido.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::SetPIN),
            0x02 => Some(Self::ChangePIN),
            0x03 => Some(Self::GetPINRetries),
            0x05 => Some(Self::GetPINToken),
            0x06 => Some(Self::GetPINHashEnc),
            _ => None,
        }
    }
}

pub(crate) const PIN_MIN_LENGTH: usize = 4;
pub(crate) const PIN_MAX_RETRIES: u8 = 8;
pub(crate) const PIN_BLOCK_THRESHOLD: u8 = 3;
pub(crate) const PIN_STORAGE_KEY: &str = "client_pin_hash";
pub(crate) const PIN_RETRIES_KEY: &str = "client_pin_retries";
pub(crate) const SHARED_SECRET_KEY: &str = "client_pin_shared_secret";

/// Operações de PIN implementadas pelo autenticador.
///
/// O contador de tentativas é decrementado *antes* da verificação, para que
/// uma interrupção de energia no meio da checagem não conceda tentativas extras.
pub trait ClientPin {
    /// Tentativas de PIN restantes.
    fn get_pin_retries(&self) -> u8;
    /// Emite um pinUvAuthToken para a sessão atual.
    fn get_pin_token(&mut self) -> Result<Vec<u8>, Ctap2Error>;
    /// Define o PIN inicial. Falha se já houver PIN configurado.
    fn set_pin(&mut self, pin: &[u8]) -> Result<(), Ctap2Error>;
    /// Troca o PIN, exigindo o valor anterior.
    fn change_pin(&mut self, old_pin: &[u8], new_pin: &[u8]) -> Result<(), Ctap2Error>;
    /// Retorna o hash do PIN cifrado com o segredo compartilhado.
    fn get_pin_hash_enc(&mut self) -> Result<Vec<u8>, Ctap2Error>;
    /// Restaura o contador de tentativas após uma verificação bem-sucedida.
    fn reset_pin_retries(&mut self);
    /// Consome uma tentativa de PIN.
    fn decrement_pin_retries(&mut self);
    /// Verifica o PIN em tempo constante, ajustando o contador de tentativas.
    fn verify_pin(&mut self, pin: &[u8]) -> Result<(), Ctap2Error>;
}

fn read_retries(storage: &storage::StorageEngine) -> u8 {
    storage
        .retrieve(PIN_RETRIES_KEY)
        .ok()
        .and_then(|data| String::from_utf8(data).ok())
        .and_then(|s| s.parse::<u8>().ok())
        .unwrap_or(PIN_MAX_RETRIES)
}

/// Indica se já existe um PIN configurado no storage.
pub fn is_pin_set(storage: &storage::StorageEngine) -> bool {
    storage.retrieve(PIN_STORAGE_KEY).is_ok()
}

pub fn is_pin_blocked(storage: &storage::StorageEngine) -> bool {
    read_retries(storage) < PIN_BLOCK_THRESHOLD
}

pub(crate) fn handle_client_pin(
    authenticator: &mut Ctap2Authenticator,
    request: ClientPinRequest,
) -> Result<ClientPinResponse, Ctap2Error> {
    let sub = ClientPinSubCommand::from_u8(request.sub_command);

    match sub {
        Some(ClientPinSubCommand::GetPINRetries) => handle_get_retries(authenticator),
        Some(ClientPinSubCommand::SetPIN) => handle_set_pin(authenticator, request),
        Some(ClientPinSubCommand::ChangePIN) => handle_change_pin(authenticator, request),
        Some(ClientPinSubCommand::GetPINToken) => handle_get_pin_token(authenticator, request),
        Some(ClientPinSubCommand::GetPINHashEnc) => handle_get_pin_hash_enc(authenticator, request),
        None => Err(Ctap2Error::InvalidParameter),
    }
}

fn handle_get_retries(authenticator: &Ctap2Authenticator) -> Result<ClientPinResponse, Ctap2Error> {
    let retries = authenticator.get_pin_retries();
    let blocked = is_pin_blocked(authenticator.get_storage());

    Ok(ClientPinResponse {
        retries: Some(retries),
        power_cycle_state: if blocked { Some(true) } else { None },
        ..Default::default()
    })
}

fn handle_set_pin(
    authenticator: &mut Ctap2Authenticator,
    request: ClientPinRequest,
) -> Result<ClientPinResponse, Ctap2Error> {
    if is_pin_set(authenticator.get_storage()) {
        return Err(Ctap2Error::PinRequired);
    }

    let new_pin_enc = request.new_pin_enc.ok_or(Ctap2Error::InvalidParameter)?;

    let pin_bytes = authenticator
        .get_crypto()
        .decrypt(&new_pin_enc, &[0u8; 12])
        .map_err(|_| Ctap2Error::InvalidParameter)?;

    authenticator.set_pin(&pin_bytes)?;

    let shared_secret = authenticator
        .get_storage()
        .retrieve(SHARED_SECRET_KEY)
        .map_err(|_| Ctap2Error::InvalidState)?;

    Ok(ClientPinResponse {
        key_agreement: Some(shared_secret),
        ..Default::default()
    })
}

fn handle_change_pin(
    authenticator: &mut Ctap2Authenticator,
    request: ClientPinRequest,
) -> Result<ClientPinResponse, Ctap2Error> {
    if !is_pin_set(authenticator.get_storage()) {
        return Err(Ctap2Error::PinRequired);
    }

    if is_pin_blocked(authenticator.get_storage()) {
        return Err(Ctap2Error::PinInvalid);
    }

    let new_pin_enc = request.new_pin_enc.ok_or(Ctap2Error::InvalidParameter)?;
    let pin_hash_enc = request.pin_hash_enc.ok_or(Ctap2Error::InvalidParameter)?;

    let old_pin_bytes = authenticator
        .get_crypto()
        .decrypt(&pin_hash_enc, &[0u8; 12])
        .map_err(|_| Ctap2Error::InvalidParameter)?;

    let new_pin_bytes = authenticator
        .get_crypto()
        .decrypt(&new_pin_enc, &[0u8; 12])
        .map_err(|_| Ctap2Error::InvalidParameter)?;

    authenticator.change_pin(&old_pin_bytes, &new_pin_bytes)?;

    Ok(ClientPinResponse::default())
}

fn handle_get_pin_token(
    authenticator: &mut Ctap2Authenticator,
    request: ClientPinRequest,
) -> Result<ClientPinResponse, Ctap2Error> {
    if !is_pin_set(authenticator.get_storage()) {
        return Err(Ctap2Error::PinRequired);
    }

    if is_pin_blocked(authenticator.get_storage()) {
        return Err(Ctap2Error::PinInvalid);
    }

    if let Some(pin_hash_enc) = request.pin_hash_enc {
        let submitted_hash = authenticator
            .get_crypto()
            .decrypt(&pin_hash_enc, &[0u8; 12])
            .map_err(|_| Ctap2Error::InvalidParameter)?;

        let stored_hash = authenticator
            .get_storage()
            .retrieve(PIN_STORAGE_KEY)
            .map_err(|_| Ctap2Error::PinRequired)?;

        if submitted_hash != stored_hash {
            authenticator.decrement_pin_retries();
            return Err(Ctap2Error::PinInvalid);
        }

        authenticator.reset_pin_retries();
    } else {
        return Err(Ctap2Error::PinTokenRequired);
    }

    let token = authenticator.get_pin_token()?;

    Ok(ClientPinResponse {
        pin_uv_auth_token: Some(token),
        ..Default::default()
    })
}

fn handle_get_pin_hash_enc(
    authenticator: &mut Ctap2Authenticator,
    _request: ClientPinRequest,
) -> Result<ClientPinResponse, Ctap2Error> {
    if !is_pin_set(authenticator.get_storage()) {
        return Err(Ctap2Error::PinRequired);
    }

    if is_pin_blocked(authenticator.get_storage()) {
        return Err(Ctap2Error::PinInvalid);
    }

    let hash_enc = authenticator.get_pin_hash_enc()?;

    Ok(ClientPinResponse {
        key_agreement: Some(hash_enc),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctap2::{Ctap2Authenticator, AAGUID};
    use crypto::CryptoEngine;
    use storage::StorageEngine;

    fn create_authenticator() -> Ctap2Authenticator {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap()
    }

    #[test]
    fn test_get_pin_retries_initial() {
        let authenticator = create_authenticator();
        assert_eq!(authenticator.get_pin_retries(), PIN_MAX_RETRIES);
    }

    #[test]
    fn test_set_pin_success() {
        let mut authenticator = create_authenticator();
        let pin = b"1234";
        let result = authenticator.set_pin(pin);
        assert!(result.is_ok());
        assert!(is_pin_set(authenticator.get_storage()));
    }

    #[test]
    fn test_set_pin_too_short() {
        let mut authenticator = create_authenticator();
        let pin = b"12";
        let result = authenticator.set_pin(pin);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Ctap2Error::PinPolicyViolation);
    }

    #[test]
    fn test_change_pin_success() {
        let mut authenticator = create_authenticator();
        authenticator.set_pin(b"1234").unwrap();
        let result = authenticator.change_pin(b"1234", b"5678");
        assert!(result.is_ok());

        let new_hash = authenticator.get_crypto().sha256(b"5678");
        let stored = authenticator
            .get_storage()
            .retrieve(PIN_STORAGE_KEY)
            .unwrap();
        assert_eq!(stored, new_hash);
    }

    #[test]
    fn test_change_pin_wrong_old() {
        let mut authenticator = create_authenticator();
        authenticator.set_pin(b"1234").unwrap();
        let result = authenticator.change_pin(b"9999", b"5678");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Ctap2Error::PinInvalid);
    }

    #[test]
    fn test_change_pin_new_too_short() {
        let mut authenticator = create_authenticator();
        authenticator.set_pin(b"1234").unwrap();
        let result = authenticator.change_pin(b"1234", b"12");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Ctap2Error::PinPolicyViolation);
    }

    #[test]
    fn test_get_pin_token() {
        let mut authenticator = create_authenticator();
        authenticator.set_pin(b"1234").unwrap();
        let result = authenticator.get_pin_token();
        assert!(result.is_ok());
        let token = result.unwrap();
        assert!(!token.is_empty());
    }

    #[test]
    fn test_get_pin_token_no_pin() {
        let mut authenticator = create_authenticator();
        let result = authenticator.get_pin_token();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Ctap2Error::PinRequired);
    }

    #[test]
    fn test_get_pin_hash_enc() {
        let mut authenticator = create_authenticator();
        authenticator.set_pin(b"1234").unwrap();
        let result = authenticator.get_pin_hash_enc();
        assert!(result.is_ok());
        let hash_enc = result.unwrap();
        assert!(!hash_enc.is_empty());
    }

    #[test]
    fn test_get_pin_hash_enc_no_pin() {
        let mut authenticator = create_authenticator();
        let result = authenticator.get_pin_hash_enc();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Ctap2Error::PinRequired);
    }

    #[test]
    fn test_pin_retry_counter_decrement() {
        let mut authenticator = create_authenticator();
        authenticator.set_pin(b"1234").unwrap();

        authenticator.change_pin(b"wrong", b"5678").ok();
        assert_eq!(authenticator.get_pin_retries(), PIN_MAX_RETRIES - 1);

        authenticator.change_pin(b"wrong", b"5678").ok();
        assert_eq!(authenticator.get_pin_retries(), PIN_MAX_RETRIES - 2);
    }

    #[test]
    fn test_pin_retry_counter_reset() {
        let mut authenticator = create_authenticator();
        authenticator.set_pin(b"1234").unwrap();

        authenticator.change_pin(b"wrong", b"5678").ok();
        assert_eq!(authenticator.get_pin_retries(), PIN_MAX_RETRIES - 1);

        authenticator.change_pin(b"1234", b"5678").unwrap();
        assert_eq!(authenticator.get_pin_retries(), PIN_MAX_RETRIES);
    }

    #[test]
    fn test_pin_blocked_after_threshold() {
        let mut authenticator = create_authenticator();
        authenticator.set_pin(b"1234").unwrap();

        for _ in 0..(PIN_MAX_RETRIES - PIN_BLOCK_THRESHOLD + 1) {
            authenticator.change_pin(b"wrong", b"5678").ok();
        }

        assert!(is_pin_blocked(authenticator.get_storage()));
    }

    #[test]
    fn test_pin_protocol_negotiation() {
        let mut authenticator = create_authenticator();
        let request = ClientPinRequest {
            sub_command: ClientPinSubCommand::GetPINRetries as u8,
            pin_protocol: Some(1),
            key_agreement: None,
            pin_auth: None,
            new_pin_enc: None,
            pin_hash_enc: None,
        };

        let response = handle_client_pin(&mut authenticator, request);
        assert!(response.is_ok());
    }

    #[test]
    fn test_client_pin_response_default() {
        let response = ClientPinResponse::default();
        assert!(response.key_agreement.is_none());
        assert!(response.pin_uv_auth_token.is_none());
        assert!(response.retries.is_none());
        assert!(response.power_cycle_state.is_none());
    }
}
