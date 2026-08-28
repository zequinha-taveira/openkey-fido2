//! authenticatorConfig (0x0D) — CTAP 2.1 §6.11.
//!
//! Subcomandos: `enableEnterpriseAttestation` (0x01), `toggleAlwaysUv`
//! (0x02), `setMinPINLength` (0x03), `makeCredUvNotRqd` (0x04) e
//! `setMinPINLengthRPIDs` (0x05). Todos exigem `pinUvAuthParam` com a
//! permissão `acfg` (0x20), MAC sobre `0x0D || subCommand || subCommandParams`.
//!
//! Decisões de design (erros de enforcement, `currentPIN` cifrado com o
//! segredo compartilhado da sessão, flag `forceChangePin`): ver
//! `docs/adr/ADR-0021-authnr-config-e-gates-de-hardware.md`.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use ciborium::de::from_reader;
use ciborium::ser::into_writer;
use ciborium::value::Integer;
use ciborium::Value;
use crypto::pin_protocol::strip_zero_padding;

use crate::client_pin::{
    is_pin_set, PERMISSION_ACFG, PIN_MAX_LENGTH, PIN_MIN_LENGTH, PIN_STORAGE_KEY,
};
use crate::ctap2::Ctap2Authenticator;
use crate::ctap2::Ctap2Error;

extern crate alloc;

/// Serializa um valor em CBOR para persistência no kv-store.
///
/// Substitui o antigo `serde_json::to_vec` para manter a crate compilável em
/// alvos `no_std`; o formato é opaco ao protocolo (só este módulo relê).
fn cbor_to_vec<T: serde::Serialize + ?Sized>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    // Escrita em Vec<u8> é infalível (ciborium_io::Write for Vec<u8>).
    let _ = into_writer(value, &mut out);
    out
}

/// Subcomandos do authenticatorConfig (CTAP 2.1 §6.11).
pub mod sub_commands {
    pub const ENABLE_ENTERPRISE_ATTESTATION: u8 = 0x01;
    pub const TOGGLE_ALWAYS_UV: u8 = 0x02;
    pub const SET_MIN_PIN_LENGTH: u8 = 0x03;
    pub const MAKE_CRED_UV_NOT_RQD: u8 = 0x04;
    pub const SET_MIN_PIN_LENGTH_RPIDS: u8 = 0x05;
}

/// Número máximo de RP IDs aceitos em `setMinPINLengthRPIDs`.
pub(crate) const MAX_MIN_PIN_LENGTH_RPIDS: usize = 32;

const CFG_ALWAYS_UV_KEY: &str = "sys:cfg_always_uv";
const CFG_MAKE_CRED_UV_NOT_RQD_KEY: &str = "sys:cfg_mc_uv_not_rqd";
const CFG_MIN_PIN_LENGTH_KEY: &str = "sys:cfg_min_pin_length";
const CFG_MIN_PIN_LENGTH_RPIDS_KEY: &str = "sys:cfg_min_pin_length_rpids";
const CFG_FORCE_CHANGE_PIN_KEY: &str = "sys:cfg_force_change_pin";
const CFG_EP_PENDING_KEY: &str = "sys:cfg_ep_pending";

/// Request do authenticatorConfig decodificado do wire.
#[derive(Debug)]
struct AuthnrConfigRequest {
    sub_command: u8,
    params: Option<Value>,
    pin_uv_auth_protocol: Option<u8>,
    pin_uv_auth_param: Option<Vec<u8>>,
}

/// Processa o comando authenticatorConfig (0x0D). Response é vazia em sucesso.
pub(crate) fn handle_authnr_config(
    authenticator: &mut Ctap2Authenticator,
    data: &[u8],
) -> Result<Vec<u8>, Ctap2Error> {
    let request = decode_authnr_config_request(data)?;

    // Subcomandos que alteram política exigem PIN configurado.
    if request.sub_command != sub_commands::ENABLE_ENTERPRISE_ATTESTATION
        && !is_pin_set(authenticator.get_storage())
    {
        return Err(Ctap2Error::PinNotSet);
    }

    let protocol = request
        .pin_uv_auth_protocol
        .ok_or(Ctap2Error::MissingParameter)?;
    let pin_auth = request
        .pin_uv_auth_param
        .as_deref()
        .ok_or(Ctap2Error::MissingParameter)?;
    let auth_message = authnr_config_auth_message(data)?;
    authenticator.verify_pin_uv_auth_for_operation(
        Some(protocol),
        Some(pin_auth),
        &auth_message,
        PERMISSION_ACFG,
        None,
    )?;

    match request.sub_command {
        sub_commands::ENABLE_ENTERPRISE_ATTESTATION => {
            authenticator
                .get_storage_mut()
                .store(CFG_EP_PENDING_KEY, b"1".to_vec())
                .map_err(|_| Ctap2Error::Unknown)?;
        }
        sub_commands::TOGGLE_ALWAYS_UV => toggle_flag(authenticator, CFG_ALWAYS_UV_KEY)?,
        sub_commands::MAKE_CRED_UV_NOT_RQD => {
            toggle_flag(authenticator, CFG_MAKE_CRED_UV_NOT_RQD_KEY)?;
        }
        sub_commands::SET_MIN_PIN_LENGTH => {
            handle_set_min_pin_length(authenticator, request.params.as_ref())?;
        }
        sub_commands::SET_MIN_PIN_LENGTH_RPIDS => {
            handle_set_min_pin_length_rpids(authenticator, request.params.as_ref())?;
        }
        _ => return Err(Ctap2Error::InvalidParameter),
    }

    Ok(Vec::new())
}

fn toggle_flag(authenticator: &mut Ctap2Authenticator, key: &str) -> Result<(), Ctap2Error> {
    let current = authenticator.get_storage().retrieve(key).is_ok();
    if current {
        let _ = authenticator.get_storage_mut().delete(key);
    } else {
        authenticator
            .get_storage_mut()
            .store(key, b"1".to_vec())
            .map_err(|_| Ctap2Error::Unknown)?;
    }
    Ok(())
}

fn handle_set_min_pin_length(
    authenticator: &mut Ctap2Authenticator,
    params: Option<&Value>,
) -> Result<(), Ctap2Error> {
    let map = params_map(params)?;

    let new_min = param_u8(&map, 0x02, "newMinPINLength")?.ok_or(Ctap2Error::MissingParameter)?;
    if new_min < PIN_MIN_LENGTH as u8 || new_min > PIN_MAX_LENGTH as u8 {
        return Err(Ctap2Error::PinPolicyViolation);
    }

    let force_change = param_bool(&map, 0x04, "forceChangePin")?.unwrap_or(false);
    let rpids = param_text_array(&map, 0x03, "minPinLengthRpIDs")?;

    if let Some(current_pin) = param_bytes(&map, 0x01, "currentPIN")? {
        verify_current_pin(authenticator, &current_pin)?;
    } else if force_change {
        return Err(Ctap2Error::MissingParameter);
    }

    authenticator
        .get_storage_mut()
        .store(CFG_MIN_PIN_LENGTH_KEY, vec![new_min])
        .map_err(|_| Ctap2Error::Unknown)?;
    if let Some(rpids) = rpids {
        authenticator
            .get_storage_mut()
            .store(CFG_MIN_PIN_LENGTH_RPIDS_KEY, cbor_to_vec(&rpids))
            .map_err(|_| Ctap2Error::Unknown)?;
    }
    if force_change {
        authenticator
            .get_storage_mut()
            .store(CFG_FORCE_CHANGE_PIN_KEY, b"1".to_vec())
            .map_err(|_| Ctap2Error::Unknown)?;
    } else {
        let _ = authenticator
            .get_storage_mut()
            .delete(CFG_FORCE_CHANGE_PIN_KEY);
    }
    Ok(())
}

fn handle_set_min_pin_length_rpids(
    authenticator: &mut Ctap2Authenticator,
    params: Option<&Value>,
) -> Result<(), Ctap2Error> {
    let map = params_map(params)?;
    let rpids = param_text_array(&map, 0x01, "rpIds")?.ok_or(Ctap2Error::MissingParameter)?;
    if rpids.len() > MAX_MIN_PIN_LENGTH_RPIDS {
        return Err(Ctap2Error::InvalidParameter);
    }
    authenticator
        .get_storage_mut()
        .store(CFG_MIN_PIN_LENGTH_RPIDS_KEY, cbor_to_vec(&rpids))
        .map_err(|_| Ctap2Error::Unknown)?;
    Ok(())
}

/// Verifica o `currentPIN` cifrado contra o hash do PIN armazenado.
///
/// O plaintext esperado é o **PIN cru com zero-padding** — a mesma convenção
/// do `newPinEnc` (CTAP 2.1 §6.5.5.5), não um hash. Após decifrar e remover
/// o padding, o PIN recuperado é re-hasheado com SHA-256 e comparado em
/// tempo constante aos primeiros 16 bytes do valor armazenado. O segredo
/// compartilhado da sessão é consumido nesta operação (ADR-0021).
fn verify_current_pin(
    authenticator: &mut Ctap2Authenticator,
    encrypted: &[u8],
) -> Result<(), Ctap2Error> {
    let (secret, protocol) = authenticator
        .take_pin_shared_secret()
        .ok_or(Ctap2Error::PinAuthInvalid)?;
    let protocol = crypto::pin_protocol::PinUvProtocol::new(protocol)
        .map_err(|_| Ctap2Error::PinAuthInvalid)?;
    let padded = protocol
        .decrypt(&secret, encrypted)
        .map_err(|_| Ctap2Error::PinAuthInvalid)?;
    let submitted = strip_zero_padding(&padded).map_err(|_| Ctap2Error::PinAuthInvalid)?;

    let stored_hash = authenticator
        .get_storage()
        .retrieve(PIN_STORAGE_KEY)
        .map_err(|_| Ctap2Error::PinNotSet)?;
    let submitted_hash = authenticator.get_crypto().sha256(&submitted);
    if !crypto::constant_time_eq(&submitted_hash[..16], &stored_hash) {
        return Err(Ctap2Error::PinInvalid);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Estado persistido (consultado por ctap2.rs e client_pin.rs)
// ---------------------------------------------------------------------------

/// `alwaysUv` está habilitado?
pub fn is_always_uv(storage: &storage::StorageEngine) -> bool {
    storage.retrieve(CFG_ALWAYS_UV_KEY).is_ok()
}

/// `makeCredUvNotRqd` está habilitado?
pub fn is_make_cred_uv_not_rqd(storage: &storage::StorageEngine) -> bool {
    storage.retrieve(CFG_MAKE_CRED_UV_NOT_RQD_KEY).is_ok()
}

/// O PIN precisa ser trocado antes de emitir um novo pinUvAuthToken?
pub fn is_force_change_pin(storage: &storage::StorageEngine) -> bool {
    storage.retrieve(CFG_FORCE_CHANGE_PIN_KEY).is_ok()
}

/// Comprimento mínimo de PIN configurado, com fallback para o perfil.
pub fn get_min_pin_length(storage: &storage::StorageEngine, fallback: u32) -> u32 {
    storage
        .retrieve(CFG_MIN_PIN_LENGTH_KEY)
        .ok()
        .and_then(|data| data.first().copied())
        .map(u32::from)
        .unwrap_or(fallback)
}

/// Consome o flag de Enterprise Attestation pendente (one-shot).
///
/// Retorna `true` se o flag estava ativo; ele é removido ao ser consumido.
pub fn consume_ep_pending(storage: &mut storage::StorageEngine) -> bool {
    let was_pending = storage.retrieve(CFG_EP_PENDING_KEY).is_ok();
    if was_pending {
        let _ = storage.delete(CFG_EP_PENDING_KEY);
    }
    was_pending
}

// ---------------------------------------------------------------------------
// Codec CBOR
// ---------------------------------------------------------------------------

/// Decodifica o request do authenticatorConfig.
///
/// Aceita mapa com chaves inteiras (CTAP 2.1) e, por compatibilidade, chaves
/// string. Payloads com bytes residuais após o item CBOR são rejeitados.
fn decode_authnr_config_request(data: &[u8]) -> Result<AuthnrConfigRequest, Ctap2Error> {
    let mut restante = data;
    let value: Value = from_reader(&mut restante).map_err(|_| Ctap2Error::InvalidCbor)?;
    if !restante.is_empty() {
        return Err(Ctap2Error::InvalidCbor);
    }

    let Value::Map(entries) = value else {
        return Err(Ctap2Error::InvalidCbor);
    };

    let mut request = AuthnrConfigRequest {
        sub_command: 0,
        params: None,
        pin_uv_auth_protocol: None,
        pin_uv_auth_param: None,
    };
    for (key, val) in entries {
        let name = match &key {
            Value::Integer(number) => match i64::try_from(*number).unwrap_or_default() {
                0x01 => Some("subCommand"),
                0x02 => Some("subCommandParams"),
                0x03 => Some("pinUvAuthProtocol"),
                0x04 => Some("pinUvAuthParam"),
                _ => None,
            },
            Value::Text(text) => match text.as_str() {
                "subCommand" => Some("subCommand"),
                "subCommandParams" => Some("subCommandParams"),
                "pinUvAuthProtocol" => Some("pinUvAuthProtocol"),
                "pinUvAuthParam" => Some("pinUvAuthParam"),
                _ => None,
            },
            _ => None,
        };
        match name {
            Some("subCommand") => request.sub_command = value_to_u8(&val)?,
            Some("subCommandParams") => request.params = Some(val),
            Some("pinUvAuthProtocol") => request.pin_uv_auth_protocol = Some(value_to_u8(&val)?),
            Some("pinUvAuthParam") => request.pin_uv_auth_param = Some(value_to_bytes(&val)?),
            _ => {}
        }
    }
    if request.sub_command == 0 {
        return Err(Ctap2Error::MissingParameter);
    }
    Ok(request)
}

/// Reconstrói a mensagem autenticada: `0x0D || subCommand || subCommandParams`.
///
/// `subCommandParams` é re-codificado exatamente como chegou no request
/// (mesma técnica de `credential_management_auth_message`).
fn authnr_config_auth_message(data: &[u8]) -> Result<Vec<u8>, Ctap2Error> {
    let mut restante = data;
    let value: Value = from_reader(&mut restante).map_err(|_| Ctap2Error::InvalidCbor)?;
    if !restante.is_empty() {
        return Err(Ctap2Error::InvalidCbor);
    }
    let Value::Map(entries) = value else {
        return Err(Ctap2Error::InvalidCbor);
    };

    let mut sub_command = None;
    let mut params: Option<Value> = None;
    for (key, val) in entries {
        match &key {
            Value::Integer(number) if *number == Integer::from(1) => sub_command = Some(val),
            Value::Text(text) if text == "subCommand" => sub_command = Some(val),
            Value::Integer(number) if *number == Integer::from(2) => params = Some(val),
            Value::Text(text) if text == "subCommandParams" => params = Some(val),
            _ => {}
        }
    }
    let sub_command = match sub_command {
        Some(Value::Integer(number)) => {
            u8::try_from(number).map_err(|_| Ctap2Error::InvalidParameter)?
        }
        _ => return Err(Ctap2Error::InvalidParameter),
    };

    let mut message = vec![0x0D, sub_command];
    if let Some(params) = params {
        into_writer(&params, &mut message).map_err(|_| Ctap2Error::InvalidCbor)?;
    }
    Ok(message)
}

fn params_map(params: Option<&Value>) -> Result<Vec<(Value, Value)>, Ctap2Error> {
    match params {
        Some(Value::Map(entries)) => Ok(entries.clone()),
        _ => Err(Ctap2Error::InvalidParameter),
    }
}

fn param_u8(map: &[(Value, Value)], key_int: u8, key_text: &str) -> Result<Option<u8>, Ctap2Error> {
    for (key, val) in map {
        let is_match = match key {
            Value::Integer(number) => u8::try_from(i64::try_from(*number).unwrap_or_default())
                .map(|n| n == key_int)
                .unwrap_or(false),
            Value::Text(text) => text == key_text,
            _ => false,
        };
        if is_match {
            return Ok(Some(value_to_u8(val)?));
        }
    }
    Ok(None)
}

fn param_bool(
    map: &[(Value, Value)],
    key_int: u8,
    key_text: &str,
) -> Result<Option<bool>, Ctap2Error> {
    for (key, val) in map {
        let is_match = match key {
            Value::Integer(number) => u8::try_from(i64::try_from(*number).unwrap_or_default())
                .map(|n| n == key_int)
                .unwrap_or(false),
            Value::Text(text) => text == key_text,
            _ => false,
        };
        if is_match {
            return Ok(Some(value_to_bool(val)?));
        }
    }
    Ok(None)
}

fn param_bytes(
    map: &[(Value, Value)],
    key_int: u8,
    key_text: &str,
) -> Result<Option<Vec<u8>>, Ctap2Error> {
    for (key, val) in map {
        let is_match = match key {
            Value::Integer(number) => u8::try_from(i64::try_from(*number).unwrap_or_default())
                .map(|n| n == key_int)
                .unwrap_or(false),
            Value::Text(text) => text == key_text,
            _ => false,
        };
        if is_match {
            return Ok(Some(value_to_bytes(val)?));
        }
    }
    Ok(None)
}

fn param_text_array(
    map: &[(Value, Value)],
    key_int: u8,
    key_text: &str,
) -> Result<Option<Vec<String>>, Ctap2Error> {
    for (key, val) in map {
        let is_match = match key {
            Value::Integer(number) => u8::try_from(i64::try_from(*number).unwrap_or_default())
                .map(|n| n == key_int)
                .unwrap_or(false),
            Value::Text(text) => text == key_text,
            _ => false,
        };
        if is_match {
            let Value::Array(items) = val else {
                return Err(Ctap2Error::InvalidParameter);
            };
            let mut rpids = Vec::with_capacity(items.len());
            for item in items {
                rpids.push(value_to_text(item)?);
            }
            return Ok(Some(rpids));
        }
    }
    Ok(None)
}

fn value_to_u8(value: &Value) -> Result<u8, Ctap2Error> {
    match value {
        Value::Integer(number) => u8::try_from(*number).map_err(|_| Ctap2Error::InvalidParameter),
        _ => Err(Ctap2Error::InvalidParameter),
    }
}

fn value_to_bool(value: &Value) -> Result<bool, Ctap2Error> {
    match value {
        Value::Bool(flag) => Ok(*flag),
        _ => Err(Ctap2Error::InvalidParameter),
    }
}

fn value_to_bytes(value: &Value) -> Result<Vec<u8>, Ctap2Error> {
    match value {
        Value::Bytes(bytes) => Ok(bytes.clone()),
        _ => Err(Ctap2Error::InvalidParameter),
    }
}

fn value_to_text(value: &Value) -> Result<String, Ctap2Error> {
    match value {
        Value::Text(text) => Ok(text.clone()),
        _ => Err(Ctap2Error::InvalidParameter),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctap2::{
        Ctap2Authenticator, GetAssertionOptions, GetAssertionRequest, MakeCredentialOptions,
        MakeCredentialRequest, PublicKeyCredParams, RelyingParty, User, AAGUID,
    };
    use crypto::CryptoEngine;
    use storage::StorageEngine;

    fn make_authenticator() -> Ctap2Authenticator {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap()
    }

    fn make_credential_request(uv: bool) -> MakeCredentialRequest {
        MakeCredentialRequest {
            client_data_hash: vec![0x11; 32],
            rp: RelyingParty {
                id: "example.com".to_string(),
                name: None,
                icon: None,
            },
            user: User {
                id: b"user".to_vec(),
                name: None,
                display_name: None,
                icon_url: None,
            },
            pub_key_cred_params: vec![PublicKeyCredParams {
                r#type: "public-key".to_string(),
                algorithms: -7,
            }],
            exclude_list: vec![],
            extensions: None,
            options: MakeCredentialOptions {
                rk: false,
                uv,
                up: false,
                extended: false,
            },
            pin_uv_auth_param: None,
            pin_protocol: None,
            enterprise_protections: None,
        }
    }

    fn compute_mac(token: &[u8], protocol: u8, message: &[u8]) -> Vec<u8> {
        crypto::pin_protocol::PinUvProtocol::new(protocol)
            .unwrap()
            .authenticate(token, message)
            .unwrap()
    }

    fn config_request_bytes(sub_command: u8, params: Option<Value>) -> Vec<u8> {
        let mut map: alloc::collections::BTreeMap<Integer, Value> =
            alloc::collections::BTreeMap::new();
        map.insert(
            Integer::from(0x01),
            Value::Integer(Integer::from(sub_command)),
        );
        if let Some(params) = params {
            map.insert(Integer::from(0x02), params);
        }
        let entries: Vec<(Value, Value)> = map
            .into_iter()
            .map(|(k, v)| (Value::Integer(k), v))
            .collect();
        let mut buf = Vec::new();
        into_writer(&Value::Map(entries), &mut buf).unwrap();
        buf
    }

    fn set_pin(authenticator: &mut Ctap2Authenticator) {
        use crate::client_pin::ClientPin;
        authenticator.set_pin(b"1234").unwrap();
    }

    #[test]
    fn test_decode_rejects_trailing_bytes() {
        let mut data = config_request_bytes(sub_commands::TOGGLE_ALWAYS_UV, None);
        data.push(0x00);
        assert_eq!(
            decode_authnr_config_request(&data).unwrap_err(),
            Ctap2Error::InvalidCbor
        );
    }

    #[test]
    fn test_decode_rejects_non_map() {
        assert_eq!(
            decode_authnr_config_request(b"\x81\x01").unwrap_err(),
            Ctap2Error::InvalidCbor
        );
    }

    #[test]
    fn test_auth_message_matches_wire_params() {
        let params = Value::Map(vec![(
            Value::Integer(Integer::from(0x02)),
            Value::Integer(Integer::from(6)),
        )]);
        let data = config_request_bytes(sub_commands::SET_MIN_PIN_LENGTH, Some(params.clone()));

        let mut expected = vec![0x0D, sub_commands::SET_MIN_PIN_LENGTH];
        into_writer(&params, &mut expected).unwrap();
        assert_eq!(authnr_config_auth_message(&data).unwrap(), expected);
    }

    #[test]
    fn test_policy_commands_require_pin() {
        let mut authenticator = make_authenticator();
        let token = vec![0xA5; 32];
        authenticator.set_pin_uv_auth_token(token, client_pin_token_perms(), None, 2);

        // Sem PIN configurado, subcomandos de política falham com PIN_NOT_SET.
        let data = config_request_bytes(sub_commands::TOGGLE_ALWAYS_UV, None);
        assert_eq!(
            handle_authnr_config(&mut authenticator, &data).unwrap_err(),
            Ctap2Error::PinNotSet
        );
    }

    fn client_pin_token_perms() -> u8 {
        crate::client_pin::PERMISSION_ACFG
    }

    #[test]
    fn test_toggle_always_uv_and_enforcement() {
        let mut authenticator = make_authenticator();
        set_pin(&mut authenticator);
        let token = vec![0xA5; 32];
        authenticator.set_pin_uv_auth_token(token.clone(), client_pin_token_perms(), None, 2);

        let data = config_request_bytes(sub_commands::TOGGLE_ALWAYS_UV, None);
        let message = authnr_config_auth_message(&data).unwrap();
        let params_mac = compute_mac(&token, 2, &message);

        // remonta o request com pinUvAuthProtocol/pinUvAuthParam
        let mut map: alloc::collections::BTreeMap<Integer, Value> =
            alloc::collections::BTreeMap::new();
        map.insert(
            Integer::from(0x01),
            Value::Integer(Integer::from(sub_commands::TOGGLE_ALWAYS_UV)),
        );
        map.insert(Integer::from(0x03), Value::Integer(Integer::from(2)));
        map.insert(Integer::from(0x04), Value::Bytes(params_mac));
        let entries: Vec<(Value, Value)> = map
            .into_iter()
            .map(|(k, v)| (Value::Integer(k), v))
            .collect();
        let mut data = Vec::new();
        into_writer(&Value::Map(entries), &mut data).unwrap();

        assert!(handle_authnr_config(&mut authenticator, &data).is_ok());
        assert!(is_always_uv(authenticator.get_storage()));

        // MC sem uv é negado quando alwaysUv está ativo.
        let error = authenticator
            .make_credential(make_credential_request(false))
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<Ctap2Error>(),
            Some(&Ctap2Error::PinRequired)
        );

        // MC com uv + pinAuth do token acfg... o MC exige permissão MC;
        // uso de token com permissão errada deve falhar.
        let client_data_hash = vec![0x11; 32];
        let mut mc = make_credential_request(true);
        mc.pin_protocol = Some(2);
        mc.pin_uv_auth_param = Some(compute_mac(&token, 2, &client_data_hash));
        mc.client_data_hash = client_data_hash;
        let error = authenticator.make_credential(mc).unwrap_err();
        assert_eq!(
            error.downcast_ref::<Ctap2Error>(),
            Some(&Ctap2Error::UnauthorizedPermission)
        );
    }

    #[test]
    fn test_always_uv_get_assertion_enforcement() {
        let mut authenticator = make_authenticator();
        // Credencial pré-existente criada antes do PIN para não exigir pinUvAuth.
        authenticator
            .make_credential(make_credential_request(false))
            .unwrap();
        set_pin(&mut authenticator);
        let cred_id = authenticator.get_storage().list_credentials()[0]
            .credential_id
            .clone();

        // Ativa alwaysUv diretamente no storage.
        authenticator
            .get_storage_mut()
            .store(CFG_ALWAYS_UV_KEY, b"1".to_vec())
            .unwrap();

        let request = GetAssertionRequest {
            rp_id: "example.com".to_string(),
            client_data_hash: vec![0x22; 32],
            credentials: vec![],
            allow_list: None,
            extensions: None,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_protocol: None,
            uv: None,
        };
        let error = authenticator.get_assertion(request).unwrap_err();
        assert_eq!(
            error.downcast_ref::<Ctap2Error>(),
            Some(&Ctap2Error::PinRequired)
        );
        let _ = cred_id;
    }

    #[test]
    fn test_set_min_pin_length_range() {
        let mut authenticator = make_authenticator();
        set_pin(&mut authenticator);
        let token = vec![0xA5; 32];
        authenticator.set_pin_uv_auth_token(token.clone(), client_pin_token_perms(), None, 2);

        for invalid in [2u8, 70u8] {
            let params = Value::Map(vec![(
                Value::Integer(Integer::from(0x02)),
                Value::Integer(Integer::from(invalid)),
            )]);
            let data = config_request_bytes(sub_commands::SET_MIN_PIN_LENGTH, Some(params));
            let message = authnr_config_auth_message(&data).unwrap();
            let mac = compute_mac(&token, 2, &message);
            let data = with_auth_fields(data, mac);
            assert_eq!(
                handle_authnr_config(&mut authenticator, &data).unwrap_err(),
                Ctap2Error::PinPolicyViolation
            );
        }

        let params = Value::Map(vec![(
            Value::Integer(Integer::from(0x02)),
            Value::Integer(Integer::from(6)),
        )]);
        let data = config_request_bytes(sub_commands::SET_MIN_PIN_LENGTH, Some(params));
        let message = authnr_config_auth_message(&data).unwrap();
        let mac = compute_mac(&token, 2, &message);
        let data = with_auth_fields(data, mac);
        assert!(handle_authnr_config(&mut authenticator, &data).is_ok());
        assert_eq!(get_min_pin_length(authenticator.get_storage(), 4), 6);
    }

    fn with_auth_fields(mut data: Vec<u8>, pin_auth: Vec<u8>) -> Vec<u8> {
        let mut restante = data.as_slice();
        let value: Value = from_reader(&mut restante).unwrap();
        let Value::Map(entries) = value else {
            unreachable!()
        };
        let mut entries = entries;
        entries.push((
            Value::Integer(Integer::from(0x03)),
            Value::Integer(Integer::from(2)),
        ));
        entries.push((Value::Integer(Integer::from(0x04)), Value::Bytes(pin_auth)));
        data.clear();
        into_writer(&Value::Map(entries), &mut data).unwrap();
        data
    }

    #[test]
    fn test_set_min_pin_length_requires_acfg_permission() {
        let mut authenticator = make_authenticator();
        set_pin(&mut authenticator);
        // Token com permissão CM apenas.
        let token = vec![0xA5; 32];
        authenticator.set_pin_uv_auth_token(
            token.clone(),
            crate::client_pin::PERMISSION_CM,
            None,
            2,
        );

        let params = Value::Map(vec![(
            Value::Integer(Integer::from(0x02)),
            Value::Integer(Integer::from(6)),
        )]);
        let data = config_request_bytes(sub_commands::SET_MIN_PIN_LENGTH, Some(params));
        let message = authnr_config_auth_message(&data).unwrap();
        let mac = compute_mac(&token, 2, &message);
        let data = with_auth_fields(data, mac);
        assert_eq!(
            handle_authnr_config(&mut authenticator, &data).unwrap_err(),
            Ctap2Error::UnauthorizedPermission
        );
    }

    #[test]
    fn test_set_min_pin_length_invalid_mac() {
        let mut authenticator = make_authenticator();
        set_pin(&mut authenticator);
        let token = vec![0xA5; 32];
        authenticator.set_pin_uv_auth_token(token.clone(), client_pin_token_perms(), None, 2);

        let params = Value::Map(vec![(
            Value::Integer(Integer::from(0x02)),
            Value::Integer(Integer::from(6)),
        )]);
        let data = config_request_bytes(sub_commands::SET_MIN_PIN_LENGTH, Some(params));
        let data = with_auth_fields(data, vec![0u8; 32]);
        assert_eq!(
            handle_authnr_config(&mut authenticator, &data).unwrap_err(),
            Ctap2Error::PinAuthInvalid
        );
    }

    #[test]
    fn test_force_change_pin_blocks_token_until_change() {
        let mut authenticator = make_authenticator();
        set_pin(&mut authenticator);
        let token = vec![0xA5; 32];
        authenticator.set_pin_uv_auth_token(token.clone(), client_pin_token_perms(), None, 2);

        let params = Value::Map(vec![
            (
                Value::Integer(Integer::from(0x02)),
                Value::Integer(Integer::from(6)),
            ),
            (Value::Integer(Integer::from(0x04)), Value::Bool(true)),
        ]);
        let data = config_request_bytes(sub_commands::SET_MIN_PIN_LENGTH, Some(params));
        let message = authnr_config_auth_message(&data).unwrap();
        let computed_mac = compute_mac(&token, 2, &message);
        let data = with_auth_fields(data, computed_mac);
        assert_eq!(
            handle_authnr_config(&mut authenticator, &data).unwrap_err(),
            Ctap2Error::MissingParameter
        );

        // forceChangePin sem currentPIN → MissingParameter; com PIN errado → PinInvalid.
        let params = Value::Map(vec![
            (
                Value::Integer(Integer::from(0x01)),
                Value::Bytes(vec![0xAB; 64]),
            ),
            (
                Value::Integer(Integer::from(0x02)),
                Value::Integer(Integer::from(6)),
            ),
            (Value::Integer(Integer::from(0x04)), Value::Bool(true)),
        ]);
        let data = config_request_bytes(sub_commands::SET_MIN_PIN_LENGTH, Some(params));
        let message = authnr_config_auth_message(&data).unwrap();
        let computed_mac2 = compute_mac(&token, 2, &message);
        let data = with_auth_fields(data, computed_mac2);
        assert_eq!(
            handle_authnr_config(&mut authenticator, &data).unwrap_err(),
            Ctap2Error::PinAuthInvalid
        );

        // Flag persistido via storage diretamente: getPinToken deve ser negado.
        authenticator
            .get_storage_mut()
            .store(CFG_FORCE_CHANGE_PIN_KEY, b"1".to_vec())
            .unwrap();
        assert!(is_force_change_pin(authenticator.get_storage()));
    }

    #[test]
    fn test_ep_one_shot() {
        let mut authenticator = make_authenticator();
        set_pin(&mut authenticator);

        // EP pendente é consumido no primeiro MC: attestation `packed`.
        authenticator
            .get_storage_mut()
            .store(CFG_EP_PENDING_KEY, b"1".to_vec())
            .unwrap();
        let first = authenticator
            .make_credential(make_credential_request(false))
            .unwrap();
        assert_eq!(first.fmt, "packed");

        // Segundo MC volta ao formato padrão (`none`).
        let second = authenticator
            .make_credential(make_credential_request(false))
            .unwrap();
        assert_eq!(second.fmt, "none");
    }

    #[test]
    fn test_set_min_pin_length_rpids() {
        let mut authenticator = make_authenticator();
        set_pin(&mut authenticator);
        let token = vec![0xA5; 32];
        authenticator.set_pin_uv_auth_token(token.clone(), client_pin_token_perms(), None, 2);

        let params = Value::Map(vec![(
            Value::Integer(Integer::from(0x01)),
            Value::Array(vec![
                Value::Text("internal.example.com".to_string()),
                Value::Text("corp.example.com".to_string()),
            ]),
        )]);
        let data = config_request_bytes(sub_commands::SET_MIN_PIN_LENGTH_RPIDS, Some(params));
        let message = authnr_config_auth_message(&data).unwrap();
        let mac = compute_mac(&token, 2, &message);
        let data = with_auth_fields(data, mac);
        assert!(handle_authnr_config(&mut authenticator, &data).is_ok());
        assert!(authenticator
            .get_storage()
            .retrieve(CFG_MIN_PIN_LENGTH_RPIDS_KEY)
            .is_ok());
    }

    #[test]
    fn test_make_cred_uv_not_rqd_toggle() {
        let mut authenticator = make_authenticator();
        set_pin(&mut authenticator);
        let token = vec![0xA5; 32];
        authenticator.set_pin_uv_auth_token(token.clone(), client_pin_token_perms(), None, 2);

        let data = config_request_bytes(sub_commands::MAKE_CRED_UV_NOT_RQD, None);
        let message = authnr_config_auth_message(&data).unwrap();
        let mac = compute_mac(&token, 2, &message);
        let data = with_auth_fields(data, mac);
        assert!(handle_authnr_config(&mut authenticator, &data).is_ok());
        assert!(is_make_cred_uv_not_rqd(authenticator.get_storage()));

        // Novo toggle reverte.
        let data = config_request_bytes(sub_commands::MAKE_CRED_UV_NOT_RQD, None);
        let message = authnr_config_auth_message(&data).unwrap();
        let mac = compute_mac(&token, 2, &message);
        let data = with_auth_fields(data, mac);
        assert!(handle_authnr_config(&mut authenticator, &data).is_ok());
        assert!(!is_make_cred_uv_not_rqd(authenticator.get_storage()));
    }
}
