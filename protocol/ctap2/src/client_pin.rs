//! authenticatorClientPIN (0x06) — implementação interoperável CTAP 2.1 §6.5.
//!
//! Substitui o formato legado (chaves string, ChaCha20-Poly1305 com nonce
//! zero, subcomandos renumerados) pelo wire format padrão:
//!
//! - Request: array CBOR posicional (como enviam python-fido2/Chromium) ou
//!   mapa com chaves inteiras (CTAP 2.1); mapas com chaves string (CTAP 2.0)
//!   são aceitos por compatibilidade.
//! - Response: mapa CBOR com chaves inteiras `0x01..0x05`.
//! - Crypto: P-256 ECDH + (protocolo 1) SHA-256/AES-256-CBC-IV-zero/HMAC
//!   truncado 16B ou (protocolo 2) HKDF/AES-256-CBC-IV-aleatório/HMAC 32B —
//!   implementado em [`crypto::pin_protocol`].

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use ciborium::de::from_reader;
use ciborium::ser::into_writer;
use ciborium::value::Integer;
use ciborium::Value;
use crypto::pin_protocol::{
    strip_zero_padding, PinAgreementKey, PinUvProtocol, Zeroizing, PIN_HASH_LEN,
};
use serde::{Deserialize, Serialize};

use crate::ctap2::Ctap2Authenticator;
use crate::ctap2::Ctap2Error;

extern crate alloc;

pub(crate) const PIN_MIN_LENGTH: usize = 4;
pub(crate) const PIN_MAX_LENGTH: usize = 63;
pub(crate) const PIN_MAX_RETRIES: u8 = 8;
pub(crate) const PIN_BLOCK_THRESHOLD: u8 = 3;
pub(crate) const PIN_STORAGE_KEY: &str = "client_pin_hash";
pub(crate) const PIN_RETRIES_KEY: &str = "client_pin_retries";
pub(crate) const UV_RETRIES_KEY: &str = "sys:uv_retries";
pub(crate) const UV_MAX_RETRIES: u8 = 8;

/// Permissões de pinUvAuthToken (CTAP 2.1 §6.5.5.7).
pub(crate) const PERMISSION_MC: u8 = 0x01;
pub(crate) const PERMISSION_GA: u8 = 0x02;
pub(crate) const PERMISSION_CM: u8 = 0x04;
pub(crate) const PERMISSION_BE: u8 = 0x08;
pub(crate) const PERMISSION_LBW: u8 = 0x10;
pub(crate) const PERMISSION_ACFG: u8 = 0x20;
/// Permissões padrão do subcomando getPinToken (mc | ga).
pub(crate) const PERMISSION_MC_GA: u8 = PERMISSION_MC | PERMISSION_GA;

/// Chave pública EC2 P-256 extraída de um COSE_Key CBOR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoseEc2Key {
    #[serde(with = "serde_bytes")]
    pub x: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub y: Vec<u8>,
}

impl CoseEc2Key {
    /// Formato SEC1 não-comprimido (`0x04 || x || y`, 65 bytes) para o ECDH.
    pub fn to_uncompressed(&self) -> Result<Vec<u8>, Ctap2Error> {
        if self.x.len() != 32 || self.y.len() != 32 {
            return Err(Ctap2Error::InvalidParameter);
        }
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend_from_slice(&self.x);
        point.extend_from_slice(&self.y);
        Ok(point)
    }

    /// Codifica a chave como mapa COSE_Key CBOR com os labels da spec:
    /// `1 (kty)=2 (EC2)`, `3 (alg)=-25`, `-1 (crv)=1 (P-256)`,
    /// `-2 (x)`, `-3 (y)`.
    pub fn to_cose_value(&self) -> Value {
        Value::Map(vec![
            (
                Value::Integer(Integer::from(-3)),
                Value::Bytes(self.y.clone()),
            ),
            (
                Value::Integer(Integer::from(-2)),
                Value::Bytes(self.x.clone()),
            ),
            (
                Value::Integer(Integer::from(-1)),
                Value::Integer(Integer::from(1)),
            ),
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(2)),
            ),
            (
                Value::Integer(Integer::from(3)),
                Value::Integer(Integer::from(-25)),
            ),
        ])
    }

    /// Codifica a chave como bytes CBOR canônicos (para a response).
    pub fn encode_cose(&self) -> Result<Vec<u8>, Ctap2Error> {
        let value = self.to_cose_value();
        let mut buf = Vec::new();
        into_writer(&value, &mut buf).map_err(|_| Ctap2Error::Unknown)?;
        Ok(buf)
    }

    /// Decodifica um COSE_Key EC2 P-256 de um valor CBOR.
    pub(crate) fn from_cose_value(value: &Value) -> Result<Self, Ctap2Error> {
        let Value::Map(entries) = value else {
            return Err(Ctap2Error::InvalidParameter);
        };
        let mut kty: Option<i64> = None;
        let mut crv: Option<i64> = None;
        let mut x: Option<Vec<u8>> = None;
        let mut y: Option<Vec<u8>> = None;
        for (key, val) in entries {
            match (key, val) {
                (Value::Integer(k), Value::Integer(v)) => {
                    let v = i64::try_from(*v).unwrap_or_default();
                    if i64::try_from(*k).unwrap_or_default() == 1 {
                        kty = Some(v);
                    } else if i64::try_from(*k).unwrap_or_default() == -1 {
                        crv = Some(v);
                    }
                }
                (Value::Integer(k), Value::Bytes(b)) => {
                    if i64::try_from(*k).unwrap_or_default() == -2 {
                        x = Some(b.clone());
                    } else if i64::try_from(*k).unwrap_or_default() == -3 {
                        y = Some(b.clone());
                    }
                }
                _ => {}
            }
        }
        if kty != Some(2) || crv != Some(1) {
            return Err(Ctap2Error::InvalidParameter);
        }
        let key = Self {
            x: x.ok_or(Ctap2Error::InvalidParameter)?,
            y: y.ok_or(Ctap2Error::InvalidParameter)?,
        };
        if key.x.len() != 32 || key.y.len() != 32 {
            return Err(Ctap2Error::InvalidParameter);
        }
        Ok(key)
    }
}

/// Request do comando authenticatorClientPIN (CTAP2 0x06).
///
/// No wire, o request chega como array CBOR posicional
/// `[pinUvAuthProtocol, subCommand, keyAgreement, pinUvAuthParam, newPinEnc,
/// pinHashEnc, (reservado), (reservado), permissions, rpId]` ou como mapa
/// com as chaves inteiras abaixo. Ver [`decode_client_pin_request`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientPinRequest {
    /// 0x01 pinUvAuthProtocol — versão do protocolo escolhida pela plataforma.
    #[serde(rename = "pinUvAuthProtocol", skip_serializing_if = "Option::is_none")]
    pub pin_protocol: Option<u8>,
    /// 0x02 subCommand — ação solicitada (ver [`ClientPinSubCommand`]).
    #[serde(rename = "subCommand")]
    pub sub_command: u8,
    /// 0x03 keyAgreement — chave efêmera da plataforma (COSE_Key EC2).
    #[serde(rename = "keyAgreement", skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<CoseEc2Key>,
    /// 0x04 pinUvAuthParam — MAC dos parâmetros do subcomando.
    #[serde(rename = "pinUvAuthParam", skip_serializing_if = "Option::is_none")]
    pub pin_auth: Option<Vec<u8>>,
    /// 0x05 newPinEnc — novo PIN cifrado (64 bytes de plaintext com padding).
    #[serde(rename = "newPinEnc", skip_serializing_if = "Option::is_none")]
    pub new_pin_enc: Option<Vec<u8>>,
    /// 0x06 pinHashEnc — LEFT(SHA-256(PIN), 16) cifrado.
    #[serde(rename = "pinHashEnc", skip_serializing_if = "Option::is_none")]
    pub pin_hash_enc: Option<Vec<u8>>,
    /// 0x09 permissions — bitfield de permissões do token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<u8>,
    /// 0x0A rpId — RP ID associado às permissões.
    #[serde(rename = "rpId", skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
}

/// Response do comando authenticatorClientPIN. Campos ausentes são omitidos.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientPinResponse {
    /// 0x01 keyAgreement — chave pública efêmera do autenticador (COSE_Key CBOR).
    #[serde(rename = "keyAgreement", skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<Vec<u8>>,
    /// 0x02 pinUvAuthToken — token cifrado com o segredo compartilhado.
    #[serde(rename = "pinUvAuthToken", skip_serializing_if = "Option::is_none")]
    pub pin_uv_auth_token: Option<Vec<u8>>,
    /// 0x03 retries — tentativas de PIN restantes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries: Option<u8>,
    /// 0x04 powerCycleState — `true` se um power cycle é necessário.
    #[serde(rename = "powerCycleState", skip_serializing_if = "Option::is_none")]
    pub power_cycle_state: Option<bool>,
    /// 0x05 uvRetries — tentativas de verificação de usuário restantes.
    #[serde(rename = "uvRetries", skip_serializing_if = "Option::is_none")]
    pub uv_retries: Option<u8>,
}

/// Subcomandos do authenticatorClientPIN (CTAP 2.1 §6.5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClientPinSubCommand {
    /// Consulta tentativas de PIN restantes.
    GetPINRetries = 0x01,
    /// Obtém a chave pública de acordo do autenticador.
    GetKeyAgreement = 0x02,
    /// Define o PIN inicial.
    SetPIN = 0x03,
    /// Troca um PIN existente.
    ChangePIN = 0x04,
    /// Obtém um pinUvAuthToken (legado, permissões padrão mc|ga).
    GetPINToken = 0x05,
    /// Obtém um pinUvAuthToken via verificação de usuário embutida.
    GetPinUvAuthTokenUsingUvWithPermissions = 0x06,
    /// Consulta tentativas de verificação de usuário restantes.
    GetUVRetries = 0x07,
    /// Obtém um pinUvAuthToken usando PIN, com permissões explícitas.
    GetPinUvAuthTokenUsingPinWithPermissions = 0x09,
}

impl ClientPinSubCommand {
    /// Converte o código do wire em subcomando; `None` se desconhecido.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::GetPINRetries),
            0x02 => Some(Self::GetKeyAgreement),
            0x03 => Some(Self::SetPIN),
            0x04 => Some(Self::ChangePIN),
            0x05 => Some(Self::GetPINToken),
            0x06 => Some(Self::GetPinUvAuthTokenUsingUvWithPermissions),
            0x07 => Some(Self::GetUVRetries),
            0x09 => Some(Self::GetPinUvAuthTokenUsingPinWithPermissions),
            _ => None,
        }
    }
}

/// Estado do pinUvAuthToken da sessão (CTAP 2.1 §6.5.2.1).
///
/// O token é zerado quando o estado é dropado; [`Debug`] oculta o material.
pub(crate) struct PinUvAuthTokenState {
    pub(crate) token: Zeroizing<Vec<u8>>,
    pub(crate) permissions: u8,
    pub(crate) permissions_rp_id: Option<String>,
    pub(crate) protocol: u8,
}

impl PinUvAuthTokenState {
    pub(crate) fn new(
        token: Vec<u8>,
        permissions: u8,
        permissions_rp_id: Option<String>,
        protocol: u8,
    ) -> Self {
        Self {
            token: Zeroizing::new(token),
            permissions,
            permissions_rp_id,
            protocol,
        }
    }
}

impl core::fmt::Debug for PinUvAuthTokenState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PinUvAuthTokenState")
            .field("token", &"[redacted]")
            .field("permissions", &self.permissions)
            .field("permissions_rp_id", &self.permissions_rp_id)
            .field("protocol", &self.protocol)
            .finish()
    }
}

/// Operações de PIN implementadas pelo autenticador.
///
/// O contador de tentativas é decrementado *antes* da verificação, para que
/// uma interrupção de energia no meio da checagem não conceda tentativas
/// extras (CTAP 2.1 §6.5.5.6).
pub trait ClientPin {
    /// Tentativas de PIN restantes.
    fn get_pin_retries(&self) -> u8;
    /// Define o PIN inicial. Falha se já houver PIN configurado.
    fn set_pin(&mut self, pin: &[u8]) -> Result<(), Ctap2Error>;
    /// Troca o PIN, exigindo o valor anterior.
    fn change_pin(&mut self, old_pin: &[u8], new_pin: &[u8]) -> Result<(), Ctap2Error>;
    /// Verifica o PIN em tempo constante, ajustando o contador de tentativas.
    fn verify_pin(&mut self, pin: &[u8]) -> Result<(), Ctap2Error>;
    /// Restaura o contador de tentativas após uma verificação bem-sucedida.
    fn reset_pin_retries(&mut self);
    /// Consome uma tentativa de PIN.
    fn decrement_pin_retries(&mut self);
}

pub(crate) fn read_retries(storage: &storage::StorageEngine) -> u8 {
    storage
        .retrieve(PIN_RETRIES_KEY)
        .ok()
        .and_then(|data| String::from_utf8(data).ok())
        .and_then(|s| s.parse::<u8>().ok())
        .unwrap_or(PIN_MAX_RETRIES)
}

/// Lê o contador persistente de tentativas de UV embutida
/// (`sys:uv_retries`); ausente ⇒ [`UV_MAX_RETRIES`].
pub(crate) fn read_uv_retries(storage: &storage::StorageEngine) -> u8 {
    storage
        .retrieve(UV_RETRIES_KEY)
        .ok()
        .and_then(|data| String::from_utf8(data).ok())
        .and_then(|s| s.parse::<u8>().ok())
        .unwrap_or(UV_MAX_RETRIES)
}

/// Indica se já existe um PIN configurado no storage.
pub fn is_pin_set(storage: &storage::StorageEngine) -> bool {
    storage.retrieve(PIN_STORAGE_KEY).is_ok()
}

/// Indica se o PIN está bloqueado após [`PIN_BLOCK_THRESHOLD`] falhas
/// consecutivas na sessão atual (`PIN_AUTH_BLOCKED`, powerCycleState = true).
///
/// O bloqueio é **volátil**: nasce limpo em cada instância do autenticador
/// (um novo power cycle o encerra), enquanto o contador persistente de
/// tentativas continua valendo (CTAP 2.1 §6.5.5.6).
pub fn is_pin_blocked(authenticator: &Ctap2Authenticator) -> bool {
    authenticator.is_pin_auth_blocked()
}

/// Processa o comando authenticatorClientPIN (0x06) e devolve a response CBOR.
pub(crate) fn handle_client_pin(
    authenticator: &mut Ctap2Authenticator,
    data: &[u8],
) -> Result<Vec<u8>, Ctap2Error> {
    let request = decode_client_pin_request(data)?;
    let sub =
        ClientPinSubCommand::from_u8(request.sub_command).ok_or(Ctap2Error::InvalidParameter)?;

    let response = match sub {
        ClientPinSubCommand::GetPINRetries => handle_get_retries(authenticator),
        ClientPinSubCommand::GetKeyAgreement => handle_get_key_agreement(authenticator, &request),
        ClientPinSubCommand::SetPIN => handle_set_pin(authenticator, &request),
        ClientPinSubCommand::ChangePIN => handle_change_pin(authenticator, &request),
        ClientPinSubCommand::GetPINToken => handle_get_pin_token(authenticator, &request),
        ClientPinSubCommand::GetPinUvAuthTokenUsingUvWithPermissions => {
            handle_get_uv_token(authenticator, &request)
        }
        ClientPinSubCommand::GetUVRetries => handle_get_uv_retries(authenticator),
        ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions => {
            handle_get_pin_token_with_permissions(authenticator, &request)
        }
    }?;

    encode_client_pin_response(&response)
}

/// Valida e instancia o protocolo PIN/UV do request.
fn validate_protocol(pin_protocol: Option<u8>) -> Result<PinUvProtocol, Ctap2Error> {
    let version = pin_protocol.ok_or(Ctap2Error::MissingParameter)?;
    PinUvProtocol::new(version).map_err(|_| Ctap2Error::InvalidParameter)
}

/// Executa o acordo de chaves do lado do autenticador usando a chave privada
/// anunciada em getKeyAgreement (CTAP 2.1 §6.5.4 `decapsulate`). A chave é
/// consumida: cada transação exige um getKeyAgreement novo (§6.5.5.4).
fn perform_key_agreement(
    authenticator: &mut Ctap2Authenticator,
    protocol: &PinUvProtocol,
    peer_cose: &CoseEc2Key,
) -> Result<Zeroizing<Vec<u8>>, Ctap2Error> {
    let peer_point = peer_cose.to_uncompressed()?;
    let agreement_key = match authenticator.take_pin_agreement_key() {
        Some(key) => key,
        None => PinAgreementKey::generate().map_err(|_| Ctap2Error::Unknown)?,
    };
    let z = Zeroizing::new(
        agreement_key
            .agree(&peer_point)
            .map_err(|_| Ctap2Error::InvalidParameter)?,
    );
    let secret = Zeroizing::new(protocol.kdf(&z).map_err(|_| Ctap2Error::Unknown)?);
    Ok(secret)
}

/// Decifra `pinHashEnc` com o segredo compartilhado, exigindo exatamente
/// [`PIN_HASH_LEN`] bytes.
///
/// O plaintext do `pinHashEnc` é exatamente `LEFT(SHA-256(PIN),16)` — **sem**
/// zero-padding (CTAP 2.1 §6.5.5.5). Remover zeros à direita rejeitaria
/// ~1/256 dos PINs corretos, cujo prefixo do hash termina em 0x00.
fn decrypt_pin_hash(
    protocol: &PinUvProtocol,
    secret: &[u8],
    pin_hash_enc: &[u8],
) -> Result<Vec<u8>, Ctap2Error> {
    protocol
        .decrypt_exact(secret, pin_hash_enc, PIN_HASH_LEN)
        .map_err(|_| Ctap2Error::PinAuthInvalid)
}

/// Valida `pinHashEnc` contra o hash armazenado (comparação em tempo
/// constante). Não ajusta o contador de tentativas — o chamador decide.
fn verify_decrypted_pin_hash(
    authenticator: &Ctap2Authenticator,
    submitted: &[u8],
) -> Result<(), Ctap2Error> {
    let stored_hash = authenticator
        .get_storage()
        .retrieve(PIN_STORAGE_KEY)
        .map_err(|_| Ctap2Error::PinNotSet)?;
    if !crypto::constant_time_eq(submitted, &stored_hash) {
        return Err(Ctap2Error::PinInvalid);
    }
    Ok(())
}

/// Escada de erros após um PIN incorreto (CTAP 2.1 §6.5.5.4/§6.5.5.7):
/// `PIN_BLOCKED` sem tentativas, `PIN_AUTH_BLOCKED` após 3 falhas
/// consecutivas da sessão, senão `PIN_INVALID`.
fn pin_failure_error(authenticator: &mut Ctap2Authenticator) -> Ctap2Error {
    authenticator.register_pin_failure()
}

/// Emite um pinUvAuthToken novo (32 bytes aleatórios), registra o estado da
/// sessão e devolve o token cifrado para a plataforma.
fn issue_pin_uv_auth_token(
    authenticator: &mut Ctap2Authenticator,
    protocol: &PinUvProtocol,
    secret: &[u8],
    permissions: u8,
    permissions_rp_id: Option<String>,
) -> Result<Vec<u8>, Ctap2Error> {
    let token = Zeroizing::new(authenticator.get_crypto().random_bytes(32));
    let encrypted = protocol
        .encrypt(secret, &token)
        .map_err(|_| Ctap2Error::Unknown)?;
    authenticator.set_pin_uv_auth_token(
        token.to_vec(),
        permissions,
        permissions_rp_id,
        protocol.version(),
    );
    // Retém o segredo compartilhado para operações que cifram dados com ele
    // (ex.: `currentPIN` do setMinPINLength — ADR-0021).
    authenticator.set_pin_shared_secret(secret.to_vec(), protocol.version());
    Ok(encrypted)
}

/// Valida o bitfield `permissions` contra as options do GetInfo
/// (CTAP 2.1 §6.5.5.7.2). Bits indefinidos são ignorados.
fn validate_permissions(
    authenticator: &Ctap2Authenticator,
    permissions: u8,
) -> Result<(), Ctap2Error> {
    if permissions == 0 {
        return Err(Ctap2Error::InvalidParameter);
    }
    let options = &authenticator.capabilities().options;
    if permissions & PERMISSION_BE != 0 && !options.contains(&"bioEnroll".to_string()) {
        return Err(Ctap2Error::UnauthorizedPermission);
    }
    if permissions & PERMISSION_ACFG != 0 && !options.contains(&"authnrCfg".to_string()) {
        return Err(Ctap2Error::UnauthorizedPermission);
    }
    if permissions & PERMISSION_CM != 0 && !options.contains(&"credMgmt".to_string()) {
        return Err(Ctap2Error::UnauthorizedPermission);
    }
    if permissions & PERMISSION_LBW != 0 && !options.contains(&"largeBlobs".to_string()) {
        return Err(Ctap2Error::UnauthorizedPermission);
    }
    Ok(())
}

fn handle_get_retries(authenticator: &Ctap2Authenticator) -> Result<ClientPinResponse, Ctap2Error> {
    let retries = authenticator.get_pin_retries();
    let blocked = is_pin_blocked(authenticator);
    Ok(ClientPinResponse {
        retries: Some(retries),
        power_cycle_state: if blocked { Some(true) } else { None },
        ..Default::default()
    })
}

fn handle_get_key_agreement(
    authenticator: &mut Ctap2Authenticator,
    request: &ClientPinRequest,
) -> Result<ClientPinResponse, Ctap2Error> {
    let _protocol = validate_protocol(request.pin_protocol)?;
    let agreement_key = PinAgreementKey::generate().map_err(|_| Ctap2Error::Unknown)?;
    let public_key = agreement_key
        .public_key_bytes()
        .map_err(|_| Ctap2Error::Unknown)?;
    let cose_key = CoseEc2Key {
        x: public_key[1..33].to_vec(),
        y: public_key[33..65].to_vec(),
    };
    authenticator.set_pin_agreement_key(agreement_key);
    Ok(ClientPinResponse {
        key_agreement: Some(cose_key.encode_cose()?),
        ..Default::default()
    })
}

fn handle_set_pin(
    authenticator: &mut Ctap2Authenticator,
    request: &ClientPinRequest,
) -> Result<ClientPinResponse, Ctap2Error> {
    let protocol = validate_protocol(request.pin_protocol)?;

    if is_pin_set(authenticator.get_storage()) {
        return Err(Ctap2Error::PinAuthInvalid);
    }

    let peer_cose = request
        .key_agreement
        .as_ref()
        .ok_or(Ctap2Error::MissingParameter)?;
    let new_pin_enc = request
        .new_pin_enc
        .as_ref()
        .ok_or(Ctap2Error::MissingParameter)?;
    let pin_auth = request
        .pin_auth
        .as_ref()
        .ok_or(Ctap2Error::MissingParameter)?;

    let secret = perform_key_agreement(authenticator, &protocol, peer_cose)?;

    // verify(shared secret, newPinEnc, pinUvAuthParam) — antes de qualquer
    // decifragem (CTAP 2.1 §6.5.5.5).
    if !protocol
        .verify(&secret, new_pin_enc, pin_auth)
        .map_err(|_| Ctap2Error::PinAuthInvalid)?
    {
        return Err(Ctap2Error::PinAuthInvalid);
    }

    let padded_new_pin = protocol
        .decrypt(&secret, new_pin_enc)
        .map_err(|_| Ctap2Error::PinAuthInvalid)?;
    if padded_new_pin.len() != 64 {
        return Err(Ctap2Error::InvalidParameter);
    }
    let new_pin = Zeroizing::new(
        strip_zero_padding(&padded_new_pin).map_err(|_| Ctap2Error::PinAuthInvalid)?,
    );

    if new_pin.len() < PIN_MIN_LENGTH || new_pin.len() > PIN_MAX_LENGTH {
        return Err(Ctap2Error::PinPolicyViolation);
    }

    authenticator.set_pin(&new_pin)?;
    Ok(ClientPinResponse::default())
}

fn handle_change_pin(
    authenticator: &mut Ctap2Authenticator,
    request: &ClientPinRequest,
) -> Result<ClientPinResponse, Ctap2Error> {
    let protocol = validate_protocol(request.pin_protocol)?;

    if !is_pin_set(authenticator.get_storage()) {
        return Err(Ctap2Error::PinNotSet);
    }
    if authenticator.get_pin_retries() == 0 {
        return Err(Ctap2Error::PinBlocked);
    }
    if is_pin_blocked(authenticator) {
        return Err(Ctap2Error::PinAuthBlocked);
    }

    let peer_cose = request
        .key_agreement
        .as_ref()
        .ok_or(Ctap2Error::MissingParameter)?;
    let pin_hash_enc = request
        .pin_hash_enc
        .as_ref()
        .ok_or(Ctap2Error::MissingParameter)?;
    let new_pin_enc = request
        .new_pin_enc
        .as_ref()
        .ok_or(Ctap2Error::MissingParameter)?;
    let pin_auth = request
        .pin_auth
        .as_ref()
        .ok_or(Ctap2Error::MissingParameter)?;

    let secret = perform_key_agreement(authenticator, &protocol, peer_cose)?;

    // verify(shared secret, newPinEnc || pinHashEnc, pinUvAuthParam) antes de
    // consumir tentativas (CTAP 2.1 §6.5.5.6).
    let mut pin_auth_message = Vec::with_capacity(new_pin_enc.len() + pin_hash_enc.len());
    pin_auth_message.extend_from_slice(new_pin_enc);
    pin_auth_message.extend_from_slice(pin_hash_enc);
    if !protocol
        .verify(&secret, &pin_auth_message, pin_auth)
        .map_err(|_| Ctap2Error::PinAuthInvalid)?
    {
        return Err(Ctap2Error::PinAuthInvalid);
    }

    // Decrementa antes da verificação do PIN (CTAP 2.1 §6.5.5.6).
    authenticator.decrement_pin_retries();

    let submitted_hash = match decrypt_pin_hash(&protocol, &secret, pin_hash_enc) {
        Ok(hash) => hash,
        Err(_) => return Err(pin_failure_error(authenticator)),
    };
    if verify_decrypted_pin_hash(authenticator, &submitted_hash).is_err() {
        return Err(pin_failure_error(authenticator));
    }

    authenticator.reset_pin_retries();

    let padded_new_pin = protocol
        .decrypt(&secret, new_pin_enc)
        .map_err(|_| Ctap2Error::PinAuthInvalid)?;
    if padded_new_pin.len() != 64 {
        return Err(Ctap2Error::InvalidParameter);
    }
    let new_pin = Zeroizing::new(
        strip_zero_padding(&padded_new_pin).map_err(|_| Ctap2Error::PinAuthInvalid)?,
    );
    if new_pin.len() < PIN_MIN_LENGTH || new_pin.len() > PIN_MAX_LENGTH {
        return Err(Ctap2Error::PinPolicyViolation);
    }

    // resetPinUvAuthToken: tokens anteriores são invalidados na troca de PIN.
    authenticator.invalidate_pin_uv_auth_token();

    let full_hash = authenticator.get_crypto().sha256(&new_pin);
    authenticator
        .get_storage_mut()
        .store(PIN_STORAGE_KEY, full_hash[..16].to_vec())
        .map_err(|_| Ctap2Error::Unknown)?;

    Ok(ClientPinResponse::default())
}

fn handle_get_pin_token(
    authenticator: &mut Ctap2Authenticator,
    request: &ClientPinRequest,
) -> Result<ClientPinResponse, Ctap2Error> {
    let protocol = validate_protocol(request.pin_protocol)?;

    // O getPinToken legado não aceita permissions nem rpId (CTAP 2.1 §6.5.5.7.1).
    if request.permissions.is_some() || request.rp_id.is_some() {
        return Err(Ctap2Error::InvalidParameter);
    }

    handle_get_pin_token_common(authenticator, request, &protocol, PERMISSION_MC_GA, None)
}

fn handle_get_pin_token_with_permissions(
    authenticator: &mut Ctap2Authenticator,
    request: &ClientPinRequest,
) -> Result<ClientPinResponse, Ctap2Error> {
    let protocol = validate_protocol(request.pin_protocol)?;

    let permissions = request.permissions.ok_or(Ctap2Error::MissingParameter)?;
    validate_permissions(authenticator, permissions)?;

    // Tokens que autorizam MakeCredential/GetAssertion exigem rpId: sem ele,
    // o token valeria para qualquer RP (CTAP 2.1 §6.5.5.7; comportamento do
    // dispositivo virtual do Chromium). Outros conjuntos de permissões (ex.:
    // be|cm) podem omitir rpId.
    if permissions & (PERMISSION_MC | PERMISSION_GA) != 0 && request.rp_id.is_none() {
        return Err(Ctap2Error::MissingParameter);
    }

    handle_get_pin_token_common(
        authenticator,
        request,
        &protocol,
        permissions,
        request.rp_id.clone(),
    )
}

fn handle_get_pin_token_common(
    authenticator: &mut Ctap2Authenticator,
    request: &ClientPinRequest,
    protocol: &PinUvProtocol,
    permissions: u8,
    permissions_rp_id: Option<String>,
) -> Result<ClientPinResponse, Ctap2Error> {
    if !is_pin_set(authenticator.get_storage()) {
        return Err(Ctap2Error::PinNotSet);
    }
    if crate::authnr_config::is_force_change_pin(authenticator.get_storage()) {
        // PIN precisa ser trocado antes de emitir um novo token
        // (setMinPINLength com forceChangePin — ADR-0021).
        return Err(Ctap2Error::PinPolicyViolation);
    }
    if authenticator.get_pin_retries() == 0 {
        return Err(Ctap2Error::PinBlocked);
    }
    if is_pin_blocked(authenticator) {
        return Err(Ctap2Error::PinAuthBlocked);
    }

    let peer_cose = request
        .key_agreement
        .as_ref()
        .ok_or(Ctap2Error::MissingParameter)?;
    let pin_hash_enc = request
        .pin_hash_enc
        .as_ref()
        .ok_or(Ctap2Error::MissingParameter)?;

    let secret = perform_key_agreement(authenticator, protocol, peer_cose)?;

    // Decrementa antes da verificação do PIN (CTAP 2.1 §6.5.5.7).
    authenticator.decrement_pin_retries();

    let submitted_hash = match decrypt_pin_hash(protocol, &secret, pin_hash_enc) {
        Ok(hash) => hash,
        Err(_) => return Err(pin_failure_error(authenticator)),
    };
    if verify_decrypted_pin_hash(authenticator, &submitted_hash).is_err() {
        return Err(pin_failure_error(authenticator));
    }

    authenticator.reset_pin_retries();

    let token_enc = issue_pin_uv_auth_token(
        authenticator,
        protocol,
        &secret,
        permissions,
        permissions_rp_id,
    )?;

    Ok(ClientPinResponse {
        pin_uv_auth_token: Some(token_enc),
        ..Default::default()
    })
}

/// Reporta as tentativas restantes de UV embutida quando há mock injetado
/// e a capability `uv` habilitada; caso contrário `UnsupportedOption`
/// (padrão, sem hardware de verificação embutida).
fn handle_get_uv_retries(
    authenticator: &Ctap2Authenticator,
) -> Result<ClientPinResponse, Ctap2Error> {
    match authenticator.builtin_uv_retries() {
        Some(retries) => Ok(ClientPinResponse {
            uv_retries: Some(retries),
            ..Default::default()
        }),
        None => Err(Ctap2Error::UnsupportedOption),
    }
}

/// Emite um pinUvAuthToken via verificação de usuário embutida
/// (CTAP 2.1 §6.5.5.7.3).
///
/// Sem mock de [`crate::ctap2::UserVerification`] injetado ou sem a
/// capability `uv`, falha com `CTAP2_ERR_UV_BLOCKED` (sem hardware embutido).
/// Com o mock, verifica o usuário e emite um token com as `permissions`/`rpId`
/// solicitadas, como o fluxo 0x09 baseado em PIN. O token resultante
/// autentica MakeCredential/GetAssertion e seta o bit UV (0x04) do authData.
fn handle_get_uv_token(
    authenticator: &mut Ctap2Authenticator,
    request: &ClientPinRequest,
) -> Result<ClientPinResponse, Ctap2Error> {
    let protocol = validate_protocol(request.pin_protocol)?;
    let permissions = request.permissions.ok_or(Ctap2Error::MissingParameter)?;
    validate_permissions(authenticator, permissions)?;
    // Gate de UV antes das demais validações de parâmetro, para que o
    // comportamento padrão (sem mock) siga retornando `UvBlocked`.
    authenticator.perform_builtin_uv()?;
    // Tokens com escopo mc|ga vinculam-se a um RP: sem rpId valeriam para
    // qualquer RP (mesma regra do 0x09, CTAP 2.1 §6.5.5.7).
    if permissions & (PERMISSION_MC | PERMISSION_GA) != 0 && request.rp_id.is_none() {
        return Err(Ctap2Error::MissingParameter);
    }
    let peer_cose = request
        .key_agreement
        .as_ref()
        .ok_or(Ctap2Error::MissingParameter)?;
    let secret = perform_key_agreement(authenticator, &protocol, peer_cose)?;
    let token_enc = issue_pin_uv_auth_token(
        authenticator,
        &protocol,
        &secret,
        permissions,
        request.rp_id.clone(),
    )?;
    Ok(ClientPinResponse {
        pin_uv_auth_token: Some(token_enc),
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------
// Codec CBOR do authenticatorClientPIN
// ---------------------------------------------------------------------------

/// Decodifica o request do authenticatorClientPIN.
///
/// Aceita o array posicional usado por python-fido2/Chromium
/// (`[pinUvAuthProtocol, subCommand, keyAgreement, pinUvAuthParam, newPinEnc,
/// pinHashEnc, _, _, permissions, rpId]`), o mapa com chaves inteiras do
/// CTAP 2.1 e, por compatibilidade, mapas com chaves string do CTAP 2.0.
pub(crate) fn decode_client_pin_request(data: &[u8]) -> Result<ClientPinRequest, Ctap2Error> {
    let mut restante = data;
    let value: Value = from_reader(&mut restante).map_err(|_| Ctap2Error::InvalidCbor)?;
    if !restante.is_empty() {
        return Err(Ctap2Error::InvalidCbor);
    }

    match value {
        Value::Array(items) => decode_request_from_array(&items),
        Value::Map(entries) => decode_request_from_map(&entries),
        _ => Err(Ctap2Error::InvalidCbor),
    }
}

/// Decodifica o array CBOR posicional enviado por python-fido2/Chromium.
///
/// Após os dois primeiros elementos obrigatórios (`pinUvAuthProtocol`,
/// `subCommand`), os parâmetros opcionais são **compactados sem lacunas**
/// (`args()` do python-fido2) e atribuídos na ordem definida pela spec para
/// o subcomando. `Null`s intermediários são ignorados.
fn decode_request_from_array(items: &[Value]) -> Result<ClientPinRequest, Ctap2Error> {
    let mut request = ClientPinRequest::default();
    if let Some(first) = items.first().filter(|i| !matches!(i, Value::Null)) {
        request.pin_protocol = Some(value_to_u8(first)?);
    }
    if let Some(second) = items.get(1).filter(|i| !matches!(i, Value::Null)) {
        request.sub_command = value_to_u8(second)?;
    }

    let rest: Vec<&Value> = items
        .iter()
        .skip(2)
        .filter(|item| !matches!(item, Value::Null))
        .collect();
    let mut idx = 0;
    let mut next = |request: &mut ClientPinRequest, field: u8| -> Result<(), Ctap2Error> {
        let Some(item) = rest.get(idx) else {
            return Ok(());
        };
        idx += 1;
        match field {
            1 => request.key_agreement = Some(CoseEc2Key::from_cose_value(item)?),
            2 => request.pin_auth = Some(value_to_bytes(item)?),
            3 => request.new_pin_enc = Some(value_to_bytes(item)?),
            4 => request.pin_hash_enc = Some(value_to_bytes(item)?),
            5 => request.permissions = Some(value_to_u8(item)?),
            6 => request.rp_id = Some(value_to_text(item)?),
            _ => {}
        }
        Ok(())
    };

    match request.sub_command {
        // setPIN: keyAgreement, pinUvAuthParam, newPinEnc
        0x03 => {
            next(&mut request, 1)?;
            next(&mut request, 2)?;
            next(&mut request, 3)?;
        }
        // changePIN: keyAgreement, pinUvAuthParam, newPinEnc, pinHashEnc
        0x04 => {
            next(&mut request, 1)?;
            next(&mut request, 2)?;
            next(&mut request, 3)?;
            next(&mut request, 4)?;
        }
        // getPinToken: keyAgreement, pinHashEnc. Elementos extras são
        // tratados como permissions/rpId presentes, que a spec rejeita
        // (CTAP 2.1 §6.5.5.7.1).
        0x05 => {
            next(&mut request, 1)?;
            next(&mut request, 4)?;
            if rest.len() > 2 {
                let item = rest[2];
                if matches!(item, Value::Text(_)) {
                    request.rp_id = Some(value_to_text(item)?);
                } else {
                    request.permissions = Some(value_to_u8(item)?);
                }
            }
        }
        // getPinUvAuthTokenUsingUvWithPermissions: keyAgreement, permissions, rpId
        0x06 => {
            next(&mut request, 1)?;
            next(&mut request, 5)?;
            next(&mut request, 6)?;
        }
        // getPinUvAuthTokenUsingPinWithPermissions:
        // keyAgreement, pinHashEnc, permissions, rpId
        0x09 => {
            next(&mut request, 1)?;
            next(&mut request, 4)?;
            next(&mut request, 5)?;
            next(&mut request, 6)?;
        }
        // getPINRetries/getKeyAgreement/getUVRetries: sem parâmetros extras.
        _ => {}
    }

    Ok(request)
}

fn decode_request_from_map(entries: &[(Value, Value)]) -> Result<ClientPinRequest, Ctap2Error> {
    let mut request = ClientPinRequest::default();
    for (key, val) in entries {
        let name = match key {
            Value::Integer(n) => match i64::try_from(*n).unwrap_or_default() {
                0x01 => Some("pinProtocol"),
                0x02 => Some("subCommand"),
                0x03 => Some("keyAgreement"),
                0x04 => Some("pinAuth"),
                0x05 => Some("newPinEnc"),
                0x06 => Some("pinHashEnc"),
                0x09 => Some("permissions"),
                0x0A => Some("rpId"),
                _ => None,
            },
            Value::Text(t) => Some(t.as_str()),
            _ => None,
        };
        match name {
            Some("pinProtocol") => request.pin_protocol = Some(value_to_u8(val)?),
            Some("subCommand") => request.sub_command = value_to_u8(val)?,
            Some("keyAgreement") => request.key_agreement = Some(CoseEc2Key::from_cose_value(val)?),
            Some("pinAuth") => request.pin_auth = Some(value_to_bytes(val)?),
            Some("newPinEnc") => request.new_pin_enc = Some(value_to_bytes(val)?),
            Some("pinHashEnc") => request.pin_hash_enc = Some(value_to_bytes(val)?),
            Some("permissions") => request.permissions = Some(value_to_u8(val)?),
            Some("rpId") => request.rp_id = Some(value_to_text(val)?),
            _ => {}
        }
    }
    Ok(request)
}

fn value_to_u8(value: &Value) -> Result<u8, Ctap2Error> {
    match value {
        Value::Integer(n) => {
            let n = i64::try_from(*n).map_err(|_| Ctap2Error::InvalidParameter)?;
            u8::try_from(n).map_err(|_| Ctap2Error::InvalidParameter)
        }
        _ => Err(Ctap2Error::InvalidCbor),
    }
}

fn value_to_bytes(value: &Value) -> Result<Vec<u8>, Ctap2Error> {
    match value {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(Ctap2Error::InvalidCbor),
    }
}

fn value_to_text(value: &Value) -> Result<String, Ctap2Error> {
    match value {
        Value::Text(t) => Ok(t.clone()),
        _ => Err(Ctap2Error::InvalidCbor),
    }
}

/// Codifica a response do authenticatorClientPIN como mapa CBOR canônico
/// com chaves inteiras (0x01..0x05), na ordem crescente de chave.
pub(crate) fn encode_client_pin_response(
    response: &ClientPinResponse,
) -> Result<Vec<u8>, Ctap2Error> {
    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(5);
    if let Some(key_agreement) = &response.key_agreement {
        let value: Value =
            from_reader(key_agreement.as_slice()).map_err(|_| Ctap2Error::Unknown)?;
        entries.push((Value::Integer(Integer::from(1)), value));
    }
    if let Some(token) = &response.pin_uv_auth_token {
        entries.push((
            Value::Integer(Integer::from(2)),
            Value::Bytes(token.clone()),
        ));
    }
    if let Some(retries) = response.retries {
        entries.push((
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(retries)),
        ));
    }
    if let Some(power_cycle_state) = response.power_cycle_state {
        entries.push((
            Value::Integer(Integer::from(4)),
            Value::Bool(power_cycle_state),
        ));
    }
    if let Some(uv_retries) = response.uv_retries {
        entries.push((
            Value::Integer(Integer::from(5)),
            Value::Integer(Integer::from(uv_retries)),
        ));
    }
    let value = Value::Map(entries);
    let mut buf = Vec::new();
    into_writer(&value, &mut buf).map_err(|_| Ctap2Error::Unknown)?;
    Ok(buf)
}

/// Decodifica a response do authenticatorClientPIN (mapa de chaves inteiras).
/// Usado em testes e ferramentas.
#[cfg(test)]
pub(crate) fn decode_client_pin_response(data: &[u8]) -> Result<ClientPinResponse, Ctap2Error> {
    let mut restante = data;
    let value: Value = from_reader(&mut restante).map_err(|_| Ctap2Error::InvalidCbor)?;
    if !restante.is_empty() {
        return Err(Ctap2Error::InvalidCbor);
    }
    let Value::Map(entries) = value else {
        return Err(Ctap2Error::InvalidCbor);
    };
    let mut response = ClientPinResponse::default();
    for (key, val) in &entries {
        match key {
            Value::Integer(n) if *n == Integer::from(1) => {
                let mut buf = Vec::new();
                into_writer(val, &mut buf).map_err(|_| Ctap2Error::Unknown)?;
                response.key_agreement = Some(buf);
            }
            Value::Integer(n) if *n == Integer::from(2) => {
                response.pin_uv_auth_token = Some(value_to_bytes(val)?);
            }
            Value::Integer(n) if *n == Integer::from(3) => {
                response.retries = Some(value_to_u8(val)?);
            }
            Value::Integer(n) if *n == Integer::from(4) => match val {
                Value::Bool(b) => response.power_cycle_state = Some(*b),
                _ => return Err(Ctap2Error::InvalidCbor),
            },
            Value::Integer(n) if *n == Integer::from(5) => {
                response.uv_retries = Some(value_to_u8(val)?);
            }
            _ => {}
        }
    }
    Ok(response)
}

/// Monta o request CBOR posicional usado por python-fido2/Chromium.
/// Útil em testes: `[pinUvAuthProtocol, subCommand, keyAgreement,
/// pinUvAuthParam, newPinEnc, pinHashEnc, null, null, permissions, rpId]`.
#[cfg(test)]
pub(crate) fn encode_client_pin_request_array(
    request: &ClientPinRequest,
) -> Result<Vec<u8>, Ctap2Error> {
    let mut items: Vec<Value> = Vec::with_capacity(10);
    match request.pin_protocol {
        Some(v) => items.push(Value::Integer(Integer::from(v))),
        None => items.push(Value::Null),
    }
    items.push(Value::Integer(Integer::from(request.sub_command)));
    match &request.key_agreement {
        Some(key) => items.push(key.to_cose_value()),
        None => items.push(Value::Null),
    }
    for field in [
        &request.pin_auth,
        &request.new_pin_enc,
        &request.pin_hash_enc,
    ] {
        match field {
            Some(bytes) => items.push(Value::Bytes(bytes.clone())),
            None => items.push(Value::Null),
        }
    }
    items.push(Value::Null);
    items.push(Value::Null);
    match request.permissions {
        Some(v) => items.push(Value::Integer(Integer::from(v))),
        None => items.push(Value::Null),
    }
    match &request.rp_id {
        Some(v) => items.push(Value::Text(v.clone())),
        None => items.push(Value::Null),
    }
    let value = Value::Array(items);
    let mut buf = Vec::new();
    into_writer(&value, &mut buf).map_err(|_| Ctap2Error::Unknown)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctap2::{
        CredProtectPolicy, Ctap2Authenticator, Extensions, GetAssertionOptions,
        GetAssertionRequest, MakeCredentialOptions, MakeCredentialRequest, PublicKeyCredParams,
        RelyingParty, User, UserVerification, AAGUID,
    };
    use crypto::pin_protocol::{zero_pad_to_64, PinUvProtocol};
    use crypto::CryptoEngine;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use storage::{StorageBackend, StorageEngine};

    fn create_authenticator() -> Ctap2Authenticator {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap()
    }

    fn send(
        authenticator: &mut Ctap2Authenticator,
        request: &ClientPinRequest,
    ) -> Result<ClientPinResponse, Ctap2Error> {
        let data = encode_client_pin_request_array(request).unwrap();
        let encoded = handle_client_pin(authenticator, &data)?;
        decode_client_pin_response(&encoded)
    }

    /// Lado da plataforma em um teste: faz o acordo de chaves e encapsula as
    /// operações de alto nível (set_pin, change_pin, get_pin_token),
    /// espelhando `fido2.ctap2.pin.ClientPin`.
    struct TestPlatform {
        protocol: PinUvProtocol,
        client_public: Vec<u8>,
        secret: Zeroizing<Vec<u8>>,
    }

    impl TestPlatform {
        fn start(authenticator: &mut Ctap2Authenticator, version: u8) -> (Self, CoseEc2Key) {
            let mut platform = Self {
                protocol: PinUvProtocol::new(version).unwrap(),
                client_public: Vec::new(),
                secret: Zeroizing::new(Vec::new()),
            };
            let authenticator_cose = platform.refresh_agreement(authenticator);
            (platform, authenticator_cose)
        }

        /// Refaz o acordo de chaves, como o python-fido2 faz antes de cada
        /// subcomando (`_get_shared_secret`). A chave do autenticador é
        /// efêmera por transação.
        fn refresh_agreement(&mut self, authenticator: &mut Ctap2Authenticator) -> CoseEc2Key {
            let response = send(
                authenticator,
                &ClientPinRequest {
                    pin_protocol: Some(self.protocol.version()),
                    sub_command: ClientPinSubCommand::GetKeyAgreement as u8,
                    ..Default::default()
                },
            )
            .unwrap();
            let cose_bytes = response.key_agreement.expect("keyAgreement ausente");
            let value: Value = from_reader(cose_bytes.as_slice()).unwrap();
            let authenticator_cose = CoseEc2Key::from_cose_value(&value).unwrap();

            let key = PinAgreementKey::generate().unwrap();
            self.client_public = key.public_key_bytes().unwrap();
            let z = Zeroizing::new(
                key.agree(&authenticator_cose.to_uncompressed().unwrap())
                    .unwrap(),
            );
            self.secret = Zeroizing::new(self.protocol.kdf(&z).unwrap());

            authenticator_cose
        }

        fn request(&self, sub_command: u8) -> ClientPinRequest {
            ClientPinRequest {
                pin_protocol: Some(self.protocol.version()),
                sub_command,
                ..Default::default()
            }
        }

        fn request_with_key(&self, sub_command: u8) -> ClientPinRequest {
            let mut request = self.request(sub_command);
            request.key_agreement = Some(CoseEc2Key {
                x: self.client_public[1..33].to_vec(),
                y: self.client_public[33..65].to_vec(),
            });
            request
        }

        fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
            self.protocol.encrypt(&self.secret, plaintext).unwrap()
        }

        fn authenticate(&self, message: &[u8]) -> Vec<u8> {
            self.protocol.authenticate(&self.secret, message).unwrap()
        }

        fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
            self.protocol.decrypt(&self.secret, ciphertext).unwrap()
        }

        fn set_pin(
            &mut self,
            authenticator: &mut Ctap2Authenticator,
            pin: &[u8],
        ) -> Result<(), Ctap2Error> {
            self.refresh_agreement(authenticator);
            let mut request = self.request_with_key(ClientPinSubCommand::SetPIN as u8);
            request.new_pin_enc = Some(self.encrypt(&zero_pad_to_64(pin).unwrap()));
            request.pin_auth = Some(self.authenticate(request.new_pin_enc.as_ref().unwrap()));
            send(authenticator, &request).map(|_| ())
        }

        fn get_pin_token(
            &mut self,
            authenticator: &mut Ctap2Authenticator,
            pin: &[u8],
        ) -> Result<Vec<u8>, Ctap2Error> {
            self.refresh_agreement(authenticator);
            let mut request = self.request_with_key(ClientPinSubCommand::GetPINToken as u8);
            request.pin_hash_enc = Some(self.encrypt(&hash_pin(pin)));
            let response = send(authenticator, &request)?;
            response
                .pin_uv_auth_token
                .ok_or(Ctap2Error::InvalidParameter)
        }

        fn get_pin_token_with_permissions(
            &mut self,
            authenticator: &mut Ctap2Authenticator,
            pin: &[u8],
            permissions: u8,
            rp_id: Option<&str>,
        ) -> Result<Vec<u8>, Ctap2Error> {
            self.refresh_agreement(authenticator);
            let mut request = self.request_with_key(
                ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions as u8,
            );
            request.pin_hash_enc = Some(self.encrypt(&hash_pin(pin)));
            request.permissions = Some(permissions);
            request.rp_id = rp_id.map(|s| s.to_string());
            let response = send(authenticator, &request)?;
            response
                .pin_uv_auth_token
                .ok_or(Ctap2Error::InvalidParameter)
        }

        fn get_uv_token(
            &mut self,
            authenticator: &mut Ctap2Authenticator,
            permissions: u8,
            rp_id: Option<&str>,
        ) -> Result<Vec<u8>, Ctap2Error> {
            self.refresh_agreement(authenticator);
            let mut request = self.request_with_key(
                ClientPinSubCommand::GetPinUvAuthTokenUsingUvWithPermissions as u8,
            );
            request.permissions = Some(permissions);
            request.rp_id = rp_id.map(|s| s.to_string());
            let response = send(authenticator, &request)?;
            response
                .pin_uv_auth_token
                .ok_or(Ctap2Error::InvalidParameter)
        }

        fn change_pin(
            &mut self,
            authenticator: &mut Ctap2Authenticator,
            old_pin: &[u8],
            new_pin: &[u8],
        ) -> Result<(), Ctap2Error> {
            self.refresh_agreement(authenticator);
            let mut request = self.request_with_key(ClientPinSubCommand::ChangePIN as u8);
            let pin_hash_enc = self.encrypt(&hash_pin(old_pin));
            let new_pin_enc = self.encrypt(&zero_pad_to_64(new_pin).unwrap());
            request.pin_hash_enc = Some(pin_hash_enc);
            request.new_pin_enc = Some(new_pin_enc);
            let mut message = Vec::new();
            message.extend_from_slice(request.new_pin_enc.as_ref().unwrap());
            message.extend_from_slice(request.pin_hash_enc.as_ref().unwrap());
            request.pin_auth = Some(self.authenticate(&message));
            send(authenticator, &request).map(|_| ())
        }
    }

    fn hash_pin(pin: &[u8]) -> Vec<u8> {
        let engine = CryptoEngine::new().unwrap();
        engine.sha256(pin)[..16].to_vec()
    }

    /// Backend em memória compartilhável entre instâncias: simula a
    /// persistência que sobrevive a um power cycle do autenticador.
    #[derive(Clone, Default)]
    struct SharedMemoryBackend(Arc<Mutex<HashMap<String, Vec<u8>>>>);

    impl StorageBackend for SharedMemoryBackend {
        fn read(&self, key: &str) -> Result<Option<Vec<u8>>, storage::StorageError> {
            Ok(self.0.lock().unwrap().get(key).cloned())
        }

        fn write(&mut self, key: &str, value: &[u8]) -> Result<(), storage::StorageError> {
            self.0
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &str) -> Result<(), storage::StorageError> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }

        fn list_keys(&self) -> Result<Vec<String>, storage::StorageError> {
            Ok(self.0.lock().unwrap().keys().cloned().collect())
        }
    }

    #[test]
    fn test_get_pin_retries_initial() {
        let mut authenticator = create_authenticator();
        let response = send(
            &mut authenticator,
            &ClientPinRequest {
                pin_protocol: Some(1),
                sub_command: ClientPinSubCommand::GetPINRetries as u8,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(response.retries, Some(PIN_MAX_RETRIES));
        assert!(response.power_cycle_state.is_none());
    }

    #[test]
    fn test_get_key_agreement_returns_cose_key() {
        let mut authenticator = create_authenticator();
        let response = send(
            &mut authenticator,
            &ClientPinRequest {
                pin_protocol: Some(1),
                sub_command: ClientPinSubCommand::GetKeyAgreement as u8,
                ..Default::default()
            },
        )
        .unwrap();
        let cose_bytes = response.key_agreement.unwrap();
        let value: Value = from_reader(cose_bytes.as_slice()).unwrap();
        let key = CoseEc2Key::from_cose_value(&value).unwrap();
        assert_eq!(key.x.len(), 32);
        assert_eq!(key.y.len(), 32);
    }

    #[test]
    fn test_get_key_agreement_requires_protocol() {
        let mut authenticator = create_authenticator();
        let result = send(
            &mut authenticator,
            &ClientPinRequest {
                pin_protocol: None,
                sub_command: ClientPinSubCommand::GetKeyAgreement as u8,
                ..Default::default()
            },
        );
        assert_eq!(result.unwrap_err(), Ctap2Error::MissingParameter);
    }

    #[test]
    fn test_unsupported_protocol_rejected() {
        let mut authenticator = create_authenticator();
        let result = send(
            &mut authenticator,
            &ClientPinRequest {
                pin_protocol: Some(3),
                sub_command: ClientPinSubCommand::GetKeyAgreement as u8,
                ..Default::default()
            },
        );
        assert_eq!(result.unwrap_err(), Ctap2Error::InvalidParameter);
    }

    #[test]
    fn test_cose_key_roundtrip() {
        let original = CoseEc2Key {
            x: vec![0x11; 32],
            y: vec![0x22; 32],
        };
        let value = original.to_cose_value();
        let parsed = CoseEc2Key::from_cose_value(&value).unwrap();
        assert_eq!(parsed, original);
        assert_eq!(original.to_uncompressed().unwrap().len(), 65);
        assert_eq!(original.to_uncompressed().unwrap()[0], 0x04);
    }

    fn full_set_token_change_flow(version: u8) {
        let mut authenticator = create_authenticator();
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, version);

        // setPIN
        platform.set_pin(&mut authenticator, b"1234").unwrap();
        assert!(is_pin_set(authenticator.get_storage()));

        // getPinToken
        let token_enc = platform.get_pin_token(&mut authenticator, b"1234").unwrap();
        let token = platform.decrypt(&token_enc);
        assert_eq!(token.len(), 32);

        // O token da sessão valida um pinUvAuthParam sobre clientDataHash.
        let client_data_hash = [0xAAu8; 32];
        let param = platform
            .protocol
            .authenticate(&token, &client_data_hash)
            .unwrap();
        authenticator
            .verify_pin_uv_auth_param(version, &param, &client_data_hash)
            .unwrap();
        assert!(authenticator
            .verify_pin_uv_auth_param(version, &[0u8; 16], &client_data_hash)
            .is_err());

        // changePIN
        platform
            .change_pin(&mut authenticator, b"1234", b"5678")
            .unwrap();
        assert!(platform.get_pin_token(&mut authenticator, b"5678").is_ok());
        assert!(platform.get_pin_token(&mut authenticator, b"1234").is_err());
    }

    #[test]
    fn test_set_token_change_flow_protocol_1() {
        full_set_token_change_flow(1);
    }

    #[test]
    fn test_set_token_change_flow_protocol_2() {
        full_set_token_change_flow(2);
    }

    #[test]
    fn test_set_pin_when_already_set_returns_pin_auth_invalid() {
        let mut authenticator = create_authenticator();
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        platform.set_pin(&mut authenticator, b"1234").unwrap();
        let result = platform.set_pin(&mut authenticator, b"9999");
        assert_eq!(result.unwrap_err(), Ctap2Error::PinAuthInvalid);
    }

    #[test]
    fn test_set_pin_short_pin_policy_violation() {
        let mut authenticator = create_authenticator();
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        let result = platform.set_pin(&mut authenticator, b"12");
        assert_eq!(result.unwrap_err(), Ctap2Error::PinPolicyViolation);
    }

    #[test]
    fn test_set_pin_bad_pin_auth_does_not_set_pin() {
        let mut authenticator = create_authenticator();
        let (platform, _cose) = TestPlatform::start(&mut authenticator, 1);
        let mut request = platform.request_with_key(ClientPinSubCommand::SetPIN as u8);
        request.new_pin_enc = Some(platform.encrypt(&zero_pad_to_64(b"1234").unwrap()));
        request.pin_auth = Some(vec![0u8; 16]);
        let result = send(&mut authenticator, &request);
        assert_eq!(result.unwrap_err(), Ctap2Error::PinAuthInvalid);
        assert!(!is_pin_set(authenticator.get_storage()));
    }

    #[test]
    fn test_change_pin_bad_pin_auth_does_not_consume_retries() {
        let mut authenticator = create_authenticator();
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        platform.set_pin(&mut authenticator, b"1234").unwrap();

        let mut request = platform.request_with_key(ClientPinSubCommand::ChangePIN as u8);
        let pin_hash_enc = platform.encrypt(&hash_pin(b"1234"));
        let new_pin_enc = platform.encrypt(&zero_pad_to_64(b"5678").unwrap());
        request.pin_hash_enc = Some(pin_hash_enc);
        request.new_pin_enc = Some(new_pin_enc);
        request.pin_auth = Some(vec![0u8; 32]);
        let result = send(&mut authenticator, &request);
        assert_eq!(result.unwrap_err(), Ctap2Error::PinAuthInvalid);
        assert_eq!(authenticator.get_pin_retries(), PIN_MAX_RETRIES);
    }

    #[test]
    fn test_wrong_pin_decrements_then_blocks_after_three() {
        let mut authenticator = create_authenticator();
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 1);
        platform.set_pin(&mut authenticator, b"1234").unwrap();

        // 1ª falha: PIN_INVALID, retries 7
        assert_eq!(
            platform
                .get_pin_token(&mut authenticator, b"0000")
                .unwrap_err(),
            Ctap2Error::PinInvalid
        );
        assert_eq!(authenticator.get_pin_retries(), PIN_MAX_RETRIES - 1);

        // 2ª falha: PIN_INVALID, retries 6
        assert_eq!(
            platform
                .get_pin_token(&mut authenticator, b"0000")
                .unwrap_err(),
            Ctap2Error::PinInvalid
        );
        assert_eq!(authenticator.get_pin_retries(), PIN_MAX_RETRIES - 2);

        // 3ª falha consecutiva: PIN_AUTH_BLOCKED (power cycle)
        assert_eq!(
            platform
                .get_pin_token(&mut authenticator, b"0000")
                .unwrap_err(),
            Ctap2Error::PinAuthBlocked
        );

        // getPINRetries reporta powerCycleState
        let response = send(
            &mut authenticator,
            &ClientPinRequest {
                pin_protocol: Some(1),
                sub_command: ClientPinSubCommand::GetPINRetries as u8,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(response.power_cycle_state, Some(true));

        // Qualquer operação com PIN continua bloqueada
        assert_eq!(
            platform
                .get_pin_token(&mut authenticator, b"1234")
                .unwrap_err(),
            Ctap2Error::PinAuthBlocked
        );
    }

    #[test]
    fn test_retries_reset_on_success() {
        let mut authenticator = create_authenticator();
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        platform.set_pin(&mut authenticator, b"1234").unwrap();

        assert!(platform.get_pin_token(&mut authenticator, b"0000").is_err());
        assert!(platform.get_pin_token(&mut authenticator, b"0000").is_err());
        assert_eq!(authenticator.get_pin_retries(), PIN_MAX_RETRIES - 2);

        assert!(platform.get_pin_token(&mut authenticator, b"1234").is_ok());
        assert_eq!(authenticator.get_pin_retries(), PIN_MAX_RETRIES);
    }

    /// O bloqueio `PIN_AUTH_BLOCKED` é volátil: sobrevive dentro da sessão
    /// (até uma verificação bem-sucedida), mas um power cycle — nova
    /// instância sobre o mesmo backend persistente — o encerra, enquanto o
    /// contador persistente de tentativas continua valendo (CTAP 2.1 §6.5.5.6).
    #[test]
    fn test_pin_auth_blocked_clears_on_power_cycle() {
        let backend = SharedMemoryBackend::default();

        // Sessão atual: define o PIN e acumula 3 falhas consecutivas.
        let storage = StorageEngine::with_backend(Box::new(backend.clone()));
        let crypto = CryptoEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 1);
        platform.set_pin(&mut authenticator, b"1234").unwrap();

        assert_eq!(
            platform
                .get_pin_token(&mut authenticator, b"0000")
                .unwrap_err(),
            Ctap2Error::PinInvalid
        );
        assert_eq!(
            platform
                .get_pin_token(&mut authenticator, b"0000")
                .unwrap_err(),
            Ctap2Error::PinInvalid
        );
        assert_eq!(
            platform
                .get_pin_token(&mut authenticator, b"0000")
                .unwrap_err(),
            Ctap2Error::PinAuthBlocked
        );

        // Na mesma sessão, mesmo o PIN correto segue bloqueado...
        assert_eq!(
            platform
                .get_pin_token(&mut authenticator, b"1234")
                .unwrap_err(),
            Ctap2Error::PinAuthBlocked
        );
        assert_eq!(authenticator.get_pin_retries(), PIN_MAX_RETRIES - 3);

        // ...até o "power cycle": nova instância sobre o mesmo backend.
        drop(platform);
        drop(authenticator);
        let storage = StorageEngine::with_backend(Box::new(backend));
        let crypto = CryptoEngine::new().unwrap();
        let mut rebooted = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        assert_eq!(rebooted.get_pin_retries(), PIN_MAX_RETRIES - 3);

        let (mut platform_after, _cose) = TestPlatform::start(&mut rebooted, 1);
        // O PIN correto é aceito e restaura as tentativas.
        assert!(platform_after.get_pin_token(&mut rebooted, b"1234").is_ok());
        assert_eq!(rebooted.get_pin_retries(), PIN_MAX_RETRIES);
    }

    /// Localiza um PIN cujo `LEFT(SHA-256(PIN),16)` termina em 0x00 — caso que
    /// a remoção indevida de zero-padding do pinHashEnc rejeitava (~1/256 dos
    /// PINs, CTAP 2.1 §6.5.5.5).
    fn find_pin_with_trailing_zero_hash() -> Vec<u8> {
        let engine = CryptoEngine::new().unwrap();
        for n in 0u32..100_000 {
            let candidate = format!("{:04}", n);
            if engine.sha256(candidate.as_bytes())[15] == 0x00 {
                return candidate.into_bytes();
            }
        }
        panic!("nenhum PIN com hash terminando em 0x00 foi encontrado");
    }

    fn full_flow_with_trailing_zero_pin(version: u8) {
        let pin = find_pin_with_trailing_zero_hash();
        assert_eq!(hash_pin(&pin)[15], 0x00);

        let mut authenticator = create_authenticator();
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, version);

        // setPIN + getPinToken com hash terminando em 0x00 devem funcionar.
        platform.set_pin(&mut authenticator, &pin).unwrap();
        assert!(platform.get_pin_token(&mut authenticator, &pin).is_ok());

        // changePIN compara os mesmos 16 bytes exatos do PIN atual.
        platform
            .change_pin(&mut authenticator, &pin, b"9876")
            .unwrap();
        assert!(platform.get_pin_token(&mut authenticator, b"9876").is_ok());
        assert!(platform.get_pin_token(&mut authenticator, &pin).is_err());
    }

    #[test]
    fn test_trailing_zero_hash_pin_accepted_protocol_1() {
        full_flow_with_trailing_zero_pin(1);
    }

    #[test]
    fn test_trailing_zero_hash_pin_accepted_protocol_2() {
        full_flow_with_trailing_zero_pin(2);
    }

    /// Tokens emitidos via getPinUvAuthTokenUsingPinWithPermissions com
    /// permissões mc|ga exigem rpId (CTAP 2.1 §6.5.5.7); sem ele o token
    /// autorizaria MakeCredential/GetAssertion para qualquer RP.
    #[test]
    fn test_mc_ga_permissions_require_rp_id() {
        let mut authenticator = create_authenticator();
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        platform.set_pin(&mut authenticator, b"1234").unwrap();

        let result = platform.get_pin_token_with_permissions(
            &mut authenticator,
            b"1234",
            PERMISSION_MC_GA,
            None,
        );
        assert_eq!(result.unwrap_err(), Ctap2Error::MissingParameter);

        // Com rpId o token é emitido normalmente.
        assert!(platform
            .get_pin_token_with_permissions(
                &mut authenticator,
                b"1234",
                PERMISSION_MC_GA,
                Some("example.com"),
            )
            .is_ok());
    }

    #[test]
    fn test_get_pin_token_no_pin_set() {
        let mut authenticator = create_authenticator();
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 1);
        let result = platform.get_pin_token(&mut authenticator, b"1234");
        assert_eq!(result.unwrap_err(), Ctap2Error::PinNotSet);
    }

    #[test]
    fn test_get_pin_token_rejects_permissions_and_rpid() {
        let mut authenticator = create_authenticator();
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        platform.set_pin(&mut authenticator, b"1234").unwrap();

        let mut request = platform.request_with_key(ClientPinSubCommand::GetPINToken as u8);
        request.pin_hash_enc = Some(platform.encrypt(&hash_pin(b"1234")));
        request.permissions = Some(PERMISSION_MC_GA);
        assert_eq!(
            send(&mut authenticator, &request).unwrap_err(),
            Ctap2Error::InvalidParameter
        );
    }

    #[test]
    fn test_get_pin_token_with_permissions_and_rpid() {
        let mut authenticator = create_authenticator();
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        platform.set_pin(&mut authenticator, b"1234").unwrap();

        let token_enc = platform
            .get_pin_token_with_permissions(
                &mut authenticator,
                b"1234",
                PERMISSION_MC_GA,
                Some("example.com"),
            )
            .unwrap();
        let token = platform.decrypt(&token_enc);
        assert_eq!(token.len(), 32);

        let client_data_hash = [0x55u8; 32];
        let param = platform
            .protocol
            .authenticate(&token, &client_data_hash)
            .unwrap();
        authenticator
            .verify_pin_uv_auth_param(2, &param, &client_data_hash)
            .unwrap();
    }

    #[test]
    fn test_unauthorized_permission_rejected() {
        let mut authenticator = create_authenticator();
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        platform.set_pin(&mut authenticator, b"1234").unwrap();

        // bioEnroll não é anunciado → be (0x08) não é autorizado.
        let result = platform.get_pin_token_with_permissions(
            &mut authenticator,
            b"1234",
            PERMISSION_MC_GA | PERMISSION_BE,
            None,
        );
        assert_eq!(result.unwrap_err(), Ctap2Error::UnauthorizedPermission);

        // authnrCfg não é anunciado → acfg (0x20) não é autorizado.
        let result = platform.get_pin_token_with_permissions(
            &mut authenticator,
            b"1234",
            PERMISSION_ACFG,
            None,
        );
        assert_eq!(result.unwrap_err(), Ctap2Error::UnauthorizedPermission);
    }

    #[test]
    fn test_zero_permissions_rejected() {
        let mut authenticator = create_authenticator();
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        platform.set_pin(&mut authenticator, b"1234").unwrap();
        let result = platform.get_pin_token_with_permissions(&mut authenticator, b"1234", 0, None);
        assert_eq!(result.unwrap_err(), Ctap2Error::InvalidParameter);
    }

    #[test]
    fn test_get_uv_token_returns_uv_blocked() {
        let mut authenticator = create_authenticator();
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        platform.set_pin(&mut authenticator, b"1234").unwrap();

        let mut request = platform
            .request_with_key(ClientPinSubCommand::GetPinUvAuthTokenUsingUvWithPermissions as u8);
        request.permissions = Some(PERMISSION_MC_GA);
        let result = send(&mut authenticator, &request);
        assert_eq!(result.unwrap_err(), Ctap2Error::UvBlocked);
    }

    #[test]
    fn test_get_uv_retries_unsupported() {
        let mut authenticator = create_authenticator();
        let result = send(
            &mut authenticator,
            &ClientPinRequest {
                pin_protocol: Some(1),
                sub_command: ClientPinSubCommand::GetUVRetries as u8,
                ..Default::default()
            },
        );
        assert_eq!(result.unwrap_err(), Ctap2Error::UnsupportedOption);
    }

    /// Mock de UV embutida restrito a host: sem alegações de hardware, apenas
    /// um verificador configurável para testes.
    #[derive(Debug)]
    struct MockUserVerification {
        succeed: bool,
        retries: u8,
    }

    impl UserVerification for MockUserVerification {
        fn verify(&mut self) -> Result<(), Ctap2Error> {
            if self.succeed {
                Ok(())
            } else {
                Err(Ctap2Error::UvBlocked)
            }
        }

        fn retries(&self) -> u8 {
            self.retries
        }
    }

    /// Autenticador com capability `uv` e mock injetado.
    fn authenticator_with_uv_mock(succeed: bool, retries: u8) -> Ctap2Authenticator {
        let mut authenticator = create_authenticator();
        let mut caps = authenticator.capabilities().clone();
        if !caps.options.contains(&"uv".to_string()) {
            caps.options.push("uv".to_string());
        }
        authenticator.set_capabilities(caps);
        // Semeia o contador persistente com o valor passado, para preservar
        // os testes existentes que liam o valor volátil do mock.
        let _ = authenticator
            .get_storage_mut()
            .store(UV_RETRIES_KEY, retries.to_string().into_bytes());
        authenticator
            .set_user_verification(Some(Box::new(MockUserVerification { succeed, retries })));
        authenticator
    }

    fn make_credential_with_uv_token(
        client_data_hash: Vec<u8>,
        token: &[u8],
        protocol_version: u8,
    ) -> MakeCredentialRequest {
        let protocol = PinUvProtocol::new(protocol_version).unwrap();
        MakeCredentialRequest {
            client_data_hash: client_data_hash.clone(),
            rp: RelyingParty {
                id: "example.com".to_string(),
                name: None,
                icon: None,
            },
            user: User {
                id: b"user123".to_vec(),
                name: None,
                display_name: None,
                icon_url: None,
            },
            pub_key_cred_params: vec![PublicKeyCredParams {
                r#type: "public-key".to_string(),
                algorithms: -8,
            }],
            exclude_list: vec![],
            extensions: None,
            options: MakeCredentialOptions {
                rk: false,
                uv: true,
                up: false,
                extended: false,
            },
            pin_uv_auth_param: Some(protocol.authenticate(token, &client_data_hash).unwrap()),
            pin_protocol: Some(protocol_version),
            enterprise_protections: None,
        }
    }

    #[test]
    fn test_builtin_uv_mock_get_uv_retries_success() {
        let mut authenticator = authenticator_with_uv_mock(true, 5);
        let response = send(
            &mut authenticator,
            &ClientPinRequest {
                pin_protocol: Some(2),
                sub_command: ClientPinSubCommand::GetUVRetries as u8,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(response.uv_retries, Some(5));
    }

    #[test]
    fn test_builtin_uv_mock_get_uv_token_success() {
        let mut authenticator = authenticator_with_uv_mock(true, 5);
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        let token_enc = platform
            .get_uv_token(&mut authenticator, PERMISSION_MC_GA, Some("example.com"))
            .unwrap();
        let token = platform.decrypt(&token_enc);
        assert_eq!(token.len(), 32);

        // O token autentica operações com escopo mc.
        let client_data_hash = [0xAAu8; 32];
        let param = platform
            .protocol
            .authenticate(&token, &client_data_hash)
            .unwrap();
        authenticator
            .verify_pin_uv_auth_param(2, &param, &client_data_hash)
            .unwrap();
    }

    #[test]
    fn test_builtin_uv_mock_get_uv_token_failure() {
        let mut authenticator = authenticator_with_uv_mock(false, 0);
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        let result =
            platform.get_uv_token(&mut authenticator, PERMISSION_MC_GA, Some("example.com"));
        assert_eq!(result.unwrap_err(), Ctap2Error::UvBlocked);
    }

    #[test]
    fn test_builtin_uv_mock_flag_set() {
        let mut authenticator = authenticator_with_uv_mock(true, 5);
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        let token_enc = platform
            .get_uv_token(&mut authenticator, PERMISSION_MC_GA, Some("example.com"))
            .unwrap();
        let token = platform.decrypt(&token_enc);

        // MakeCredential com `uv` e token UV autenticado seta o bit 0x04.
        let client_data_hash = vec![0x41u8; 32];
        let request = make_credential_with_uv_token(client_data_hash, &token, 2);
        let response = authenticator.make_credential(request).unwrap();
        assert_ne!(response.auth_data[32] & 0x04, 0);
    }

    #[test]
    fn test_builtin_uv_mock_get_assertion_flag_set() {
        let mut authenticator = authenticator_with_uv_mock(true, 5);
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        let token_enc = platform
            .get_uv_token(&mut authenticator, PERMISSION_MC_GA, Some("example.com"))
            .unwrap();
        let token = platform.decrypt(&token_enc);

        // Credencial criada com o token UV (permissão mc).
        let mc_cdh = vec![0x41u8; 32];
        let mc = make_credential_with_uv_token(mc_cdh, &token, 2);
        authenticator.make_credential(mc).unwrap();

        // GetAssertion com `uv` e token UV autenticado (permissão ga) seta 0x04.
        let ga_cdh = vec![0x42u8; 32];
        let param = platform.protocol.authenticate(&token, &ga_cdh).unwrap();
        let ga = GetAssertionRequest {
            rp_id: "example.com".to_string(),
            credentials: vec![],
            allow_list: None,
            client_data_hash: ga_cdh,
            extensions: None,
            options: GetAssertionOptions {
                up: false,
                uv: true,
            },
            pin_uv_auth_param: Some(param),
            pin_protocol: Some(2),
            uv: None,
        };
        let response = authenticator.get_assertion(ga).unwrap();
        assert_ne!(response.auth_data[32] & 0x04, 0);

        // Sem token, o bit UV permanece apagado.
        let plain = GetAssertionRequest {
            rp_id: "example.com".to_string(),
            credentials: vec![],
            allow_list: None,
            client_data_hash: vec![0x43u8; 32],
            extensions: None,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_protocol: None,
            uv: None,
        };
        let response = authenticator.get_assertion(plain).unwrap();
        assert_eq!(response.auth_data[32] & 0x04, 0);
    }

    #[test]
    fn test_builtin_uv_mock_satisfies_always_uv() {
        let mut authenticator = authenticator_with_uv_mock(true, 5);
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        let token_enc = platform
            .get_uv_token(&mut authenticator, PERMISSION_MC_GA, Some("example.com"))
            .unwrap();
        let token = platform.decrypt(&token_enc);

        // Credencial pré-existente criada antes de ativar o alwaysUv.
        let mc_cdh = vec![0x41u8; 32];
        let mc = make_credential_with_uv_token(mc_cdh, &token, 2);
        authenticator.make_credential(mc).unwrap();

        // Ativa alwaysUv diretamente no storage (mesma chave do authnr_config).
        authenticator
            .get_storage_mut()
            .store("sys:cfg_always_uv", b"1".to_vec())
            .unwrap();

        // MakeCredential sem `uv` é negado com alwaysUv ativo.
        let mut plain_mc = make_credential_with_uv_token(vec![0x44u8; 32], &token, 2);
        plain_mc.options.uv = false;
        plain_mc.pin_uv_auth_param = None;
        plain_mc.pin_protocol = None;
        let error = authenticator.make_credential(plain_mc).unwrap_err();
        assert_eq!(
            error.downcast_ref::<Ctap2Error>(),
            Some(&Ctap2Error::PinRequired)
        );

        // MakeCredential com `uv` + token UV é aceito.
        let mc_cdh = vec![0x45u8; 32];
        let mc = make_credential_with_uv_token(mc_cdh, &token, 2);
        authenticator.make_credential(mc).unwrap();

        // GetAssertion sem `uv` é negado com alwaysUv ativo.
        let plain_ga = GetAssertionRequest {
            rp_id: "example.com".to_string(),
            credentials: vec![],
            allow_list: None,
            client_data_hash: vec![0x46u8; 32],
            extensions: None,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_protocol: None,
            uv: None,
        };
        let error = authenticator.get_assertion(plain_ga).unwrap_err();
        assert_eq!(
            error.downcast_ref::<Ctap2Error>(),
            Some(&Ctap2Error::PinRequired)
        );

        // GetAssertion com `uv` + token UV é aceito e seta 0x04.
        let ga_cdh = vec![0x47u8; 32];
        let param = platform.protocol.authenticate(&token, &ga_cdh).unwrap();
        let ga = GetAssertionRequest {
            rp_id: "example.com".to_string(),
            credentials: vec![],
            allow_list: None,
            client_data_hash: ga_cdh,
            extensions: None,
            options: GetAssertionOptions {
                up: false,
                uv: true,
            },
            pin_uv_auth_param: Some(param),
            pin_protocol: Some(2),
            uv: None,
        };
        let response = authenticator.get_assertion(ga).unwrap();
        assert_ne!(response.auth_data[32] & 0x04, 0);
    }

    #[test]
    fn test_builtin_uv_mock_satisfies_cred_protect_l3() {
        let mut authenticator = authenticator_with_uv_mock(true, 5);
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        let token_enc = platform
            .get_uv_token(&mut authenticator, PERMISSION_MC_GA, Some("example.com"))
            .unwrap();
        let token = platform.decrypt(&token_enc);

        // Credencial credProtect=3 (userVerificationRequired).
        let mc_cdh = vec![0x41u8; 32];
        let mut mc = make_credential_with_uv_token(mc_cdh, &token, 2);
        mc.extensions = Some(Extensions {
            cred_protect: Some(CredProtectPolicy::UserVerificationRequired.into()),
            ..Default::default()
        });
        authenticator.make_credential(mc).unwrap();

        // Sem token: a credencial é silenciosamente ignorada (descoberta por RP).
        let plain = GetAssertionRequest {
            rp_id: "example.com".to_string(),
            credentials: vec![],
            allow_list: None,
            client_data_hash: vec![0x42u8; 32],
            extensions: None,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_protocol: None,
            uv: None,
        };
        let error = authenticator.get_assertion(plain).unwrap_err();
        assert_eq!(
            error.downcast_ref::<Ctap2Error>(),
            Some(&Ctap2Error::NoCredentials)
        );

        // Com token UV (permissão ga): a credencial é retornada com bit UV.
        let ga_cdh = vec![0x43u8; 32];
        let param = platform.protocol.authenticate(&token, &ga_cdh).unwrap();
        let ga = GetAssertionRequest {
            rp_id: "example.com".to_string(),
            credentials: vec![],
            allow_list: None,
            client_data_hash: ga_cdh,
            extensions: None,
            options: GetAssertionOptions {
                up: false,
                uv: true,
            },
            pin_uv_auth_param: Some(param),
            pin_protocol: Some(2),
            uv: None,
        };
        let response = authenticator.get_assertion(ga).unwrap();
        assert!(response.credential.is_some());
        assert_ne!(response.auth_data[32] & 0x04, 0);
    }

    #[test]
    fn test_builtin_uv_mock_get_info_gate() {
        // Mock + capability `uv` ⇒ anunciado.
        let authenticator = authenticator_with_uv_mock(true, 5);
        let info = authenticator.get_info().unwrap();
        assert!(info.options.contains(&"uv".to_string()));

        // Capability `uv` sem mock ⇒ removido (padrão, sem hardware).
        let mut authenticator = create_authenticator();
        let mut caps = authenticator.capabilities().clone();
        caps.options.push("uv".to_string());
        authenticator.set_capabilities(caps);
        let info = authenticator.get_info().unwrap();
        assert!(!info.options.contains(&"uv".to_string()));

        // Padrão (sem mock, sem capability) ⇒ ausente.
        let authenticator = create_authenticator();
        let info = authenticator.get_info().unwrap();
        assert!(!info.options.contains(&"uv".to_string()));
    }

    #[test]
    fn test_builtin_uv_mock_default_none_preserves_errors() {
        let mut authenticator = create_authenticator();
        // getUVRetries sem mock ⇒ UnsupportedOption.
        let result = send(
            &mut authenticator,
            &ClientPinRequest {
                pin_protocol: Some(1),
                sub_command: ClientPinSubCommand::GetUVRetries as u8,
                ..Default::default()
            },
        );
        assert_eq!(result.unwrap_err(), Ctap2Error::UnsupportedOption);

        // 0x06 sem mock ⇒ UvBlocked, mesmo com a capability `uv` presente.
        let mut caps = authenticator.capabilities().clone();
        caps.options.push("uv".to_string());
        authenticator.set_capabilities(caps);
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        let result =
            platform.get_uv_token(&mut authenticator, PERMISSION_MC_GA, Some("example.com"));
        assert_eq!(result.unwrap_err(), Ctap2Error::UvBlocked);
    }

    #[test]
    fn test_uv_failure_decrements_retries() {
        let mut authenticator = authenticator_with_uv_mock(false, 5);
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        let result =
            platform.get_uv_token(&mut authenticator, PERMISSION_MC_GA, Some("example.com"));
        assert_eq!(result.unwrap_err(), Ctap2Error::UvBlocked);
        assert_eq!(authenticator.get_uv_retries(), 4);
        let response = send(
            &mut authenticator,
            &ClientPinRequest {
                pin_protocol: Some(2),
                sub_command: ClientPinSubCommand::GetUVRetries as u8,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(response.uv_retries, Some(4));
    }

    #[test]
    fn test_uv_success_resets_retries() {
        let mut authenticator = authenticator_with_uv_mock(true, 5);
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        platform
            .get_uv_token(&mut authenticator, PERMISSION_MC_GA, Some("example.com"))
            .unwrap();
        assert_eq!(authenticator.get_uv_retries(), UV_MAX_RETRIES);
    }

    #[test]
    fn test_uv_blocked_at_zero() {
        let mut authenticator = authenticator_with_uv_mock(true, 0);
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        let result =
            platform.get_uv_token(&mut authenticator, PERMISSION_MC_GA, Some("example.com"));
        assert_eq!(result.unwrap_err(), Ctap2Error::UvBlocked);
        assert_eq!(authenticator.get_uv_retries(), 0);
        let response = send(
            &mut authenticator,
            &ClientPinRequest {
                pin_protocol: Some(2),
                sub_command: ClientPinSubCommand::GetUVRetries as u8,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(response.uv_retries, Some(0));
    }

    #[test]
    fn test_uv_retries_persist_across_reboot() {
        let backend = SharedMemoryBackend::default();
        let storage = StorageEngine::with_backend(Box::new(backend.clone()));
        let crypto = CryptoEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        let mut caps = authenticator.capabilities().clone();
        if !caps.options.contains(&"uv".to_string()) {
            caps.options.push("uv".to_string());
        }
        authenticator.set_capabilities(caps);
        let _ = authenticator
            .get_storage_mut()
            .store(UV_RETRIES_KEY, 5u8.to_string().into_bytes());
        authenticator.set_user_verification(Some(Box::new(MockUserVerification {
            succeed: false,
            retries: 5,
        })));
        let (mut platform, _cose) = TestPlatform::start(&mut authenticator, 2);
        assert_eq!(
            platform
                .get_uv_token(&mut authenticator, PERMISSION_MC_GA, Some("example.com"))
                .unwrap_err(),
            Ctap2Error::UvBlocked
        );
        assert_eq!(authenticator.get_uv_retries(), 4);

        drop(platform);
        drop(authenticator);
        let storage = StorageEngine::with_backend(Box::new(backend));
        let crypto = CryptoEngine::new().unwrap();
        let mut rebooted = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        let mut caps = rebooted.capabilities().clone();
        if !caps.options.contains(&"uv".to_string()) {
            caps.options.push("uv".to_string());
        }
        rebooted.set_capabilities(caps);
        rebooted.set_user_verification(Some(Box::new(MockUserVerification {
            succeed: true,
            retries: 0,
        })));
        // Contador persistiu o reboot; o valor volátil do novo mock é ignorado.
        assert_eq!(rebooted.get_uv_retries(), 4);
        let (mut platform_after, _cose) = TestPlatform::start(&mut rebooted, 2);
        platform_after
            .get_uv_token(&mut rebooted, PERMISSION_MC_GA, Some("example.com"))
            .unwrap();
        assert_eq!(rebooted.get_uv_retries(), UV_MAX_RETRIES);
    }

    #[test]
    fn test_request_map_with_integer_keys() {
        let mut authenticator = create_authenticator();
        let value = Value::Map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(1)),
            ),
            (
                Value::Integer(Integer::from(2)),
                Value::Integer(Integer::from(1)),
            ),
        ]);
        let mut buf = Vec::new();
        into_writer(&value, &mut buf).unwrap();
        let response = handle_client_pin(&mut authenticator, &buf).unwrap();
        let decoded = decode_client_pin_response(&response).unwrap();
        assert_eq!(decoded.retries, Some(PIN_MAX_RETRIES));
    }

    #[test]
    fn test_request_map_with_string_keys() {
        let mut authenticator = create_authenticator();
        let value = Value::Map(vec![
            (
                Value::Text("pinProtocol".to_string()),
                Value::Integer(Integer::from(1)),
            ),
            (
                Value::Text("subCommand".to_string()),
                Value::Integer(Integer::from(1)),
            ),
        ]);
        let mut buf = Vec::new();
        into_writer(&value, &mut buf).unwrap();
        let response = handle_client_pin(&mut authenticator, &buf).unwrap();
        let decoded = decode_client_pin_response(&response).unwrap();
        assert_eq!(decoded.retries, Some(PIN_MAX_RETRIES));
    }

    #[test]
    fn test_decode_rejects_trailing_bytes() {
        let mut authenticator = create_authenticator();
        let request = ClientPinRequest {
            pin_protocol: Some(1),
            sub_command: ClientPinSubCommand::GetPINRetries as u8,
            ..Default::default()
        };
        let mut data = encode_client_pin_request_array(&request).unwrap();
        data.push(0x00);
        assert_eq!(
            handle_client_pin(&mut authenticator, &data).unwrap_err(),
            Ctap2Error::InvalidCbor
        );
    }

    #[test]
    fn test_unknown_subcommand_rejected() {
        let mut authenticator = create_authenticator();
        let result = send(
            &mut authenticator,
            &ClientPinRequest {
                pin_protocol: Some(1),
                sub_command: 0x7F,
                ..Default::default()
            },
        );
        assert_eq!(result.unwrap_err(), Ctap2Error::InvalidParameter);
    }

    #[test]
    fn test_padding_roundtrip() {
        let pin = b"5678";
        let padded = zero_pad_to_64(pin).unwrap();
        assert_eq!(padded.len(), 64);
        assert_eq!(strip_zero_padding(&padded).unwrap(), pin);
    }

    #[test]
    fn test_client_pin_response_default() {
        let response = ClientPinResponse::default();
        assert!(response.key_agreement.is_none());
        assert!(response.pin_uv_auth_token.is_none());
        assert!(response.retries.is_none());
        assert!(response.power_cycle_state.is_none());
        assert!(response.uv_retries.is_none());
    }
}
