use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use ciborium::de::from_reader;
use ciborium::ser::into_writer;
use ciborium::value::Integer;
use ciborium::Value;
use crypto::CryptoEngine;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use storage::{Credential, StorageEngine};

extern crate alloc;

use crate::attestation::{AttestationFormat, PackedAttestation, SelfAttestation};
use crate::client_pin;
use crate::cred_mgmt;
use crate::large_blobs;

/// Comando CTAP2 serializado para transporte.
///
/// `cmd` é o byte de comando (ver [`Ctap2Command`]) e `data` o payload
/// CBOR opcional.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtapCommand {
    /// Byte de comando CTAP2.
    pub cmd: u8,
    /// Payload CBOR serializado, se houver.
    #[serde(with = "serde_bytes")]
    pub data: Option<Vec<u8>>,
}

/// Resposta CTAP2 serializada para transporte.
///
/// Cada variante contém a response estruturada do comando correspondente.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CtapResponse {
    /// Resposta do comando MakeCredential.
    MakeCredential(MakeCredentialResponse),
    /// Resposta do comando GetAssertion.
    GetAssertion(GetAssertionResponse),
    /// Resposta do comando GetInfo.
    GetInfo(GetInfoResponse),
    /// Resposta do comando GetVersion.
    GetVersion(GetVersionResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MakeCredentialRequest {
    #[serde(with = "serde_bytes", rename = "clientDataHash")]
    pub client_data_hash: Vec<u8>,
    pub rp: RelyingParty,
    pub user: User,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PublicKeyCredParams>,
    #[serde(rename = "excludeList")]
    pub exclude_list: Vec<CredentialDescriptor>,
    pub extensions: Option<Extensions>,
    pub options: MakeCredentialOptions,
    #[serde(rename = "pinUvAuthProtocol")]
    pub pin_protocol: Option<u8>,
    #[serde(rename = "enterpriseAttestation")]
    pub enterprise_protections: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelyingParty {
    pub id: String,
    pub name: Option<String>,
    pub icon: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,
    pub name: Option<String>,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "icon")]
    pub icon_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredParams {
    pub r#type: String,
    #[serde(rename = "alg")]
    pub algorithms: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDescriptor {
    pub r#type: String,
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,
    pub transports: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Extensions {
    #[serde(rename = "credProtect")]
    pub cred_protect: Option<CredProtectPolicy>,
    #[serde(with = "serde_bytes", rename = "credBlob")]
    pub cred_blob: Option<Vec<u8>>,
    #[serde(rename = "minPinLength", default)]
    pub min_pin_length: bool,
    #[serde(rename = "hmac-secret")]
    pub hmac_secret: Option<HmacSecretInput>,
    #[serde(rename = "largeBlobKey", default)]
    pub large_blob_key: bool,
}

impl Extensions {
    pub fn has_any(&self) -> bool {
        self.cred_protect.is_some()
            || self.cred_blob.is_some()
            || self.min_pin_length
            || self.hmac_secret.is_some()
            || self.large_blob_key
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Input da extensão `hmac-secret` para derivação de segredo compartilhado.
pub struct HmacSecretInput {
    /// Salt cifrado com keyAgreement (ChaCha20-Poly1305).
    #[serde(with = "serde_bytes", rename = "saltEnc")]
    pub salt_enc: Vec<u8>,
    /// Versão do protocolo PIN/UV auth utilizada.
    #[serde(rename = "pinUvAuthProtocol")]
    pub pin_uv_auth_protocol: Option<u8>,
}

/// Opções do comando MakeCredential (mapa `options` do CTAP2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MakeCredentialOptions {
    /// Resident key — credencial armazenada no autenticador.
    #[serde(default)]
    pub rk: bool,
    /// User verification — exigir PIN/biometria.
    #[serde(default)]
    pub uv: bool,
    /// User presence — exigir toque físico.
    #[serde(default)]
    pub up: bool,
    /// Estendido — inclui dados adicionais no authData.
    #[serde(rename = "att", default)]
    pub extended: bool,
}

/// Resposta do comando MakeCredential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MakeCredentialResponse {
    /// Formato de attestation (e.g. `"none"`, `"packed"`).
    pub fmt: String,
    /// Authenticator Data CBOR serializado.
    #[serde(with = "serde_bytes", rename = "authData")]
    pub auth_data: Vec<u8>,
    /// Mapa CBOR de attestation statement (`{alg, sig, x5c}` ou `{alg, sig}`).
    #[serde(rename = "attStmt")]
    pub attestation_info: BTreeMap<i64, Value>,
    /// Saídas das extensões ativas, se houver.
    #[serde(rename = "extensions", skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ExtensionOutputs>,
}

/// Saídas das extensões WebAuthn incluídas na resposta CTAP2.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExtensionOutputs {
    /// Política de proteção da credencial (extensão `credProtect`).
    #[serde(rename = "credProtect", skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<u8>,
    /// Comprimento mínimo de PIN aceito (extensão `minPinLength`).
    #[serde(rename = "minPinLength", skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<u32>,
    /// Blob customizado da credencial (extensão `credBlob`).
    #[serde(
        with = "serde_bytes",
        rename = "credBlob",
        skip_serializing_if = "Option::is_none"
    )]
    pub cred_blob: Option<Vec<u8>>,
    /// Segredo HMAC compartilhado (extensão `hmac-secret`).
    #[serde(
        with = "serde_bytes",
        rename = "hmac-secret",
        skip_serializing_if = "Option::is_none"
    )]
    pub hmac_secret: Option<Vec<u8>>,
    /// Chave simétrica associada à credencial (extensão `largeBlobKey`).
    #[serde(
        with = "serde_bytes",
        rename = "largeBlobKey",
        skip_serializing_if = "Option::is_none"
    )]
    pub large_blob_key: Option<Vec<u8>>,
}

/// Dados de credencial retornados em respostas CTAP2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialData {
    /// AAGUID do autenticador.
    #[serde(with = "serde_bytes")]
    pub aaguid: Vec<u8>,
    /// Identificador opaco da credencial.
    #[serde(with = "serde_bytes")]
    pub credential_id: Vec<u8>,
    /// Tipo da credencial (e.g. `"public-key"`).
    pub credential_type: String,
    /// Chave pública no formato COSE.
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    /// Contador de assinaturas.
    pub sign_count: u32,
}

/// Requisição do comando GetAssertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAssertionRequest {
    /// Identificador do relying party.
    #[serde(rename = "rpId")]
    pub rp_id: String,
    /// Lista de credenciais permitidas (resident keys), no campo CTAP `allowList`.
    #[serde(rename = "allowList")]
    pub credentials: Vec<CredentialDescriptor>,
    /// Alias interno legado; não é serializado no wire format.
    #[serde(skip)]
    pub allow_list: Option<Vec<CredentialDescriptor>>,
    /// Hash dos clientData JSON.
    #[serde(with = "serde_bytes", rename = "clientDataHash")]
    pub client_data_hash: Vec<u8>,
    /// Extensões WebAuthn ativas.
    pub extensions: Option<Extensions>,
    /// Opções do comando.
    pub options: GetAssertionOptions,
    /// Versão do protocolo PIN/UV auth.
    #[serde(rename = "pinUvAuthProtocol")]
    pub pin_protocol: Option<u8>,
    /// Indica se user verification foi realizada.
    pub uv: Option<bool>,
}

/// Opções do comando GetAssertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAssertionOptions {
    /// User presence — exigir toque físico.
    pub up: bool,
    /// User verification — exigir PIN/biometria.
    pub uv: bool,
}

/// Resposta do comando GetAssertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAssertionResponse {
    /// Credencial utilizada na assertion.
    #[serde(rename = "credential")]
    pub credential: Option<CredentialDescriptor>,
    /// Authenticator Data CBOR serializado.
    #[serde(with = "serde_bytes", rename = "authData")]
    pub auth_data: Vec<u8>,
    /// Assinatura sobre `authData || clientDataHash`.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// Dados do usuário (quando credencial é discoverable).
    pub user: Option<User>,
    /// Total de credenciais encontradas (multi-assertion).
    #[serde(rename = "numberOfCredentials")]
    pub number_of_credentials: Option<u16>,
    /// Indica se há mais credenciais (GetNextAssertion).
    pub next: Option<bool>,
    /// Saídas das extensões ativas, se houver.
    #[serde(rename = "extensions", skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ExtensionOutputs>,
}

/// Resposta do comando GetInfo — capacidades do autenticador.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetInfoResponse {
    /// Versões CTAP suportadas (e.g. `"FIDO_2_0"`, `"FIDO_2_1"`).
    pub versions: Vec<String>,
    /// Extensões WebAuthn suportadas.
    pub extensions: Vec<String>,
    /// AAGUID do dispositivo.
    #[serde(with = "serde_bytes")]
    pub aaguid: Vec<u8>,
    /// Opções habilitadas (e.g. `"rk"`, `"uv"`, `"up"`).
    pub options: Vec<String>,
    /// Número de relying parties com credenciais armazenadas.
    pub rp_count: u32,
    /// Comprimento máximo de credBlob em bytes.
    pub max_cred_blob_length: u32,
    /// Comprimento máximo de credential ID em bytes.
    pub max_credential_id_length: u16,
    /// Número máximo de credenciais residentes.
    pub max_credential_count: u16,
    /// Versão do firmware.
    pub firmware_version: String,
    /// Algoritmos COSE suportados.
    pub algorithms: Vec<CoseAlgorithmEntry>,
    /// Recursos de segurança do silício, se houver.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<SecurityFeatures>,
    /// Tamanho máximo suportado para large blobs em bytes (CTAP 2.1 §6.4).
    #[serde(
        rename = "maxLargeBlobDataSize",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_large_blob_data_size: Option<u32>,
}

/// Entrada de algoritmo COSE para resposta GetInfo (CTAP2 §6.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoseAlgorithmEntry {
    /// Identificador numérico do algoritmo (e.g. `-8` EdDSA, `-7` ES256, `-257` RS256).
    pub alg: i32,
    /// Tipo de chave (e.g. `"public-key"`).
    #[serde(rename = "type")]
    pub key_type: String,
}

/// Resposta do comando GetVersion — metadados do firmware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetVersionResponse {
    /// Versão do firmware (ex. `"0.1.0"`).
    pub firmware_version: String,
    /// Hash do commit git.
    pub firmware_commit_id: String,
    /// Timestamp ou identificador do build.
    pub firmware_build_id: String,
}

/// Requisição do comando BioEnroll (gerenciamento de biometria).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BioEnrollRequest {
    /// Sub-comando (0x01 enroll, 0x03 get characteristics).
    #[serde(rename = "subCommand")]
    pub sub_command: u8,
    /// Parâmetros opcionais do sub-comando.
    #[serde(rename = "subCommandParams")]
    pub sub_command_params: Option<BTreeMap<String, Value>>,
}

/// Resposta do comando BioEnroll.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BioEnrollResponse {
    /// Tipo de biometria (0 = fingerprint).
    #[serde(rename = "fingerprintKind")]
    pub fingerprint_kind: u8,
    /// Número máximo de enrollments permitidos.
    #[serde(rename = "maxEnrollments")]
    pub max_enrollments: u8,
}

/// Resposta dos comandos EnumerateRPs (initial/next).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumerateRPsResponse {
    /// Dados do relying party.
    pub rp: RelyingParty,
    /// SHA-256 do `rpId`.
    #[serde(with = "serde_bytes", rename = "rpHash")]
    pub rp_hash: Vec<u8>,
    /// Total de RPs com credenciais armazenadas.
    #[serde(rename = "totalRPs")]
    pub total_rps: u8,
}

/// Comandos CTAP2 reconhecidos pelo autenticador.
///
/// Cada variante corresponde ao byte de comando definido na especificação
/// CTAP2 (§6). Comandos desconhecidos são capturados por [`Ctap2Command::Unknown`].
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ctap2Command {
    /// MakeCredential (0x01) — cria uma nova credencial.
    MakeCredential = 0x01,
    /// GetAssertion (0x02) — produz uma assinatura para autenticação.
    GetAssertion = 0x02,
    /// GetInfo (0x04) — retorna capacidades do autenticador.
    GetInfo = 0x04,
    /// ClientPIN (0x06) — gerencia PIN e pinUvAuthToken.
    ClientPIN = 0x06,
    /// Reset (0x07) — limpa todas as credenciais e estado.
    Reset = 0x07,
    /// GetNextAssertion (0x08) — retorna próxima credencial em multi-assertion.
    GetNextAssertion = 0x08,
    /// BioEnroll (0x09) — gerenciamento de biometria (stub).
    BioEnroll = 0x09,
    /// CredentialManagement (0x0A) — gerenciamento de credenciais residentes.
    CredentialManagement = 0x0A,
    /// Selection (0x0B) — seleciona dispositivo via toque.
    Selection = 0x0B,
    /// LargeBlobs (0x0C) — leitura e escrita de large blobs no autenticador.
    LargeBlobs = 0x0C,
    /// GetVersion (0x0F) — retorna versões de firmware/hardware.
    GetVersion = 0x0F,
    /// EnumerateRPsInitial (0x3B) — inicia enumeração de relying parties.
    EnumerateRPsInitial = 0x3B,
    /// EnumerateRPsNext (0x3C) — continua enumeração de relying parties.
    EnumerateRPsNext = 0x3C,
    /// Comando não reconhecido — contém o byte original.
    Unknown(u8),
}

impl Ctap2Command {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x01 => Ctap2Command::MakeCredential,
            0x02 => Ctap2Command::GetAssertion,
            0x04 => Ctap2Command::GetInfo,
            0x06 => Ctap2Command::ClientPIN,
            0x07 => Ctap2Command::Reset,
            0x08 => Ctap2Command::GetNextAssertion,
            0x09 => Ctap2Command::BioEnroll,
            0x0A => Ctap2Command::CredentialManagement,
            0x0B => Ctap2Command::Selection,
            0x0C => Ctap2Command::LargeBlobs,
            0x0F => Ctap2Command::GetVersion,
            0x3B => Ctap2Command::EnumerateRPsInitial,
            0x3C => Ctap2Command::EnumerateRPsNext,
            _ => Ctap2Command::Unknown(value),
        }
    }
}

/// Códigos de erro CTAP2 (CTAP2 §6.3).
///
/// Cada variante mapeia para o byte de status definido na especificação.
/// Erros de camadas inferiores são convertidos para `Ctap2Error` nas
/// fronteiras do protocolo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ctap2Error {
    /// Operação concluída com sucesso.
    Success = 0x00,
    /// Comando desconhecido ou não suportado.
    InvalidCommand = 0x01,
    /// Parâmetro obrigatório ausente ou inválido.
    InvalidParameter = 0x02,
    /// Comprimento do payload incorreto.
    InvalidLength = 0x03,
    /// Dados malformados ou inválidos.
    InvalidData = 0x04,
    /// Payload CBOR malformado.
    InvalidCbor = 0x12,
    /// Comando inválido no estado atual.
    InvalidState = 0x05,
    /// Opção não suportada.
    InvalidOption = 0x2C,
    /// Timeout na operação.
    Timeout = 0x3A,
    /// Recurso ocupado — outro comando está em execução.
    ResourceBusy = 0x24,
    /// Credencial já existe no exclude_list.
    CredentialExists = 0x19,
    /// Comando recebido, processamento iniciado.
    Processing = 0x21,
    /// Algoritmo criptográfico não suportado.
    UnsupportedAlgorithm = 0x26,
    /// Opção do comando não suportada.
    UnsupportedOption = 0x2B,
    /// Operação negada pelo usuário (ex.: toque físico não detectado).
    OperationDenied = 0x27,
    /// Chave inválida fornecida.
    InvalidKey = 0x22,
    /// Nenhuma credencial correspondente encontrada.
    NoCredentials = 0x2E,
    /// PIN incorreto.
    PinInvalid = 0x31,
    /// PIN incorreto com contador de tentativas decrementado.
    PinInvalidRetries = 0x32,
    /// PIN necessário para continuar.
    PinRequired = 0x35,
    /// PIN viola política de segurança.
    PinPolicyViolation = 0x37,
    /// Token de autenticação PIN/UV necessário.
    PinTokenRequired = 0x36,
    /// Token de autenticação expirado.
    PinTokenExpired = 0x38,
    /// Token pendente de aprovação do usuário.
    PinTokenPending = 0x23,

    /// Request excede o tamanho máximo permitido.
    RequestTooLarge = 0x39,
    /// Array de large blobs está cheio ou excede o limite máximo.
    LargeBlobStorageFull = 0x18,
    /// Erro não categorizado.
    Unknown = 0x7F,
}

impl Ctap2Error {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl core::fmt::Display for Ctap2Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CTAP2 error 0x{:02X}", self.as_u8())
    }
}

impl std::error::Error for Ctap2Error {}

/// Credential protection policy (CTAP2 `credProtect` extension).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum CredProtectPolicy {
    #[default]
    UserVerificationOptional = 0x01,
    UserVerificationOptionalWithCredentialIDList = 0x02,
    UserVerificationRequired = 0x03,
}

impl From<u8> for CredProtectPolicy {
    fn from(value: u8) -> Self {
        match value {
            0x02 => CredProtectPolicy::UserVerificationOptionalWithCredentialIDList,
            0x03 => CredProtectPolicy::UserVerificationRequired,
            _ => CredProtectPolicy::UserVerificationOptional,
        }
    }
}

impl From<CredProtectPolicy> for u8 {
    fn from(val: CredProtectPolicy) -> Self {
        val as u8
    }
}

/// Maps a boxed error back to a CTAP2 status code.
fn ctap2_error(error: Box<dyn std::error::Error>) -> Ctap2Error {
    error
        .downcast_ref::<Ctap2Error>()
        .copied()
        .unwrap_or(Ctap2Error::InvalidData)
}

pub const AAGUID: [u8; 16] = [0u8; 16];

fn hash_rp_id(rp_id: &str, crypto: &CryptoEngine) -> [u8; 32] {
    let result = crypto.sha256(rp_id.as_bytes());
    let mut rp_hash = [0u8; 32];
    rp_hash.copy_from_slice(&result);
    rp_hash
}

/// Converts the top-level CTAP map from serde's text field names to the
/// integer labels required by the CTAP 2.1 wire format. Nested maps are left
/// untouched because RP/user/options/extension maps use text labels.
fn ctap_key_to_int(key: &str) -> Option<i64> {
    Some(match key {
        "clientDataHash" => 0x01,
        "rp" => 0x02,
        "user" => 0x03,
        "pubKeyCredParams" => 0x04,
        "excludeList" => 0x05,
        "extensions" => 0x06,
        "options" => 0x07,
        "pinUvAuthParam" => 0x08,
        "pinUvAuthProtocol" => 0x09,
        "enterpriseAttestation" => 0x0A,
        "rpId" => 0x01,
        "allowList" => 0x03,
        "credential" => 0x01,
        "authData" => 0x02,
        "signature" => 0x03,

        "numberOfCredentials" => 0x05,
        "versions" => 0x01,
        "aaguid" => 0x03,
        "maxMsgSize" => 0x05,
        "pinUvAuthProtocols" => 0x06,
        "algorithms" => 0x0A,
        "fmt" => 0x01,
        "attStmt" => 0x03,
        "subCommand" => 0x01,
        "pinProtocol" => 0x02,
        "keyAgreement" => 0x03,
        "pinAuth" => 0x04,
        "newPinEnc" => 0x05,
        "pinHashEnc" => 0x06,
        "subCommandParams" => 0x03,
        "r#type" => 0x01,
        "id" => 0x02,
        "type" => 0x01,
        "alg" => 0x03,
        _ => return None,
    })
}

fn root_ctap_keys(value: Value, encode: bool, type_name: &str) -> Value {
    let Value::Map(entries) = value else {
        return value;
    };
    let converted = entries
        .into_iter()
        .map(|(key, val)| {
            if encode {
                if let Value::Text(name) = key {
                    // The same field name can have different labels in different
                    // command maps; use the command's top-level schema first.
                    let label = match type_name {
                        t if t.contains("GetAssertionRequest") && name == "rpId" => Some(0x01),
                        t if t.contains("GetAssertionRequest") && name == "clientDataHash" => {
                            Some(0x02)
                        }
                        t if t.contains("GetAssertionRequest") && name == "allowList" => Some(0x03),
                        t if t.contains("GetAssertionRequest") && name == "extensions" => {
                            Some(0x04)
                        }
                        t if t.contains("GetAssertionRequest") && name == "options" => Some(0x05),
                        t if t.contains("GetAssertionRequest") && name == "pinUvAuthParam" => {
                            Some(0x06)
                        }
                        t if t.contains("GetAssertionRequest") && name == "pinUvAuthProtocol" => {
                            Some(0x07)
                        }
                        t if t.contains("GetAssertionResponse") && name == "credential" => {
                            Some(0x01)
                        }
                        t if t.contains("GetAssertionResponse") && name == "auth_data" => {
                            Some(0x02)
                        }
                        t if t.contains("GetAssertionResponse") && name == "signature" => {
                            Some(0x03)
                        }
                        t if t.contains("GetAssertionResponse") && name == "user" => Some(0x04),
                        t if t.contains("MakeCredentialResponse") && name == "fmt" => Some(0x01),
                        t if t.contains("MakeCredentialResponse") && name == "auth_data" => {
                            Some(0x02)
                        }
                        t if t.contains("MakeCredentialResponse") && name == "attestation_info" => {
                            Some(0x03)
                        }
                        t if t.contains("GetInfoResponse") && name == "versions" => Some(0x01),
                        t if t.contains("GetInfoResponse") && name == "extensions" => Some(0x02),
                        t if t.contains("GetInfoResponse") && name == "aaguid" => Some(0x03),
                        t if t.contains("GetInfoResponse") && name == "options" => Some(0x04),
                        t if t.contains("GetInfoResponse")
                            && name == "max_large_blob_data_size" =>
                        {
                            Some(0x0D)
                        }
                        t if t.contains("EnumerateRPsResponse") && name == "rp" => Some(0x01),
                        t if t.contains("EnumerateRPsResponse") && name == "rpHash" => Some(0x02),
                        t if t.contains("EnumerateRPsResponse") && name == "totalRPs" => Some(0x03),
                        t if t.contains("BioEnrollRequest") && name == "subCommand" => Some(0x02),
                        t if t.contains("BioEnrollRequest") && name == "subCommandParams" => {
                            Some(0x03)
                        }
                        t if t.contains("BioEnrollResponse") && name == "fingerprintKind" => {
                            Some(0x02)
                        }
                        t if t.contains("BioEnrollResponse") && name == "maxEnrollments" => {
                            Some(0x03)
                        }
                        t if t.contains("CredentialManagementRequest") && name == "subCommand" => {
                            Some(0x01)
                        }
                        t if t.contains("CredentialManagementRequest")
                            && name == "subCommandParams" =>
                        {
                            Some(0x02)
                        }
                        t if t.contains("CredentialManagementRequest")
                            && name == "pinUvAuthProtocol" =>
                        {
                            Some(0x03)
                        }
                        t if t.contains("CredentialManagementRequest")
                            && name == "pinUvAuthParam" =>
                        {
                            Some(0x04)
                        }
                        t if t.contains("CredsMetadataResponse")
                            && name == "existingResidentCredentialsCount" =>
                        {
                            Some(0x01)
                        }
                        t if t.contains("CredsMetadataResponse")
                            && name == "maxPossibleRemainingResidentCredentialsCount" =>
                        {
                            Some(0x02)
                        }
                        t if t.contains("EnumerateRpsEntryResponse") && name == "rp" => Some(0x01),
                        t if t.contains("EnumerateRpsEntryResponse") && name == "rpIDHash" => {
                            Some(0x02)
                        }
                        t if t.contains("EnumerateRpsEntryResponse") && name == "totalRPs" => {
                            Some(0x03)
                        }
                        t if t.contains("EnumerateCredentialsEntryResponse") && name == "user" => {
                            Some(0x01)
                        }
                        t if t.contains("EnumerateCredentialsEntryResponse")
                            && name == "credentialId" =>
                        {
                            Some(0x02)
                        }
                        t if t.contains("EnumerateCredentialsEntryResponse")
                            && name == "publicKey" =>
                        {
                            Some(0x03)
                        }
                        t if t.contains("EnumerateCredentialsEntryResponse")
                            && name == "credProtect" =>
                        {
                            Some(0x04)
                        }
                        t if t.contains("EnumerateCredentialsEntryResponse")
                            && name == "largeBlobKey" =>
                        {
                            Some(0x05)
                        }
                        t if t.contains("EnumerateCredentialsEntryResponse")
                            && name == "totalCredentials" =>
                        {
                            Some(0x06)
                        }
                        _ => ctap_key_to_int(&name),
                    };
                    label
                        .map(|n| (Value::Integer(n.into()), val.clone()))
                        .unwrap_or((Value::Text(name), val))
                } else {
                    (key, val)
                }
            } else if let Value::Integer(n) = key {
                let label = i64::try_from(n)
                    .ok()
                    .and_then(|n| match type_name {
                        t if t.contains("MakeCredentialRequest") => [
                            "",
                            "clientDataHash",
                            "rp",
                            "user",
                            "pubKeyCredParams",
                            "excludeList",
                            "extensions",
                            "options",
                            "pinUvAuthParam",
                            "pinUvAuthProtocol",
                            "enterpriseAttestation",
                        ]
                        .get(n as usize)
                        .copied(),
                        t if t.contains("GetAssertionRequest") => [
                            "",
                            "rpId",
                            "clientDataHash",
                            "allowList",
                            "extensions",
                            "options",
                            "pinUvAuthParam",
                            "pinUvAuthProtocol",
                        ]
                        .get(n as usize)
                        .copied(),
                        t if t.contains("MakeCredentialResponse") => {
                            ["", "fmt", "authData", "attStmt", "extensions"]
                                .get(n as usize)
                                .copied()
                        }
                        t if t.contains("GetAssertionResponse") => [
                            "",
                            "credential",
                            "authData",
                            "signature",
                            "user",
                            "numberOfCredentials",
                            "extensions",
                        ]
                        .get(n as usize)
                        .copied(),
                        t if t.contains("GetInfoResponse") => [
                            "",
                            "versions",
                            "extensions",
                            "aaguid",
                            "options",
                            "maxMsgSize",
                            "pinUvAuthProtocols",
                            "",
                            "",
                            "",
                            "algorithms",
                        ]
                        .get(n as usize)
                        .copied(),
                        t if t.contains("EnumerateRPsResponse") => {
                            ["", "rp", "rpHash", "totalRPs"].get(n as usize).copied()
                        }
                        t if t.contains("BioEnrollRequest") => {
                            ["", "", "subCommand", "subCommandParams"]
                                .get(n as usize)
                                .copied()
                        }
                        t if t.contains("BioEnrollResponse") => {
                            ["", "", "fingerprintKind", "maxEnrollments"]
                                .get(n as usize)
                                .copied()
                        }
                        t if t.contains("CredentialManagementRequest") => [
                            "",
                            "subCommand",
                            "subCommandParams",
                            "pinUvAuthProtocol",
                            "pinUvAuthParam",
                        ]
                        .get(n as usize)
                        .copied(),
                        t if t.contains("CredsMetadataResponse") => [
                            "",
                            "existingResidentCredentialsCount",
                            "maxPossibleRemainingResidentCredentialsCount",
                        ]
                        .get(n as usize)
                        .copied(),
                        t if t.contains("EnumerateRpsEntryResponse") => {
                            ["", "rp", "rpIDHash", "totalRPs"].get(n as usize).copied()
                        }
                        t if t.contains("EnumerateCredentialsEntryResponse") => [
                            "",
                            "user",
                            "credentialId",
                            "publicKey",
                            "credProtect",
                            "largeBlobKey",
                            "totalCredentials",
                        ]
                        .get(n as usize)
                        .copied(),
                        _ => None,
                    })
                    .filter(|s| !s.is_empty());
                label
                    .map(|s| (Value::Text(s.into()), val.clone()))
                    .unwrap_or((Value::Integer(n), val))
            } else {
                (key, val)
            }
        })
        .collect();
    Value::Map(converted)
}

pub fn encode_cbor<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Ctap2Error> {
    let mut raw = Vec::new();
    ciborium::ser::into_writer(value, &mut raw).map_err(|_| Ctap2Error::InvalidData)?;
    let parsed: Value = from_reader(raw.as_slice()).map_err(|_| Ctap2Error::InvalidData)?;
    let normalized = root_ctap_keys(parsed, true, core::any::type_name::<T>());
    let mut buf = alloc::vec![];
    into_writer(&normalized, &mut buf).map_err(|_| Ctap2Error::InvalidData)?;
    Ok(buf)
}

pub fn decode_cbor<T: DeserializeOwned>(data: &[u8]) -> Result<T, Ctap2Error> {
    let parsed: Value = from_reader(data).map_err(|_| Ctap2Error::InvalidCbor)?;
    let normalized = root_ctap_keys(parsed, false, core::any::type_name::<T>());
    let mut buf = alloc::vec![];
    into_writer(&normalized, &mut buf).map_err(|_| Ctap2Error::InvalidCbor)?;
    from_reader(buf.as_slice()).map_err(|_| Ctap2Error::InvalidCbor)
}

pub trait DeserializeOwned: for<'de> Deserialize<'de> {}
impl<T: for<'de> Deserialize<'de>> DeserializeOwned for T {}

/// Capabilities reported by CTAP2 GetInfo, derived from the device profile.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SecurityFeatures {
    pub secure_boot: bool,
    pub trust_zone: bool,
    pub hardware_rng: bool,
    pub sha256_accelerator: bool,
    pub debug_disable: bool,
    pub otp_memory: bool,
    pub unique_id: bool,
    pub tamper_detection: bool,
}

impl SecurityFeatures {
    pub fn has_any_features(&self) -> bool {
        self.secure_boot
            || self.trust_zone
            || self.hardware_rng
            || self.sha256_accelerator
            || self.debug_disable
            || self.otp_memory
            || self.unique_id
            || self.tamper_detection
    }
}

/// Capabilities reported by CTAP2 GetInfo, derived from the device profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ctap2Capabilities {
    pub aaguid: [u8; 16],
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub options: Vec<String>,
    pub rp_count: u32,
    pub max_cred_blob_length: u32,
    pub max_credential_id_length: u16,
    pub max_credential_count: u16,
    pub firmware_version: String,
    pub min_pin_length: Option<u32>,
    pub security: SecurityFeatures,
    pub max_large_blob_data_size: Option<u32>,
}

impl Default for Ctap2Capabilities {
    fn default() -> Self {
        Self {
            aaguid: AAGUID,
            versions: vec!["2.0".to_string(), "2.1".to_string()],
            extensions: vec![
                "credProtect".to_string(),
                "credBlob".to_string(),
                "minPinLength".to_string(),
                "hmac-secret".to_string(),
                "largeBlobKey".to_string(),
            ],
            options: vec![
                "rk".to_string(),
                "up".to_string(),
                "largeBlobs".to_string(),
                "credMgmt".to_string(),
                "ep".to_string(),
            ],
            rp_count: 0,
            max_cred_blob_length: 32,
            max_credential_id_length: 64,
            max_credential_count: 10,
            firmware_version: "0.1.0".to_string(),
            min_pin_length: Some(4),
            security: SecurityFeatures::default(),
            max_large_blob_data_size: Some(4096),
        }
    }
}

/// Parameters for building authenticator data (authData).
struct AuthDataParams<'a> {
    rp_id_hash: [u8; 32],
    sign_count: u32,
    flags: u8,
    include_credential_data: bool,
    credential_id: &'a [u8],
    public_key: &'a [u8],
    algorithm: i32,
}

/// Sinal de user presence fornecido pela camada de hardware.
///
/// Implementado pelo board e injetado no [`Ctap2Authenticator`] para aplicar o
/// check de `up` (toque físico) em MakeCredential/GetAssertion.
pub trait UserPresence: core::fmt::Debug + Send + Sync {
    /// Retorna `true` se o usuário está presente (ex.: botão pressionado).
    fn is_present(&mut self) -> bool;
}

#[derive(Debug)]
pub struct Ctap2Authenticator {
    crypto: CryptoEngine,
    storage: StorageEngine,
    capabilities: Ctap2Capabilities,
    attestation_format: AttestationFormat,
    attestation_cert: Option<crate::attestation::AttestationCertificate>,
    enterprise_rp_list: Vec<String>,
    enumerate_rps_state: Option<EnumerateRPsState>,
    cred_mgmt_rps_state: Option<EnumerateRpsCredMgmtState>,
    cred_mgmt_creds_state: Option<EnumerateCredentialsState>,
    get_next_assertion_state: Option<GetNextAssertionState>,
    user_presence: Option<Box<dyn UserPresence>>,
}

#[derive(Debug)]
struct EnumerateRPsState {
    rps: Vec<(String, Vec<u8>)>,
    total: usize,
    current_index: usize,
}

#[derive(Debug)]
struct EnumerateRpsCredMgmtState {
    rps: Vec<(String, Vec<u8>)>,
    total: usize,
    current_index: usize,
}

#[derive(Debug)]
struct EnumerateCredentialsState {
    creds: Vec<Credential>,
    total: usize,
    current_index: usize,
}

#[derive(Debug)]
struct GetNextAssertionState {
    rp_id: String,
    #[allow(dead_code)]
    client_data_hash: Vec<u8>,
    allow_list: Vec<CredentialDescriptor>,
    #[allow(dead_code)]
    extensions: Option<Extensions>,
    #[allow(dead_code)]
    options: GetAssertionOptions,
    #[allow(dead_code)]
    pin_protocol: Option<u8>,
    current_index: usize,
}

impl Ctap2Authenticator {
    pub fn new(
        aaguid: [u8; 16],
        crypto: CryptoEngine,
        storage: StorageEngine,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let capabilities = Ctap2Capabilities {
            aaguid,
            ..Default::default()
        };
        info!("CTAP2 authenticator initialized");
        Ok(Self {
            crypto,
            storage,
            capabilities,
            attestation_format: AttestationFormat::None,
            attestation_cert: None,
            enterprise_rp_list: Vec::new(),
            enumerate_rps_state: None,
            cred_mgmt_rps_state: None,
            cred_mgmt_creds_state: None,
            get_next_assertion_state: None,
            user_presence: None,
        })
    }

    pub fn get_aaguid(&self) -> &[u8; 16] {
        &self.capabilities.aaguid
    }

    pub fn set_capabilities(&mut self, capabilities: Ctap2Capabilities) {
        self.capabilities = capabilities;
    }

    pub fn capabilities(&self) -> &Ctap2Capabilities {
        &self.capabilities
    }

    pub fn set_attestation_format(&mut self, format: AttestationFormat) {
        self.attestation_format = format;
    }

    pub fn set_attestation_certificate(
        &mut self,
        cert: crate::attestation::AttestationCertificate,
    ) {
        self.attestation_cert = Some(cert);
    }

    /// Define a fonte de user presence usada no check de `up`.
    ///
    /// Quando `None` (padrão), o check é considerado satisfeito — comportamento
    /// usado em simulação e testes sem botão físico.
    pub fn set_user_presence(&mut self, presence: Option<Box<dyn UserPresence>>) {
        self.user_presence = presence;
    }

    /// Define a lista de RP IDs autorizados para Enterprise Attestation.
    pub fn set_enterprise_rp_list(&mut self, rps: Vec<String>) {
        self.enterprise_rp_list = rps;
    }

    pub fn get_crypto(&self) -> &CryptoEngine {
        &self.crypto
    }

    pub fn get_storage(&self) -> &StorageEngine {
        &self.storage
    }

    pub fn get_storage_mut(&mut self) -> &mut StorageEngine {
        &mut self.storage
    }

    pub fn make_credential(
        &mut self,
        request: MakeCredentialRequest,
    ) -> Result<MakeCredentialResponse, Box<dyn std::error::Error>> {
        debug!("Processing MakeCredential request");

        if request.options.up {
            if let Some(presence) = self.user_presence.as_mut() {
                if !presence.is_present() {
                    return Err(Box::new(Ctap2Error::OperationDenied));
                }
            }
        }

        let rp_id_hash = hash_rp_id(&request.rp.id, &self.crypto);

        let selected_alg = if request.pub_key_cred_params.is_empty() {
            -8 // default to EdDSA
        } else {
            request
                .pub_key_cred_params
                .iter()
                .find_map(|param| match param.algorithms {
                    -7 => Some(-7),
                    -8 => Some(-8),
                    -35 => Some(-35),
                    -37 => Some(-37),
                    -257 => Some(-257),
                    _ => None,
                })
                .ok_or(Ctap2Error::UnsupportedAlgorithm)?
        };

        for descriptor in &request.exclude_list {
            if let Some(credential) = self.storage.get_credential(&descriptor.id, &self.crypto)? {
                if credential.rp_id_hash == rp_id_hash.to_vec() {
                    return Err(Box::new(Ctap2Error::CredentialExists));
                }
            }
        }

        let cred_blob = if let Some(ref ext) = request.extensions {
            if let Some(ref blob) = ext.cred_blob {
                if blob.len() > 32 {
                    return Err(Box::new(Ctap2Error::InvalidParameter));
                }
                blob.clone()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        let cred_protect_policy = request
            .extensions
            .as_ref()
            .and_then(|ext| ext.cred_protect)
            .unwrap_or_default();

        let credential_id = self.generate_credential_id();
        let (private_key, public_key) = match selected_alg {
            -7 => self.crypto.generate_p256_key_pair()?,
            -35 => self.crypto.generate_p384_key_pair()?,
            -37 | -257 => {
                // RSA: keep the PKCS#1 DER public key so both the COSE key and
                // signature verification can be derived from it.
                let (pkcs8, n, e) = self.crypto.generate_rsa_key_pair()?;
                let public_key = CryptoEngine::rsa_public_key_der(&n, &e)?;
                (pkcs8, public_key)
            }
            _ => self.crypto.generate_key_pair()?,
        };

        // Generate largeBlobKey if the extension was requested.
        let large_blob_key = if request
            .extensions
            .as_ref()
            .map(|e| e.large_blob_key)
            .unwrap_or(false)
        {
            Some(self.crypto.random_bytes(32))
        } else {
            None
        };

        let credential = Credential {
            credential_id: credential_id.clone(),
            public_key: public_key.clone(),
            private_key: private_key.clone(),
            sign_count: 0,
            rp_id_hash: rp_id_hash.to_vec(),
            user_handle: Some(request.user.id.clone()),
            cred_blob: cred_blob.clone(),
            created_at: 0,
            algorithm: selected_alg,
            rp_id: request.rp.id.clone(),
            large_blob_key: large_blob_key.clone(),
            user_name: request.user.name.clone(),
            user_display_name: request.user.display_name.clone(),
        };

        self.storage.store_credential(credential, &self.crypto)?;

        let mut flags: u8 = 0x40; // AT
        if request.options.up {
            flags |= 0x01;
        }
        if request.options.uv {
            flags |= 0x04;
        }

        if cred_protect_policy == CredProtectPolicy::UserVerificationRequired {
            flags |= 0x04;
        }

        let auth_data = self.build_auth_data(&AuthDataParams {
            rp_id_hash,
            sign_count: 0,
            flags,
            include_credential_data: true,
            credential_id: &credential_id,
            public_key: &public_key,
            algorithm: selected_alg,
        })?;

        let mut ext_outputs = ExtensionOutputs::default();
        let has_ext = request
            .extensions
            .as_ref()
            .map(|e| e.has_any())
            .unwrap_or(false);
        if has_ext {
            if request.extensions.as_ref().unwrap().min_pin_length {
                ext_outputs.min_pin_length = Some(self.capabilities.min_pin_length.unwrap_or(4));
            }
            if request.extensions.as_ref().unwrap().cred_protect.is_some() {
                ext_outputs.cred_protect = Some(cred_protect_policy.into());
            }
            if !cred_blob.is_empty() {
                ext_outputs.cred_blob = Some(cred_blob);
            }
            if request.extensions.as_ref().unwrap().hmac_secret.is_some() {
                let salt = self.crypto.random_bytes(32);
                let hmac_key = self.crypto.compute_hmac(&salt, &private_key)?;
                let encrypted = self.crypto.encrypt(&hmac_key, &[0u8; 12])?;
                ext_outputs.hmac_secret = Some(encrypted);
            }
            if request.extensions.as_ref().unwrap().large_blob_key {
                ext_outputs.large_blob_key = large_blob_key.clone();
            }
        }

        let (fmt, attestation_info) = match self.attestation_format {
            AttestationFormat::None => (
                AttestationFormat::None.as_str().to_string(),
                BTreeMap::new(),
            ),
            AttestationFormat::Self_ => {
                let mut data_to_sign = alloc::vec![];
                data_to_sign.extend_from_slice(&auth_data);
                data_to_sign.extend_from_slice(&request.client_data_hash);
                let att_stmt = SelfAttestation::generate(
                    &data_to_sign,
                    &private_key,
                    selected_alg,
                    &self.crypto,
                )?;
                (AttestationFormat::Self_.as_str().to_string(), att_stmt)
            }
            AttestationFormat::Packed => {
                let mut data_to_sign = alloc::vec![];
                data_to_sign.extend_from_slice(&auth_data);
                data_to_sign.extend_from_slice(&request.client_data_hash);
                let packed = PackedAttestation::new(selected_alg, self.attestation_cert.as_ref());
                let att_stmt = packed.generate(&data_to_sign, Some(&private_key), &self.crypto)?;
                (AttestationFormat::Packed.as_str().to_string(), att_stmt)
            }
            // U2F/AndroidKey/Apple are not implemented yet.
            _ => return Err(Box::new(Ctap2Error::UnsupportedOption)),
        };

        let response = MakeCredentialResponse {
            fmt,
            auth_data,
            attestation_info,
            extensions: if has_ext { Some(ext_outputs) } else { None },
        };

        Ok(response)
    }

    pub fn get_assertion(
        &mut self,
        request: GetAssertionRequest,
    ) -> Result<GetAssertionResponse, Box<dyn std::error::Error>> {
        debug!("Processing GetAssertion request");

        if request.options.up {
            if let Some(presence) = self.user_presence.as_mut() {
                if !presence.is_present() {
                    return Err(Box::new(Ctap2Error::OperationDenied));
                }
            }
        }

        let rp_id_hash = hash_rp_id(&request.rp_id, &self.crypto);
        let mut selected: Option<Credential> = None;

        // allow_list takes priority, then the legacy `credentials` field,
        // and finally a lookup by RP ID. Every candidate must belong to the
        // requesting RP.
        if let Some(allow) = request.allow_list.as_ref() {
            if !allow.is_empty() {
                for desc in allow {
                    if let Some(credential) = self.storage.get_credential(&desc.id, &self.crypto)? {
                        if credential.rp_id_hash == rp_id_hash.to_vec() {
                            selected = Some(credential);
                            break;
                        }
                    }
                }
            }
        }

        if selected.is_none() {
            if let Some(desc) = request.credentials.first() {
                if let Some(credential) = self.storage.get_credential(&desc.id, &self.crypto)? {
                    if credential.rp_id_hash == rp_id_hash.to_vec() {
                        selected = Some(credential);
                    }
                }
            }
        }

        let credential = match selected {
            Some(c) => c,
            None => {
                let rp_creds = self.storage.find_by_rp_id(&request.rp_id, &self.crypto);
                if rp_creds.is_empty() {
                    return Err(Box::new(Ctap2Error::NoCredentials));
                }
                rp_creds[0].clone()
            }
        };

        let mut flags: u8 = 0x00;
        if request.options.up {
            flags |= 0x01;
        }
        if request.options.uv {
            flags |= 0x04;
        }
        let sign_count = credential.sign_count + 1;

        self.storage
            .update_sign_count(&credential.credential_id, sign_count)?;

        let auth_data = self.build_auth_data(&AuthDataParams {
            rp_id_hash,
            sign_count,
            flags,
            include_credential_data: false,
            credential_id: &credential.credential_id,
            public_key: &credential.public_key,
            algorithm: credential.algorithm,
        })?;

        let mut data_to_sign = alloc::vec![];
        data_to_sign.extend_from_slice(&auth_data[..32]);
        data_to_sign.extend_from_slice(&auth_data[32..37]);
        data_to_sign.extend_from_slice(&request.client_data_hash);

        let signature = match credential.algorithm {
            -7 => self
                .crypto
                .sign_p256(&credential.private_key, &data_to_sign)?,
            -35 => self
                .crypto
                .sign_p384(&credential.private_key, &data_to_sign)?,
            -37 => self
                .crypto
                .sign_rsa_pss(&credential.private_key, &data_to_sign)?,
            -257 => self
                .crypto
                .sign_rsa(&credential.private_key, &data_to_sign)?,
            _ => self.crypto.sign(&data_to_sign, &credential.private_key)?,
        };

        let mut ext_outputs = ExtensionOutputs::default();
        let has_ext = request
            .extensions
            .as_ref()
            .map(|e| e.has_any())
            .unwrap_or(false);
        if has_ext {
            if !credential.cred_blob.is_empty() {
                ext_outputs.cred_blob = Some(credential.cred_blob.clone());
            }
            if let Some(ref hmac_input) = request.extensions.as_ref().unwrap().hmac_secret {
                let salt = if hmac_input.salt_enc.len() == 16 || hmac_input.salt_enc.len() == 32 {
                    hmac_input.salt_enc.clone()
                } else {
                    self.crypto.decrypt(&hmac_input.salt_enc, &[0u8; 12])?
                };
                let hmac_key = self.crypto.compute_hmac(&salt, &credential.private_key)?;
                let encrypted = self.crypto.encrypt(&hmac_key, &[0u8; 12])?;
                ext_outputs.hmac_secret = Some(encrypted);
            }
            if request.extensions.as_ref().unwrap().large_blob_key {
                if let Some(ref key) = credential.large_blob_key {
                    ext_outputs.large_blob_key = Some(key.clone());
                }
            }
        }

        let matching = self.find_matching_credentials(
            &request.rp_id,
            request.allow_list.as_deref().unwrap_or(&[]),
        );
        let total = matching.len();
        let current_index = matching
            .iter()
            .position(|id| id == &credential.credential_id)
            .unwrap_or(0);

        if total > 1 {
            self.get_next_assertion_state = Some(GetNextAssertionState {
                rp_id: request.rp_id.clone(),
                client_data_hash: request.client_data_hash.clone(),
                allow_list: request.allow_list.clone().unwrap_or_default(),
                extensions: request.extensions.clone(),
                options: request.options.clone(),
                pin_protocol: request.pin_protocol,
                current_index,
            });
        }

        Ok(GetAssertionResponse {
            credential: Some(CredentialDescriptor {
                r#type: "public-key".to_string(),
                id: credential.credential_id.clone(),
                transports: None,
            }),
            auth_data,
            signature,
            user: Some(User {
                id: credential.user_handle.clone().unwrap_or_default(),
                name: None,
                display_name: None,
                icon_url: None,
            }),
            number_of_credentials: if total > 1 { Some(total as u16) } else { None },
            next: if total > 1 && current_index + 1 < total {
                Some(true)
            } else {
                None
            },
            extensions: if has_ext { Some(ext_outputs) } else { None },
        })
    }

    pub fn get_info(&self) -> Result<GetInfoResponse, Box<dyn std::error::Error>> {
        debug!("Processing GetInfo request");

        let security = if self.capabilities.security.has_any_features() {
            Some(self.capabilities.security.clone())
        } else {
            None
        };

        Ok(GetInfoResponse {
            versions: self.capabilities.versions.clone(),
            extensions: self.capabilities.extensions.clone(),
            aaguid: self.capabilities.aaguid.to_vec(),
            options: self.capabilities.options.clone(),
            rp_count: self.capabilities.rp_count,
            max_cred_blob_length: self.capabilities.max_cred_blob_length,
            max_credential_id_length: self.capabilities.max_credential_id_length,
            max_credential_count: self.capabilities.max_credential_count,
            firmware_version: self.capabilities.firmware_version.clone(),
            algorithms: vec![
                CoseAlgorithmEntry {
                    alg: -7,
                    key_type: "public-key".to_string(),
                },
                CoseAlgorithmEntry {
                    alg: -8,
                    key_type: "public-key".to_string(),
                },
                CoseAlgorithmEntry {
                    alg: -35,
                    key_type: "public-key".to_string(),
                },
                CoseAlgorithmEntry {
                    alg: -37,
                    key_type: "public-key".to_string(),
                },
                CoseAlgorithmEntry {
                    alg: -257,
                    key_type: "public-key".to_string(),
                },
            ],
            security,
            max_large_blob_data_size: self.capabilities.max_large_blob_data_size,
        })
    }

    pub fn get_version(&self) -> Result<GetVersionResponse, Box<dyn std::error::Error>> {
        debug!("Processing GetVersion request");

        Ok(GetVersionResponse {
            firmware_version: "0.1.0".to_string(),
            firmware_commit_id: "0000000".to_string(),
            firmware_build_id: "00000000".to_string(),
        })
    }

    pub fn process_command(&mut self, cmd: u8, data: Vec<u8>) -> Result<Vec<u8>, Ctap2Error> {
        let command = Ctap2Command::from_u8(cmd);

        match command {
            Ctap2Command::MakeCredential => {
                let request: MakeCredentialRequest = decode_cbor(&data)?;
                let response = self.make_credential(request).map_err(ctap2_error)?;
                let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::InvalidData)?;
                Ok(encoded)
            }
            Ctap2Command::GetAssertion => {
                let request: GetAssertionRequest = decode_cbor(&data)?;
                let response = self.get_assertion(request).map_err(ctap2_error)?;
                let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::InvalidData)?;
                Ok(encoded)
            }
            Ctap2Command::GetInfo => {
                let response = self.get_info().map_err(|_| Ctap2Error::InvalidData)?;
                let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::InvalidData)?;
                Ok(encoded)
            }
            Ctap2Command::Selection => self.handle_selection(),
            Ctap2Command::GetVersion => self.handle_get_version(),
            Ctap2Command::ClientPIN => self.handle_client_pin(&data),
            Ctap2Command::Reset => self.handle_reset(),
            Ctap2Command::GetNextAssertion => self.handle_get_next_assertion(),
            Ctap2Command::BioEnroll => self.handle_bio_enroll(&data),
            Ctap2Command::CredentialManagement => self.handle_credential_management(&data),
            Ctap2Command::LargeBlobs => self.handle_large_blobs(&data),
            Ctap2Command::EnumerateRPsInitial => self.handle_enumerate_rps_initial(),
            Ctap2Command::EnumerateRPsNext => self.handle_enumerate_rps_next(),
            Ctap2Command::Unknown(_) => Err(Ctap2Error::InvalidCommand),
        }
    }

    fn handle_selection(&self) -> Result<Vec<u8>, Ctap2Error> {
        self.handle_get_version()
    }

    fn handle_get_version(&self) -> Result<Vec<u8>, Ctap2Error> {
        let response = self.get_version().map_err(|_| Ctap2Error::InvalidData)?;
        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::InvalidData)?;
        Ok(encoded)
    }

    fn handle_client_pin(&mut self, data: &[u8]) -> Result<Vec<u8>, Ctap2Error> {
        let request: client_pin::ClientPinRequest = decode_cbor(data)?;
        let response = client_pin::handle_client_pin(self, request)?;
        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::InvalidData)?;
        Ok(encoded)
    }

    fn handle_reset(&mut self) -> Result<Vec<u8>, Ctap2Error> {
        self.storage.clear();
        self.storage.clear_large_blobs();
        self.enumerate_rps_state = None;
        self.cred_mgmt_rps_state = None;
        self.cred_mgmt_creds_state = None;
        self.get_next_assertion_state = None;
        info!("Reset: all credentials and state cleared");
        Ok(Vec::new())
    }

    fn handle_get_next_assertion(&mut self) -> Result<Vec<u8>, Ctap2Error> {
        let state = self
            .get_next_assertion_state
            .take()
            .ok_or(Ctap2Error::InvalidState)?;

        let matching = self.find_matching_credentials(&state.rp_id, &state.allow_list);

        if matching.is_empty() {
            return Err(Ctap2Error::NoCredentials);
        }

        let next_index = state.current_index + 1;
        if next_index >= matching.len() {
            return Err(Ctap2Error::NoCredentials);
        }

        let credential_id = &matching[next_index];
        let credential = self
            .storage
            .get_credential(credential_id, &self.crypto)
            .map_err(|_| Ctap2Error::InvalidData)?
            .ok_or(Ctap2Error::NoCredentials)?;

        self.get_next_assertion_state = Some(GetNextAssertionState {
            current_index: next_index,
            ..state
        });

        let response = self
            .build_get_assertion_response(&credential, matching.len(), next_index)
            .map_err(|_| Ctap2Error::InvalidData)?;

        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::InvalidData)?;
        Ok(encoded)
    }

    fn handle_bio_enroll(&self, data: &[u8]) -> Result<Vec<u8>, Ctap2Error> {
        let request: BioEnrollRequest =
            decode_cbor(data).map_err(|_| Ctap2Error::InvalidParameter)?;

        if request.sub_command == 0x03 {
            let response = BioEnrollResponse {
                fingerprint_kind: 1,
                max_enrollments: 5,
            };
            let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::InvalidData)?;
            return Ok(encoded);
        }

        Err(Ctap2Error::UnsupportedOption)
    }

    fn handle_enumerate_rps_initial(&mut self) -> Result<Vec<u8>, Ctap2Error> {
        let rps = self.storage.enumerate_rps();
        let total = rps.len();

        if total == 0 {
            return Err(Ctap2Error::NoCredentials);
        }

        let first_rp_id = rps[0].0.clone();
        let first_rp_hash = rps[0].1.clone();
        self.enumerate_rps_state = Some(EnumerateRPsState {
            rps,
            total,
            current_index: 0,
        });

        let response = EnumerateRPsResponse {
            rp: RelyingParty {
                id: first_rp_id,
                name: None,
                icon: None,
            },
            rp_hash: first_rp_hash,
            total_rps: total as u8,
        };

        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::InvalidData)?;
        Ok(encoded)
    }

    fn handle_enumerate_rps_next(&mut self) -> Result<Vec<u8>, Ctap2Error> {
        let state = self
            .enumerate_rps_state
            .as_mut()
            .ok_or(Ctap2Error::InvalidState)?;

        state.current_index += 1;

        if state.current_index >= state.total {
            self.enumerate_rps_state = None;
            return Err(Ctap2Error::NoCredentials);
        }

        let (rp_id, rp_hash) = &state.rps[state.current_index];
        let response = EnumerateRPsResponse {
            rp: RelyingParty {
                id: rp_id.clone(),
                name: None,
                icon: None,
            },
            rp_hash: rp_hash.clone(),
            total_rps: state.total as u8,
        };

        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::InvalidData)?;
        Ok(encoded)
    }

    // ── LargeBlobs (0x0C) ────────────────────────────────────────────────

    fn handle_large_blobs(&mut self, data: &[u8]) -> Result<Vec<u8>, Ctap2Error> {
        let request: large_blobs::LargeBlobsRequest =
            decode_cbor(data).map_err(|_| Ctap2Error::InvalidParameter)?;

        // Read operation: `set` is None, `get` is Some
        if request.set.is_none() {
            let count = request.get.unwrap_or(0) as usize;
            let offset = request.offset as usize;
            let fragment = self.storage.read_large_blobs(offset, count);
            let response = large_blobs::LargeBlobsResponse {
                config: Some(fragment),
            };
            let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::InvalidData)?;
            return Ok(encoded);
        }

        // Write operation: `set` is Some
        let blob_data = request.set.unwrap();
        let expected_len = request.length.unwrap_or(0) as usize;
        let offset = request.offset as usize;

        // Validate against max supported size
        if let Some(max_size) = self.capabilities.max_large_blob_data_size {
            if expected_len > max_size as usize {
                return Err(Ctap2Error::LargeBlobStorageFull);
            }
        }

        self.storage
            .write_large_blobs(offset, &blob_data, expected_len)
            .map_err(|_| Ctap2Error::InvalidData)?;

        let response = large_blobs::LargeBlobsResponse { config: None };
        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::InvalidData)?;
        Ok(encoded)
    }

    // ── Credential Management (0x0A) ─────────────────────────────────────

    fn handle_credential_management(&mut self, data: &[u8]) -> Result<Vec<u8>, Ctap2Error> {
        let request: cred_mgmt::CredentialManagementRequest =
            decode_cbor(data).map_err(|_| Ctap2Error::InvalidParameter)?;

        match request.sub_command {
            cred_mgmt::sub_commands::GET_CREDS_METADATA => self.handle_cred_mgmt_get_metadata(),
            cred_mgmt::sub_commands::ENUMERATE_RPS_BEGIN => {
                self.handle_cred_mgmt_enumerate_rps_begin()
            }
            cred_mgmt::sub_commands::ENUMERATE_RPS_GET_NEXT => {
                self.handle_cred_mgmt_enumerate_rps_next()
            }
            cred_mgmt::sub_commands::ENUMERATE_CREDENTIALS_BEGIN => {
                let params = request
                    .sub_command_params
                    .ok_or(Ctap2Error::InvalidParameter)?;
                let rp_hash = params.rp_id_hash.ok_or(Ctap2Error::InvalidParameter)?;
                self.handle_cred_mgmt_enumerate_creds_begin(&rp_hash)
            }
            cred_mgmt::sub_commands::ENUMERATE_CREDENTIALS_GET_NEXT => {
                self.handle_cred_mgmt_enumerate_creds_next()
            }
            cred_mgmt::sub_commands::DELETE_CREDENTIAL => {
                let params = request
                    .sub_command_params
                    .ok_or(Ctap2Error::InvalidParameter)?;
                let cred_desc = params.credential_id.ok_or(Ctap2Error::InvalidParameter)?;
                self.handle_cred_mgmt_delete_credential(&cred_desc.id)
            }
            cred_mgmt::sub_commands::UPDATE_USER_INFORMATION => {
                let params = request
                    .sub_command_params
                    .ok_or(Ctap2Error::InvalidParameter)?;
                let cred_desc = params.credential_id.ok_or(Ctap2Error::InvalidParameter)?;
                let user = params.user.ok_or(Ctap2Error::InvalidParameter)?;
                self.handle_cred_mgmt_update_user(&cred_desc.id, &user)
            }
            _ => Err(Ctap2Error::InvalidParameter),
        }
    }

    fn handle_cred_mgmt_get_metadata(&self) -> Result<Vec<u8>, Ctap2Error> {
        let count = self.storage.get_credentials_count() as u32;
        let remaining = self.storage.get_max_possible_remaining() as u32;
        let response = cred_mgmt::CredsMetadataResponse {
            existing_resident_credentials_count: count,
            max_possible_remaining_resident_credentials_count: remaining,
        };
        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::InvalidData)?;
        Ok(encoded)
    }

    fn handle_cred_mgmt_enumerate_rps_begin(&mut self) -> Result<Vec<u8>, Ctap2Error> {
        let rps = self.storage.enumerate_rps();
        let total = rps.len();
        if total == 0 {
            return Err(Ctap2Error::NoCredentials);
        }

        let first_rp_id = rps[0].0.clone();
        let first_rp_hash = rps[0].1.clone();

        self.cred_mgmt_rps_state = Some(EnumerateRpsCredMgmtState {
            rps,
            total,
            current_index: 0,
        });

        let response = cred_mgmt::EnumerateRpsEntryResponse {
            rp: RelyingParty {
                id: first_rp_id,
                name: None,
                icon: None,
            },
            rp_id_hash: first_rp_hash,
            total_rps: total as u32,
        };
        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::InvalidData)?;
        Ok(encoded)
    }

    fn handle_cred_mgmt_enumerate_rps_next(&mut self) -> Result<Vec<u8>, Ctap2Error> {
        let state = self
            .cred_mgmt_rps_state
            .as_mut()
            .ok_or(Ctap2Error::InvalidState)?;

        state.current_index += 1;
        if state.current_index >= state.total {
            self.cred_mgmt_rps_state = None;
            return Err(Ctap2Error::NoCredentials);
        }

        let (rp_id, rp_hash) = &state.rps[state.current_index];
        let response = cred_mgmt::EnumerateRpsEntryResponse {
            rp: RelyingParty {
                id: rp_id.clone(),
                name: None,
                icon: None,
            },
            rp_id_hash: rp_hash.clone(),
            total_rps: state.total as u32,
        };
        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::InvalidData)?;
        Ok(encoded)
    }

    fn handle_cred_mgmt_enumerate_creds_begin(
        &mut self,
        rp_hash: &[u8],
    ) -> Result<Vec<u8>, Ctap2Error> {
        let creds = self
            .storage
            .find_credentials_by_rp_hash(rp_hash, &self.crypto);
        let total = creds.len();
        if total == 0 {
            return Err(Ctap2Error::NoCredentials);
        }

        let first = &creds[0];
        let response = self.build_enumerate_cred_entry(first, total as u32);

        self.cred_mgmt_creds_state = Some(EnumerateCredentialsState {
            creds,
            total,
            current_index: 0,
        });

        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::InvalidData)?;
        Ok(encoded)
    }

    fn handle_cred_mgmt_enumerate_creds_next(&mut self) -> Result<Vec<u8>, Ctap2Error> {
        let state = self
            .cred_mgmt_creds_state
            .as_mut()
            .ok_or(Ctap2Error::InvalidState)?;

        state.current_index += 1;
        if state.current_index >= state.total {
            self.cred_mgmt_creds_state = None;
            return Err(Ctap2Error::NoCredentials);
        }

        let cred = &state.creds[state.current_index].clone();
        let total = state.total as u32;
        let response = self.build_enumerate_cred_entry(cred, total);
        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::InvalidData)?;
        Ok(encoded)
    }

    fn handle_cred_mgmt_delete_credential(
        &mut self,
        credential_id: &[u8],
    ) -> Result<Vec<u8>, Ctap2Error> {
        self.storage
            .delete_credential(credential_id)
            .map_err(|_| Ctap2Error::NoCredentials)?;
        Ok(Vec::new())
    }

    fn handle_cred_mgmt_update_user(
        &mut self,
        credential_id: &[u8],
        user: &User,
    ) -> Result<Vec<u8>, Ctap2Error> {
        let updated = self
            .storage
            .update_user_info(credential_id, user.name.clone(), user.display_name.clone())
            .map_err(|_| Ctap2Error::InvalidData)?;
        if !updated {
            return Err(Ctap2Error::NoCredentials);
        }
        Ok(Vec::new())
    }

    fn build_enumerate_cred_entry(
        &self,
        credential: &Credential,
        total: u32,
    ) -> cred_mgmt::EnumerateCredentialsEntryResponse {
        cred_mgmt::EnumerateCredentialsEntryResponse {
            user: User {
                id: credential.user_handle.clone().unwrap_or_default(),
                name: credential.user_name.clone(),
                display_name: credential.user_display_name.clone(),
                icon_url: None,
            },
            credential_id: CredentialDescriptor {
                r#type: "public-key".to_string(),
                id: credential.credential_id.clone(),
                transports: None,
            },
            public_key: credential.public_key.clone(),
            total_credentials: total,
            cred_protect: None,
            large_blob_key: credential.large_blob_key.clone(),
        }
    }

    fn find_matching_credentials(
        &self,
        rp_id: &str,
        allow_list: &[CredentialDescriptor],
    ) -> Vec<Vec<u8>> {
        if allow_list.is_empty() {
            return self
                .storage
                .find_by_rp_id(rp_id, &self.crypto)
                .into_iter()
                .map(|c| c.credential_id.clone())
                .collect();
        }

        allow_list
            .iter()
            .filter_map(|desc| {
                self.storage
                    .get_credential(&desc.id, &self.crypto)
                    .ok()
                    .flatten()
                    .filter(|c| c.rp_id == rp_id)
                    .map(|c| c.credential_id.clone())
            })
            .collect()
    }

    fn build_get_assertion_response(
        &self,
        credential: &Credential,
        total: usize,
        current_index: usize,
    ) -> Result<GetAssertionResponse, Box<dyn std::error::Error>> {
        let sign_count = credential.sign_count;
        let rp_id_hash_vec = self.crypto.sha256(credential.rp_id.as_bytes());
        let rp_id_hash: [u8; 32] = rp_id_hash_vec
            .try_into()
            .map_err(|_| "rp_id_hash must be 32 bytes")?;

        let flags: u8 = 0x01;
        let auth_data = self.build_auth_data(&AuthDataParams {
            rp_id_hash,
            flags,
            sign_count,
            include_credential_data: false,
            credential_id: &credential.credential_id,
            public_key: &credential.public_key,
            algorithm: credential.algorithm,
        })?;

        let mut data_to_sign = alloc::vec![];
        data_to_sign.extend_from_slice(&auth_data[..32]);
        data_to_sign.extend_from_slice(&auth_data[32..37]);

        let signature = match credential.algorithm {
            -7 => self
                .crypto
                .sign_p256(&credential.private_key, &data_to_sign)?,
            -35 => self
                .crypto
                .sign_p384(&credential.private_key, &data_to_sign)?,
            -37 => self
                .crypto
                .sign_rsa_pss(&credential.private_key, &data_to_sign)?,
            -257 => self
                .crypto
                .sign_rsa(&credential.private_key, &data_to_sign)?,
            _ => self.crypto.sign(&data_to_sign, &credential.private_key)?,
        };

        let has_more = current_index + 1 < total;

        Ok(GetAssertionResponse {
            credential: Some(CredentialDescriptor {
                r#type: "public-key".to_string(),
                id: credential.credential_id.clone(),
                transports: None,
            }),
            auth_data,
            signature,
            user: None,
            number_of_credentials: Some(total as u16),
            next: Some(has_more),
            extensions: None,
        })
    }

    fn generate_credential_id(&self) -> Vec<u8> {
        self.crypto.random_bytes(16)
    }

    fn build_auth_data(
        &self,
        params: &AuthDataParams,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut auth_data = alloc::vec![];
        auth_data.extend_from_slice(&params.rp_id_hash);
        auth_data.push(params.flags);
        auth_data.extend_from_slice(&params.sign_count.to_be_bytes());

        if params.include_credential_data {
            // attestedCredentialData: aaguid(16) || credIdLen(2) || credId || COSE_Key
            auth_data.extend_from_slice(&self.capabilities.aaguid);

            let credential_id_len = params.credential_id.len() as u16;
            auth_data.extend_from_slice(&credential_id_len.to_be_bytes());
            auth_data.extend_from_slice(params.credential_id);

            let cose_key = match params.algorithm {
                -7 => {
                    // P-256: public_key is 65 bytes (0x04 || x || y)
                    if params.public_key.len() == 65 {
                        build_cose_key_p256(&params.public_key[1..33], &params.public_key[33..65])
                            .map_err(|_| "failed to build P-256 COSE key".to_string())?
                    } else {
                        return Err("invalid P-256 public key length".into());
                    }
                }
                -35 => {
                    // P-384: public_key is 97 bytes (0x04 || x(48) || y(48))
                    if params.public_key.len() == 97 {
                        build_cose_key_p384(&params.public_key[1..49], &params.public_key[49..97])
                            .map_err(|_| "failed to build P-384 COSE key".to_string())?
                    } else {
                        return Err("invalid P-384 public key length".into());
                    }
                }
                -37 => {
                    let (n, e) = CryptoEngine::rsa_public_key_parts(params.public_key)?;
                    build_cose_key_rsa_pss(&n, &e)
                        .map_err(|_| "failed to build RSA-PSS COSE key".to_string())?
                }
                -257 => {
                    let (n, e) = CryptoEngine::rsa_public_key_parts(params.public_key)?;
                    build_cose_key_rsa(&n, &e)
                        .map_err(|_| "failed to build RSA COSE key".to_string())?
                }
                _ => build_cose_key(params.public_key)
                    .map_err(|_| "failed to build Ed25519 COSE key".to_string())?,
            };
            auth_data.extend_from_slice(&cose_key);
        }

        Ok(auth_data)
    }
}

impl client_pin::ClientPin for Ctap2Authenticator {
    fn get_pin_retries(&self) -> u8 {
        self.storage
            .retrieve(client_pin::PIN_RETRIES_KEY)
            .ok()
            .and_then(|data| alloc::string::String::from_utf8(data).ok())
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(client_pin::PIN_MAX_RETRIES)
    }

    fn get_pin_token(&mut self) -> Result<Vec<u8>, Ctap2Error> {
        let pin_hash = self
            .storage
            .retrieve(client_pin::PIN_STORAGE_KEY)
            .map_err(|_| Ctap2Error::PinRequired)?;

        let shared_secret = self
            .storage
            .retrieve(client_pin::SHARED_SECRET_KEY)
            .map_err(|_| Ctap2Error::InvalidState)?;

        let hmac_key = self
            .crypto
            .compute_hmac(&shared_secret, &pin_hash)
            .map_err(|_| Ctap2Error::InvalidData)?;

        let token = self
            .crypto
            .compute_hmac(b"pinUvAuthToken", &hmac_key)
            .map_err(|_| Ctap2Error::InvalidData)?;

        self.crypto
            .encrypt(&token, &[0u8; 12])
            .map_err(|_| Ctap2Error::InvalidData)
    }

    fn set_pin(&mut self, pin: &[u8]) -> Result<(), Ctap2Error> {
        if pin.len() < client_pin::PIN_MIN_LENGTH {
            return Err(Ctap2Error::PinPolicyViolation);
        }

        let hash = self.crypto.sha256(pin);
        self.storage
            .store(client_pin::PIN_STORAGE_KEY, hash)
            .map_err(|_| Ctap2Error::InvalidData)?;

        let shared_secret = self.crypto.random_bytes(32);
        self.storage
            .store(client_pin::SHARED_SECRET_KEY, shared_secret)
            .map_err(|_| Ctap2Error::InvalidData)?;

        self.reset_pin_retries();

        Ok(())
    }

    fn change_pin(&mut self, old_pin: &[u8], new_pin: &[u8]) -> Result<(), Ctap2Error> {
        if new_pin.len() < client_pin::PIN_MIN_LENGTH {
            return Err(Ctap2Error::PinPolicyViolation);
        }

        let stored_hash = self
            .storage
            .retrieve(client_pin::PIN_STORAGE_KEY)
            .map_err(|_| Ctap2Error::PinRequired)?;

        let old_hash = self.crypto.sha256(old_pin);
        if !crypto::constant_time_eq(&old_hash, &stored_hash) {
            self.decrement_pin_retries();
            return Err(Ctap2Error::PinInvalid);
        }

        self.reset_pin_retries();

        let new_hash = self.crypto.sha256(new_pin);
        self.storage
            .store(client_pin::PIN_STORAGE_KEY, new_hash)
            .map_err(|_| Ctap2Error::InvalidData)?;

        let shared_secret = self.crypto.random_bytes(32);
        self.storage
            .store(client_pin::SHARED_SECRET_KEY, shared_secret)
            .map_err(|_| Ctap2Error::InvalidData)?;

        Ok(())
    }

    fn get_pin_hash_enc(&mut self) -> Result<Vec<u8>, Ctap2Error> {
        let pin_hash = self
            .storage
            .retrieve(client_pin::PIN_STORAGE_KEY)
            .map_err(|_| Ctap2Error::PinRequired)?;

        self.crypto
            .encrypt(&pin_hash, &[0u8; 12])
            .map_err(|_| Ctap2Error::InvalidData)
    }

    fn reset_pin_retries(&mut self) {
        let _ = self.storage.store(
            client_pin::PIN_RETRIES_KEY,
            client_pin::PIN_MAX_RETRIES.to_string().into_bytes(),
        );
    }

    fn decrement_pin_retries(&mut self) {
        let current = self.get_pin_retries();
        let new = current.saturating_sub(1);
        let _ = self
            .storage
            .store(client_pin::PIN_RETRIES_KEY, new.to_string().into_bytes());
    }

    fn verify_pin(&mut self, pin: &[u8]) -> Result<(), Ctap2Error> {
        if !client_pin::is_pin_set(self.get_storage()) {
            return Err(Ctap2Error::PinRequired);
        }
        if client_pin::is_pin_blocked(self.get_storage()) {
            return Err(Ctap2Error::PinInvalid);
        }
        let stored_hash = self
            .storage
            .retrieve(client_pin::PIN_STORAGE_KEY)
            .map_err(|_| Ctap2Error::PinRequired)?;
        let submitted_hash = self.crypto.sha256(pin);
        if !crypto::constant_time_eq(&submitted_hash, &stored_hash) {
            self.decrement_pin_retries();
            return Err(Ctap2Error::PinInvalid);
        }
        self.reset_pin_retries();
        Ok(())
    }
}

/// Builds a COSE_Key CBOR map for an Ed25519 (EdDSA, alg -8) public key.
/// Labels: kty(1)=OKP(1), alg(3)=EdDSA(-8), crv(-1)=Ed25519(6), x(-2)=public key.
fn build_cose_key(public_key: &[u8]) -> Result<Vec<u8>, Ctap2Error> {
    let mut key_map: BTreeMap<i64, Value> = BTreeMap::new();
    key_map.insert(1, Value::Integer(Integer::from(1)));
    key_map.insert(3, Value::Integer(Integer::from(-8)));
    key_map.insert(-1, Value::Integer(Integer::from(6)));
    key_map.insert(-2, Value::Bytes(public_key.to_vec()));
    encode_cbor(&key_map)
}

/// Builds a COSE_Key CBOR map for an ES256 (EC2, alg -7) P-256 public key.
/// Labels: kty(1)=EC2(2), alg(3)=ES256(-7), crv(-1)=P-256(1), x(-2)=32 bytes, y(-3)=32 bytes.
fn build_cose_key_p256(x: &[u8], y: &[u8]) -> Result<Vec<u8>, Ctap2Error> {
    let mut key_map: BTreeMap<i64, Value> = BTreeMap::new();
    key_map.insert(1, Value::Integer(Integer::from(2)));
    key_map.insert(3, Value::Integer(Integer::from(-7)));
    key_map.insert(-1, Value::Integer(Integer::from(1)));
    key_map.insert(-2, Value::Bytes(x.to_vec()));
    key_map.insert(-3, Value::Bytes(y.to_vec()));
    encode_cbor(&key_map)
}

/// Builds a COSE_Key CBOR map for an RS256 (RSA, alg -257) public key.
/// Labels: kty(1)=RSA(3), alg(3)=RS256(-257), n(-1)=modulus, e(-2)=exponent.
fn build_cose_key_rsa(n: &[u8], e: &[u8]) -> Result<Vec<u8>, Ctap2Error> {
    let mut key_map: BTreeMap<i64, Value> = BTreeMap::new();
    key_map.insert(1, Value::Integer(Integer::from(3)));
    key_map.insert(3, Value::Integer(Integer::from(-257)));
    key_map.insert(-1, Value::Bytes(n.to_vec()));
    key_map.insert(-2, Value::Bytes(e.to_vec()));
    encode_cbor(&key_map)
}

/// Builds a COSE_Key CBOR map for an ES384 (EC2, alg -35) P-384 public key.
/// Labels: kty(1)=EC2(2), alg(3)=ES384(-35), crv(-1)=P-384(2), x(-2)=48 bytes, y(-3)=48 bytes.
fn build_cose_key_p384(x: &[u8], y: &[u8]) -> Result<Vec<u8>, Ctap2Error> {
    let mut key_map: BTreeMap<i64, Value> = BTreeMap::new();
    key_map.insert(1, Value::Integer(Integer::from(2)));
    key_map.insert(3, Value::Integer(Integer::from(-35)));
    key_map.insert(-1, Value::Integer(Integer::from(2)));
    key_map.insert(-2, Value::Bytes(x.to_vec()));
    key_map.insert(-3, Value::Bytes(y.to_vec()));
    encode_cbor(&key_map)
}

/// Builds a COSE_Key CBOR map for a PS256 (RSA-PSS, alg -37) public key.
/// Labels: kty(1)=RSA(3), alg(3)=PS256(-37), n(-1)=modulus, e(-2)=exponent.
fn build_cose_key_rsa_pss(n: &[u8], e: &[u8]) -> Result<Vec<u8>, Ctap2Error> {
    let mut key_map: BTreeMap<i64, Value> = BTreeMap::new();
    key_map.insert(1, Value::Integer(Integer::from(3)));
    key_map.insert(3, Value::Integer(Integer::from(-37)));
    key_map.insert(-1, Value::Bytes(n.to_vec()));
    key_map.insert(-2, Value::Bytes(e.to_vec()));
    encode_cbor(&key_map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cred_protect_default() {
        assert_eq!(
            CredProtectPolicy::default(),
            CredProtectPolicy::UserVerificationOptional
        );
    }

    #[test]
    fn test_cred_protect_from_u8() {
        assert_eq!(
            CredProtectPolicy::from(0x01),
            CredProtectPolicy::UserVerificationOptional
        );
        assert_eq!(
            CredProtectPolicy::from(0x02),
            CredProtectPolicy::UserVerificationOptionalWithCredentialIDList
        );
        assert_eq!(
            CredProtectPolicy::from(0x03),
            CredProtectPolicy::UserVerificationRequired
        );
    }

    #[test]
    fn test_cred_protect_into_u8() {
        let val: u8 = CredProtectPolicy::UserVerificationOptional.into();
        assert_eq!(val, 0x01);
        let val: u8 = CredProtectPolicy::UserVerificationOptionalWithCredentialIDList.into();
        assert_eq!(val, 0x02);
        let val: u8 = CredProtectPolicy::UserVerificationRequired.into();
        assert_eq!(val, 0x03);
    }

    #[test]
    fn test_reset() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let request = MakeCredentialRequest {
            client_data_hash: b"test".to_vec(),
            rp: RelyingParty {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
                icon: None,
            },
            user: User {
                id: b"user123".to_vec(),
                name: Some("testuser".to_string()),
                display_name: Some("Test User".to_string()),
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
                uv: true,
                up: true,
                extended: false,
            },
            pin_protocol: None,
            enterprise_protections: None,
        };

        authenticator.make_credential(request).unwrap();
        assert_eq!(authenticator.get_storage().list_credentials().len(), 1);

        let result = authenticator.process_command(0x07, vec![]).unwrap();
        assert!(result.is_empty());
        assert!(authenticator.get_storage().list_credentials().is_empty());
    }

    #[test]
    fn test_selection() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let result = authenticator.process_command(0x0B, vec![]);
        assert!(result.is_ok());

        let encoded = result.unwrap();
        let response: GetVersionResponse = from_reader(encoded.as_slice()).unwrap();
        assert_eq!(response.firmware_version, "0.1.0");
        assert_eq!(response.firmware_commit_id, "0000000");
        assert_eq!(response.firmware_build_id, "00000000");
    }

    #[test]
    fn test_get_version() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let result = authenticator.process_command(0x0F, vec![]);
        assert!(result.is_ok());

        let encoded = result.unwrap();
        let response: GetVersionResponse = from_reader(encoded.as_slice()).unwrap();
        assert_eq!(response.firmware_version, "0.1.0");
        assert_eq!(response.firmware_commit_id, "0000000");
        assert_eq!(response.firmware_build_id, "00000000");
    }

    #[derive(Debug)]
    struct TestUserPresence {
        present: bool,
    }

    impl UserPresence for TestUserPresence {
        fn is_present(&mut self) -> bool {
            self.present
        }
    }

    fn make_credential_request(up: bool) -> MakeCredentialRequest {
        MakeCredentialRequest {
            client_data_hash: b"test".to_vec(),
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
                algorithms: -7,
            }],
            exclude_list: vec![],
            extensions: None,
            options: MakeCredentialOptions {
                rk: false,
                uv: false,
                up,
                extended: false,
            },
            pin_protocol: None,
            enterprise_protections: None,
        }
    }

    #[test]
    fn test_user_presence_denied_when_button_not_pressed() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut auth = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        auth.set_user_presence(Some(Box::new(TestUserPresence { present: false })));

        match auth.make_credential(make_credential_request(true)) {
            Err(e) => assert_eq!(
                e.downcast_ref::<Ctap2Error>(),
                Some(&Ctap2Error::OperationDenied)
            ),
            Ok(_) => panic!("expected OperationDenied"),
        }
    }

    #[test]
    fn test_user_presence_allowed_when_button_pressed() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut auth = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        auth.set_user_presence(Some(Box::new(TestUserPresence { present: true })));

        assert!(auth.make_credential(make_credential_request(true)).is_ok());
    }

    #[test]
    fn test_user_presence_default_allows_without_check() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut auth = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        assert!(auth.make_credential(make_credential_request(true)).is_ok());
    }

    #[test]
    fn test_cred_protect() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let request = MakeCredentialRequest {
            client_data_hash: b"test".to_vec(),
            rp: RelyingParty {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
                icon: None,
            },
            user: User {
                id: b"user123".to_vec(),
                name: Some("testuser".to_string()),
                display_name: Some("Test User".to_string()),
                icon_url: None,
            },
            pub_key_cred_params: vec![PublicKeyCredParams {
                r#type: "public-key".to_string(),
                algorithms: -7,
            }],
            exclude_list: vec![],
            extensions: Some(Extensions {
                cred_protect: Some(CredProtectPolicy::UserVerificationRequired),
                ..Default::default()
            }),
            options: MakeCredentialOptions {
                rk: false,
                uv: true,
                up: true,
                extended: false,
            },
            pin_protocol: None,
            enterprise_protections: None,
        };

        let response = authenticator.make_credential(request).unwrap();
        let ext = response.extensions.unwrap();
        assert_eq!(ext.cred_protect, Some(0x03));
    }

    #[test]
    fn test_get_info_includes_extensions() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let info = authenticator.get_info().unwrap();
        assert!(info.extensions.contains(&"credProtect".to_string()));
        assert!(info.extensions.contains(&"credBlob".to_string()));
        assert!(info.extensions.contains(&"minPinLength".to_string()));
        assert!(info.extensions.contains(&"hmac-secret".to_string()));
    }

    #[test]
    fn test_cred_blob_set_and_get() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let blob = b"my-cred-blob".to_vec();
        let request = MakeCredentialRequest {
            client_data_hash: b"test".to_vec(),
            rp: RelyingParty {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
                icon: None,
            },
            user: User {
                id: b"user123".to_vec(),
                name: Some("testuser".to_string()),
                display_name: Some("Test User".to_string()),
                icon_url: None,
            },
            pub_key_cred_params: vec![PublicKeyCredParams {
                r#type: "public-key".to_string(),
                algorithms: -7,
            }],
            exclude_list: vec![],
            extensions: Some(Extensions {
                cred_blob: Some(blob.clone()),
                ..Default::default()
            }),
            options: MakeCredentialOptions {
                rk: false,
                uv: true,
                up: true,
                extended: false,
            },
            pin_protocol: None,
            enterprise_protections: None,
        };

        authenticator.make_credential(request).unwrap();
        let stored = authenticator.get_storage().list_credentials();
        assert_eq!(stored[0].cred_blob, blob);

        let cred_id = stored[0].credential_id.clone();

        let assert_request = GetAssertionRequest {
            rp_id: "example.com".to_string(),
            credentials: vec![CredentialDescriptor {
                r#type: "public-key".to_string(),
                id: cred_id,
                transports: None,
            }],
            allow_list: None,
            client_data_hash: authenticator.get_crypto().sha256(b"client data hash"),
            extensions: Some(Extensions {
                min_pin_length: true,
                ..Default::default()
            }),
            options: GetAssertionOptions { up: true, uv: true },
            pin_protocol: None,
            uv: Some(true),
        };

        let assert_response = authenticator.get_assertion(assert_request).unwrap();
        let ext = assert_response.extensions.unwrap();
        assert_eq!(ext.cred_blob, Some(blob));
    }

    #[test]
    fn test_cred_blob_reject_too_large() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let blob = vec![0u8; 33];
        let request = MakeCredentialRequest {
            client_data_hash: b"test".to_vec(),
            rp: RelyingParty {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
                icon: None,
            },
            user: User {
                id: b"user123".to_vec(),
                name: Some("testuser".to_string()),
                display_name: Some("Test User".to_string()),
                icon_url: None,
            },
            pub_key_cred_params: vec![PublicKeyCredParams {
                r#type: "public-key".to_string(),
                algorithms: -7,
            }],
            exclude_list: vec![],
            extensions: Some(Extensions {
                cred_blob: Some(blob),
                ..Default::default()
            }),
            options: MakeCredentialOptions {
                rk: false,
                uv: true,
                up: true,
                extended: false,
            },
            pin_protocol: None,
            enterprise_protections: None,
        };

        let result = authenticator.make_credential(request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(
            *err.downcast_ref::<Ctap2Error>().unwrap(),
            Ctap2Error::InvalidParameter
        );
    }

    #[test]
    fn test_min_pin_length() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let request = MakeCredentialRequest {
            client_data_hash: b"test".to_vec(),
            rp: RelyingParty {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
                icon: None,
            },
            user: User {
                id: b"user123".to_vec(),
                name: Some("testuser".to_string()),
                display_name: Some("Test User".to_string()),
                icon_url: None,
            },
            pub_key_cred_params: vec![PublicKeyCredParams {
                r#type: "public-key".to_string(),
                algorithms: -7,
            }],
            exclude_list: vec![],
            extensions: Some(Extensions {
                min_pin_length: true,
                ..Default::default()
            }),
            options: MakeCredentialOptions {
                rk: false,
                uv: true,
                up: true,
                extended: false,
            },
            pin_protocol: None,
            enterprise_protections: None,
        };

        let response = authenticator.make_credential(request).unwrap();
        let ext = response.extensions.unwrap();
        assert_eq!(ext.min_pin_length, Some(4));
    }

    #[test]
    fn test_hmac_secret_creation() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let request = MakeCredentialRequest {
            client_data_hash: b"test".to_vec(),
            rp: RelyingParty {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
                icon: None,
            },
            user: User {
                id: b"user123".to_vec(),
                name: Some("testuser".to_string()),
                display_name: Some("Test User".to_string()),
                icon_url: None,
            },
            pub_key_cred_params: vec![PublicKeyCredParams {
                r#type: "public-key".to_string(),
                algorithms: -7,
            }],
            exclude_list: vec![],
            extensions: Some(Extensions {
                hmac_secret: Some(HmacSecretInput {
                    salt_enc: vec![0u8; 16],
                    pin_uv_auth_protocol: None,
                }),
                ..Default::default()
            }),
            options: MakeCredentialOptions {
                rk: false,
                uv: true,
                up: true,
                extended: false,
            },
            pin_protocol: None,
            enterprise_protections: None,
        };

        let response = authenticator.make_credential(request).unwrap();
        let ext = response.extensions.unwrap();
        assert!(ext.hmac_secret.is_some());
        assert_eq!(ext.hmac_secret.unwrap().len(), 48);
    }

    #[test]
    fn test_hmac_secret_get() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto.clone(), storage).unwrap();

        let request = MakeCredentialRequest {
            client_data_hash: b"test".to_vec(),
            rp: RelyingParty {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
                icon: None,
            },
            user: User {
                id: b"user123".to_vec(),
                name: Some("testuser".to_string()),
                display_name: Some("Test User".to_string()),
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
                uv: true,
                up: true,
                extended: false,
            },
            pin_protocol: None,
            enterprise_protections: None,
        };

        authenticator.make_credential(request).unwrap();
        let cred_id = authenticator.get_storage().list_credentials()[0]
            .credential_id
            .clone();

        let salt = b"1234567890123456".to_vec();
        let encrypted_salt = crypto.encrypt(&salt, &[0u8; 12]).unwrap();

        let assert_request = GetAssertionRequest {
            rp_id: "example.com".to_string(),
            credentials: vec![CredentialDescriptor {
                r#type: "public-key".to_string(),
                id: cred_id.clone(),
                transports: None,
            }],
            allow_list: None,
            client_data_hash: authenticator.get_crypto().sha256(b"client data hash"),
            extensions: Some(Extensions {
                hmac_secret: Some(HmacSecretInput {
                    salt_enc: encrypted_salt,
                    pin_uv_auth_protocol: None,
                }),
                ..Default::default()
            }),
            options: GetAssertionOptions { up: true, uv: true },
            pin_protocol: None,
            uv: Some(true),
        };

        let assert_response = authenticator.get_assertion(assert_request).unwrap();
        let ext = assert_response.extensions.unwrap();
        assert!(ext.hmac_secret.is_some());
        assert_eq!(ext.hmac_secret.unwrap().len(), 48);
    }

    #[test]
    fn test_es256_sign_verify() {
        let crypto = CryptoEngine::new().unwrap();
        let (private_key, public_key) = crypto.generate_p256_key_pair().unwrap();
        assert_eq!(public_key.len(), 65);
        assert_eq!(public_key[0], 0x04);

        let message = b"test message for ES256";
        let signature = crypto.sign_p256(&private_key, message).unwrap();
        assert!(!signature.is_empty());

        crypto
            .verify_p256(&public_key, message, &signature)
            .unwrap();
    }

    #[test]
    fn test_es256_verify_tampered_fails() {
        let crypto = CryptoEngine::new().unwrap();
        let (private_key, public_key) = crypto.generate_p256_key_pair().unwrap();

        let message = b"test message";
        let signature = crypto.sign_p256(&private_key, message).unwrap();

        let tampered = b"tampered message";
        assert!(crypto
            .verify_p256(&public_key, tampered, &signature)
            .is_err());
    }

    #[test]
    fn test_cose_key_p256() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let request = MakeCredentialRequest {
            client_data_hash: b"test".to_vec(),
            rp: RelyingParty {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
                icon: None,
            },
            user: User {
                id: b"user123".to_vec(),
                name: Some("testuser".to_string()),
                display_name: Some("Test User".to_string()),
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
                uv: true,
                up: true,
                extended: false,
            },
            pin_protocol: None,
            enterprise_protections: None,
        };

        let response = authenticator.make_credential(request).unwrap();
        let auth = &response.auth_data;
        let cred_id_len = u16::from_be_bytes([auth[53], auth[54]]) as usize;
        let cose_key_start = 55 + cred_id_len;

        let map: BTreeMap<i64, Value> = from_reader(&auth[cose_key_start..]).unwrap();
        assert_eq!(map.len(), 5);
        assert_eq!(map[&1], Value::Integer(Integer::from(2))); // kty = EC2
        assert_eq!(map[&3], Value::Integer(Integer::from(-7))); // alg = ES256
        assert_eq!(map[&-1], Value::Integer(Integer::from(1))); // crv = P-256
        match &map[&-2] {
            Value::Bytes(x) => assert_eq!(x.len(), 32),
            other => panic!("expected byte string for x, got {:?}", other),
        }
        match &map[&-3] {
            Value::Bytes(y) => assert_eq!(y.len(), 32),
            other => panic!("expected byte string for y, got {:?}", other),
        }
    }

    #[test]
    fn test_algorithm_negotiation_prefers_first_supported() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        // RS256 (-257) and ES256 (-7) are both supported — should pick RS256
        let request = MakeCredentialRequest {
            client_data_hash: b"test".to_vec(),
            rp: RelyingParty {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
                icon: None,
            },
            user: User {
                id: b"user123".to_vec(),
                name: Some("testuser".to_string()),
                display_name: Some("Test User".to_string()),
                icon_url: None,
            },
            pub_key_cred_params: vec![
                PublicKeyCredParams {
                    r#type: "public-key".to_string(),
                    algorithms: -257, // RS256 — supported, first match wins
                },
                PublicKeyCredParams {
                    r#type: "public-key".to_string(),
                    algorithms: -7, // ES256 — supported
                },
            ],
            exclude_list: vec![],
            extensions: None,
            options: MakeCredentialOptions {
                rk: false,
                uv: true,
                up: true,
                extended: false,
            },
            pin_protocol: None,
            enterprise_protections: None,
        };

        let response = authenticator.make_credential(request).unwrap();
        assert_eq!(response.fmt, "none");

        let stored = authenticator.get_storage().list_credentials();
        assert_eq!(stored[0].algorithm, -257);
    }

    #[test]
    fn test_algorithm_negotiation_unsupported_returns_error() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let request = MakeCredentialRequest {
            client_data_hash: b"test".to_vec(),
            rp: RelyingParty {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
                icon: None,
            },
            user: User {
                id: b"user123".to_vec(),
                name: Some("testuser".to_string()),
                display_name: Some("Test User".to_string()),
                icon_url: None,
            },
            pub_key_cred_params: vec![PublicKeyCredParams {
                r#type: "public-key".to_string(),
                algorithms: -65535, // RS1 — unsupported
            }],
            exclude_list: vec![],
            extensions: None,
            options: MakeCredentialOptions {
                rk: false,
                uv: true,
                up: true,
                extended: false,
            },
            pin_protocol: None,
            enterprise_protections: None,
        };

        let result = authenticator.make_credential(request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(
            *err.downcast_ref::<Ctap2Error>().unwrap(),
            Ctap2Error::UnsupportedAlgorithm
        );
    }

    #[test]
    fn test_get_info_includes_algorithms() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let info = authenticator.get_info().unwrap();
        assert_eq!(info.algorithms.len(), 5);
        assert_eq!(info.algorithms[0].alg, -7);
        assert_eq!(info.algorithms[0].key_type, "public-key");
        assert_eq!(info.algorithms[1].alg, -8);
        assert_eq!(info.algorithms[1].key_type, "public-key");
        assert_eq!(info.algorithms[2].alg, -35);
        assert_eq!(info.algorithms[2].key_type, "public-key");
        assert_eq!(info.algorithms[3].alg, -37);
        assert_eq!(info.algorithms[3].key_type, "public-key");
        assert_eq!(info.algorithms[4].alg, -257);
        assert_eq!(info.algorithms[4].key_type, "public-key");
    }

    #[test]
    fn test_cose_key_rsa() {
        let n = vec![0xABu8; 256];
        let e = vec![0x01u8, 0x00, 0x01];
        let encoded = build_cose_key_rsa(&n, &e).unwrap();

        let map: BTreeMap<i64, Value> = decode_cbor(&encoded).unwrap();
        assert_eq!(map[&1], Value::Integer(Integer::from(3))); // kty = RSA
        assert_eq!(map[&3], Value::Integer(Integer::from(-257))); // alg = RS256
        match &map[&-1] {
            Value::Bytes(modulus) => assert_eq!(modulus.len(), 256),
            other => panic!("expected byte string for n, got {:?}", other),
        }
        match &map[&-2] {
            Value::Bytes(exponent) => assert_eq!(exponent.len(), 3),
            other => panic!("expected byte string for e, got {:?}", other),
        }
    }

    #[test]
    fn test_rs256_roundtrip() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let request = MakeCredentialRequest {
            client_data_hash: b"test".to_vec(),
            rp: RelyingParty {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
                icon: None,
            },
            user: User {
                id: b"user123".to_vec(),
                name: Some("testuser".to_string()),
                display_name: Some("Test User".to_string()),
                icon_url: None,
            },
            pub_key_cred_params: vec![PublicKeyCredParams {
                r#type: "public-key".to_string(),
                algorithms: -257,
            }],
            exclude_list: vec![],
            extensions: None,
            options: MakeCredentialOptions {
                rk: false,
                uv: true,
                up: true,
                extended: false,
            },
            pin_protocol: None,
            enterprise_protections: None,
        };

        authenticator.make_credential(request).unwrap();

        let credential = authenticator.get_storage().list_credentials()[0].clone();
        assert_eq!(credential.algorithm, -257);

        let client_data_hash = b"client data hash".to_vec();
        let assertion = authenticator
            .get_assertion(GetAssertionRequest {
                rp_id: "example.com".to_string(),
                client_data_hash: client_data_hash.clone(),
                allow_list: None,
                credentials: vec![CredentialDescriptor {
                    r#type: "public-key".to_string(),
                    id: credential.credential_id.clone(),
                    transports: None,
                }],
                extensions: None,
                options: GetAssertionOptions { up: true, uv: true },
                pin_protocol: None,
                uv: None,
            })
            .unwrap();

        let mut data_to_sign = Vec::new();
        data_to_sign.extend_from_slice(&assertion.auth_data[..32]);
        data_to_sign.extend_from_slice(&assertion.auth_data[32..37]);
        data_to_sign.extend_from_slice(&client_data_hash);

        authenticator
            .get_crypto()
            .verify_rsa(&credential.public_key, &data_to_sign, &assertion.signature)
            .unwrap();
    }

    fn attestation_request(algorithm: i32) -> MakeCredentialRequest {
        MakeCredentialRequest {
            client_data_hash: b"client data hash".to_vec(),
            rp: RelyingParty {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
                icon: None,
            },
            user: User {
                id: b"user123".to_vec(),
                name: Some("testuser".to_string()),
                display_name: Some("Test User".to_string()),
                icon_url: None,
            },
            pub_key_cred_params: vec![PublicKeyCredParams {
                r#type: "public-key".to_string(),
                algorithms: algorithm,
            }],
            exclude_list: vec![],
            extensions: None,
            options: MakeCredentialOptions {
                rk: false,
                uv: true,
                up: true,
                extended: false,
            },
            pin_protocol: None,
            enterprise_protections: None,
        }
    }

    #[test]
    fn test_make_credential_default_attestation_is_none() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let response = authenticator
            .make_credential(attestation_request(-8))
            .unwrap();

        assert_eq!(response.fmt, "none");
        assert!(response.attestation_info.is_empty());
    }

    #[test]
    fn test_make_credential_with_self_attestation() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        authenticator.set_attestation_format(AttestationFormat::Self_);

        let request = attestation_request(-8);
        let client_data_hash = request.client_data_hash.clone();
        let response = authenticator.make_credential(request).unwrap();

        assert_eq!(response.fmt, "self");
        assert!(response.attestation_info.contains_key(&2));
        assert!(response.attestation_info.contains_key(&3));
        assert_eq!(
            response.attestation_info[&3],
            Value::Integer(Integer::from(-8))
        );

        let signature = match &response.attestation_info[&2] {
            Value::Bytes(sig) => sig.clone(),
            other => panic!("expected byte string for sig, got {:?}", other),
        };

        let mut data_to_sign = Vec::new();
        data_to_sign.extend_from_slice(&response.auth_data);
        data_to_sign.extend_from_slice(&client_data_hash);

        let credential = authenticator.get_storage().list_credentials()[0].clone();
        assert!(authenticator
            .get_crypto()
            .verify(&data_to_sign, &signature, &credential.public_key)
            .unwrap());
    }

    #[test]
    fn test_make_credential_with_packed_attestation() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let (cert_private_key, _) = crypto.generate_key_pair().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        authenticator.set_attestation_format(AttestationFormat::Packed);
        authenticator.set_attestation_certificate(crate::attestation::AttestationCertificate {
            cert: vec![0x30, 0x82, 0x01, 0x00],
            private_key: cert_private_key,
        });

        let response = authenticator
            .make_credential(attestation_request(-8))
            .unwrap();

        assert_eq!(response.fmt, "packed");
        assert!(response.attestation_info.contains_key(&1));
        assert!(response.attestation_info.contains_key(&2));
        assert!(response.attestation_info.contains_key(&3));

        match &response.attestation_info[&1] {
            Value::Array(x5c) => assert_eq!(x5c.len(), 1),
            other => panic!("expected array for x5c, got {:?}", other),
        }
    }

    #[test]
    fn test_make_credential_packed_without_cert_is_self_attested() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        authenticator.set_attestation_format(AttestationFormat::Packed);

        let response = authenticator
            .make_credential(attestation_request(-7))
            .unwrap();

        assert_eq!(response.fmt, "packed");
        assert!(!response.attestation_info.contains_key(&1));
        assert!(response.attestation_info.contains_key(&2));
        assert_eq!(
            response.attestation_info[&3],
            Value::Integer(Integer::from(-7))
        );
    }

    #[test]
    fn test_make_credential_unsupported_attestation_format() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        authenticator.set_attestation_format(AttestationFormat::U2F);

        let result = authenticator.make_credential(attestation_request(-8));
        let error = result.expect_err("U2F attestation must not be supported");
        assert_eq!(
            error.downcast_ref::<Ctap2Error>().map(Ctap2Error::as_u8),
            Some(Ctap2Error::UnsupportedOption.as_u8())
        );
    }

    #[test]
    fn test_reset_full() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        authenticator
            .make_credential(MakeCredentialRequest {
                client_data_hash: b"test".to_vec(),
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
                    algorithms: -8,
                }],
                exclude_list: vec![],
                extensions: None,
                options: MakeCredentialOptions {
                    rk: false,
                    uv: true,
                    up: true,
                    extended: false,
                },
                pin_protocol: None,
                enterprise_protections: None,
            })
            .unwrap();

        assert!(!authenticator.get_storage().list_credentials().is_empty());

        let result = authenticator.process_command(0x07, vec![]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
        assert!(authenticator.get_storage().list_credentials().is_empty());
    }

    #[test]
    fn test_get_next_assertion() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        for i in 0..3u8 {
            authenticator
                .make_credential(MakeCredentialRequest {
                    client_data_hash: vec![i; 32],
                    rp: RelyingParty {
                        id: "example.com".to_string(),
                        name: None,
                        icon: None,
                    },
                    user: User {
                        id: vec![i; 8],
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
                        up: true,
                        extended: false,
                    },
                    pin_protocol: None,
                    enterprise_protections: None,
                })
                .unwrap();
        }

        assert_eq!(authenticator.get_storage().list_credentials().len(), 3);

        let get_assertion_req = GetAssertionRequest {
            rp_id: "example.com".to_string(),
            credentials: vec![],
            allow_list: None,
            client_data_hash: b"test".to_vec(),
            extensions: None,
            options: GetAssertionOptions {
                up: false,
                uv: true,
            },
            pin_protocol: None,
            uv: None,
        };

        let encoded = encode_cbor(&get_assertion_req).unwrap();
        let result = authenticator.process_command(0x02, encoded);
        assert!(result.is_ok());

        let result = authenticator.process_command(0x08, vec![]);
        assert!(result.is_ok());

        let result = authenticator.process_command(0x08, vec![]);
        assert!(result.is_ok());

        let result = authenticator.process_command(0x08, vec![]);
        assert!(matches!(result, Err(Ctap2Error::NoCredentials)));
    }

    #[test]
    fn test_get_next_assertion_without_state() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let result = authenticator.process_command(0x08, vec![]);
        assert!(matches!(result, Err(Ctap2Error::InvalidState)));
    }

    #[test]
    fn test_enumerate_rps_initial() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        for rp in &["example.com", "another.com"] {
            authenticator
                .make_credential(MakeCredentialRequest {
                    client_data_hash: b"test".to_vec(),
                    rp: RelyingParty {
                        id: rp.to_string(),
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
                        algorithms: -8,
                    }],
                    exclude_list: vec![],
                    extensions: None,
                    options: MakeCredentialOptions {
                        rk: false,
                        uv: true,
                        up: true,
                        extended: false,
                    },
                    pin_protocol: None,
                    enterprise_protections: None,
                })
                .unwrap();
        }

        let result = authenticator.process_command(0x3B, vec![]);
        assert!(result.is_ok());

        let response: EnumerateRPsResponse = decode_cbor(&result.unwrap()).unwrap();
        assert_eq!(response.total_rps, 2);
        assert!(!response.rp.id.is_empty());
        assert_eq!(response.rp_hash.len(), 32);
    }

    #[test]
    fn test_enumerate_rps_next() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        for rp in &["example.com", "another.com", "third.com"] {
            authenticator
                .make_credential(MakeCredentialRequest {
                    client_data_hash: b"test".to_vec(),
                    rp: RelyingParty {
                        id: rp.to_string(),
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
                        algorithms: -8,
                    }],
                    exclude_list: vec![],
                    extensions: None,
                    options: MakeCredentialOptions {
                        rk: false,
                        uv: true,
                        up: true,
                        extended: false,
                    },
                    pin_protocol: None,
                    enterprise_protections: None,
                })
                .unwrap();
        }

        let _ = authenticator.process_command(0x3B, vec![]);

        let result = authenticator.process_command(0x3C, vec![]);
        assert!(result.is_ok());
        let response: EnumerateRPsResponse = decode_cbor(&result.unwrap()).unwrap();
        assert_eq!(response.total_rps, 3);

        let result = authenticator.process_command(0x3C, vec![]);
        assert!(result.is_ok());

        let result = authenticator.process_command(0x3C, vec![]);
        assert!(matches!(result, Err(Ctap2Error::NoCredentials)));
    }

    #[test]
    fn test_enumerate_rps_empty() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let result = authenticator.process_command(0x3B, vec![]);
        assert!(matches!(result, Err(Ctap2Error::NoCredentials)));
    }

    #[test]
    fn test_bio_enroll_stub() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let bio_req = BioEnrollRequest {
            sub_command: 0x01,
            sub_command_params: None,
        };
        let encoded = encode_cbor(&bio_req).unwrap();
        let result = authenticator.process_command(0x09, encoded);
        assert!(matches!(result, Err(Ctap2Error::UnsupportedOption)));
    }

    #[test]
    fn test_bio_characteristics() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let bio_req = BioEnrollRequest {
            sub_command: 0x03,
            sub_command_params: None,
        };
        let encoded = encode_cbor(&bio_req).unwrap();
        let result = authenticator.process_command(0x09, encoded);
        assert!(result.is_ok());

        let response: BioEnrollResponse = decode_cbor(&result.unwrap()).unwrap();
        assert_eq!(response.fingerprint_kind, 1);
        assert_eq!(response.max_enrollments, 5);
    }

    #[test]
    fn test_enumerate_rps_next_without_initial() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let result = authenticator.process_command(0x3C, vec![]);
        assert!(matches!(result, Err(Ctap2Error::InvalidState)));
    }

    #[test]
    fn test_cose_key_p384() {
        let x = vec![0x11u8; 48];
        let y = vec![0x22u8; 48];
        let encoded = build_cose_key_p384(&x, &y).unwrap();

        let map: BTreeMap<i64, Value> = decode_cbor(&encoded).unwrap();
        assert_eq!(map[&1], Value::Integer(Integer::from(2))); // kty = EC2
        assert_eq!(map[&3], Value::Integer(Integer::from(-35))); // alg = ES384
        assert_eq!(map[&-1], Value::Integer(Integer::from(2))); // crv = P-384
        match &map[&-2] {
            Value::Bytes(bx) => assert_eq!(bx.len(), 48),
            other => panic!("expected byte string for x, got {:?}", other),
        }
        match &map[&-3] {
            Value::Bytes(by) => assert_eq!(by.len(), 48),
            other => panic!("expected byte string for y, got {:?}", other),
        }
    }

    #[test]
    fn test_cose_key_rsa_pss() {
        let n = vec![0xCCu8; 256];
        let e = vec![0x01u8, 0x00, 0x01];
        let encoded = build_cose_key_rsa_pss(&n, &e).unwrap();

        let map: BTreeMap<i64, Value> = decode_cbor(&encoded).unwrap();
        assert_eq!(map[&1], Value::Integer(Integer::from(3))); // kty = RSA
        assert_eq!(map[&3], Value::Integer(Integer::from(-37))); // alg = PS256
    }

    #[test]
    fn test_es384_make_and_get_assertion_roundtrip() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let make_req = MakeCredentialRequest {
            client_data_hash: vec![0xAA; 32],
            rp: RelyingParty {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
                icon: None,
            },
            user: User {
                id: b"user-es384".to_vec(),
                name: Some("user@example.com".to_string()),
                display_name: Some("ES384 User".to_string()),
                icon_url: None,
            },
            pub_key_cred_params: vec![PublicKeyCredParams {
                r#type: "public-key".to_string(),
                algorithms: -35, // ES384
            }],
            exclude_list: vec![],
            extensions: None,
            options: MakeCredentialOptions {
                rk: true,
                uv: false,
                up: false,
                extended: false,
            },
            pin_protocol: None,
            enterprise_protections: None,
        };

        let resp = authenticator.make_credential(make_req).unwrap();
        assert!(!resp.auth_data.is_empty());

        let get_req = GetAssertionRequest {
            rp_id: "example.com".to_string(),
            client_data_hash: vec![0xBB; 32],
            credentials: vec![],
            allow_list: None,
            extensions: None,
            options: GetAssertionOptions {
                uv: false,
                up: false,
            },
            pin_protocol: None,
            uv: None,
        };

        let assert_resp = authenticator.get_assertion(get_req).unwrap();
        assert!(!assert_resp.signature.is_empty());
    }

    #[test]
    fn test_ps256_make_and_get_assertion_roundtrip() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let make_req = MakeCredentialRequest {
            client_data_hash: vec![0xAA; 32],
            rp: RelyingParty {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
                icon: None,
            },
            user: User {
                id: b"user-ps256".to_vec(),
                name: Some("user@example.com".to_string()),
                display_name: Some("PS256 User".to_string()),
                icon_url: None,
            },
            pub_key_cred_params: vec![PublicKeyCredParams {
                r#type: "public-key".to_string(),
                algorithms: -37, // PS256
            }],
            exclude_list: vec![],
            extensions: None,
            options: MakeCredentialOptions {
                rk: true,
                uv: false,
                up: false,
                extended: false,
            },
            pin_protocol: None,
            enterprise_protections: None,
        };

        let resp = authenticator.make_credential(make_req).unwrap();
        assert!(!resp.auth_data.is_empty());

        let get_req = GetAssertionRequest {
            rp_id: "example.com".to_string(),
            client_data_hash: vec![0xBB; 32],
            credentials: vec![],
            allow_list: None,
            extensions: None,
            options: GetAssertionOptions {
                uv: false,
                up: false,
            },
            pin_protocol: None,
            uv: None,
        };

        let assert_resp = authenticator.get_assertion(get_req).unwrap();
        assert!(!assert_resp.signature.is_empty());
    }

    #[test]
    fn test_large_blobs_command_read_write() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        // 1. Write 64 bytes at offset 0 with expected_length 64
        let test_blob = vec![0x42u8; 64];
        let write_req = large_blobs::LargeBlobsRequest {
            offset: 0,
            get: None,
            set: Some(test_blob.clone()),
            length: Some(64),
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let write_bytes = encode_cbor(&write_req).unwrap();
        let write_res = authenticator.process_command(0x0C, write_bytes).unwrap();
        let write_resp: large_blobs::LargeBlobsResponse = decode_cbor(&write_res).unwrap();
        assert!(write_resp.config.is_none());

        // 2. Read 32 bytes at offset 16
        let read_req = large_blobs::LargeBlobsRequest {
            offset: 16,
            get: Some(32),
            set: None,
            length: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let read_bytes = encode_cbor(&read_req).unwrap();
        let read_res = authenticator.process_command(0x0C, read_bytes).unwrap();
        let read_resp: large_blobs::LargeBlobsResponse = decode_cbor(&read_res).unwrap();
        assert_eq!(read_resp.config, Some(vec![0x42u8; 32]));
    }

    #[test]
    fn test_credential_management_full_flow() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        // Create 2 credentials
        let make_req1 = MakeCredentialRequest {
            client_data_hash: vec![0x11; 32],
            rp: RelyingParty {
                id: "rp1.com".to_string(),
                name: Some("RP 1".to_string()),
                icon: None,
            },
            user: User {
                id: b"user1".to_vec(),
                name: Some("user1@rp1.com".to_string()),
                display_name: Some("User One".to_string()),
                icon_url: None,
            },
            pub_key_cred_params: vec![PublicKeyCredParams {
                r#type: "public-key".to_string(),
                algorithms: -8,
            }],
            exclude_list: vec![],
            extensions: Some(Extensions {
                large_blob_key: true,
                ..Default::default()
            }),
            options: MakeCredentialOptions {
                rk: true,
                uv: false,
                up: false,
                extended: false,
            },
            pin_protocol: None,
            enterprise_protections: None,
        };
        let cred1_resp = authenticator.make_credential(make_req1).unwrap();
        let ext1 = cred1_resp.extensions.unwrap();
        assert!(ext1.large_blob_key.is_some());

        // 1. Get metadata
        let meta_req = cred_mgmt::CredentialManagementRequest {
            sub_command: cred_mgmt::sub_commands::GET_CREDS_METADATA,
            sub_command_params: None,
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
        };
        let meta_bytes = encode_cbor(&meta_req).unwrap();
        let meta_res = authenticator.process_command(0x0A, meta_bytes).unwrap();
        let meta_resp: cred_mgmt::CredsMetadataResponse = decode_cbor(&meta_res).unwrap();
        assert_eq!(meta_resp.existing_resident_credentials_count, 1);

        // 2. Enumerate RPs
        let enum_rp_req = cred_mgmt::CredentialManagementRequest {
            sub_command: cred_mgmt::sub_commands::ENUMERATE_RPS_BEGIN,
            sub_command_params: None,
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
        };
        let enum_rp_bytes = encode_cbor(&enum_rp_req).unwrap();
        let enum_rp_res = authenticator.process_command(0x0A, enum_rp_bytes).unwrap();
        let enum_rp_resp: cred_mgmt::EnumerateRpsEntryResponse = decode_cbor(&enum_rp_res).unwrap();
        assert_eq!(enum_rp_resp.total_rps, 1);
        assert_eq!(enum_rp_resp.rp.id, "rp1.com");

        // 3. Enumerate credentials for rp1.com
        let enum_cred_req = cred_mgmt::CredentialManagementRequest {
            sub_command: cred_mgmt::sub_commands::ENUMERATE_CREDENTIALS_BEGIN,
            sub_command_params: Some(cred_mgmt::CredMgmtParams {
                rp_id_hash: Some(enum_rp_resp.rp_id_hash.clone()),
                credential_id: None,
                user: None,
            }),
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
        };
        let enum_cred_bytes = encode_cbor(&enum_cred_req).unwrap();
        let enum_cred_res = authenticator
            .process_command(0x0A, enum_cred_bytes)
            .unwrap();
        let enum_cred_resp: cred_mgmt::EnumerateCredentialsEntryResponse =
            decode_cbor(&enum_cred_res).unwrap();
        assert_eq!(enum_cred_resp.total_credentials, 1);
        assert_eq!(enum_cred_resp.user.name, Some("user1@rp1.com".to_string()));
        assert!(enum_cred_resp.large_blob_key.is_some());

        // 4. Update user info
        let update_req = cred_mgmt::CredentialManagementRequest {
            sub_command: cred_mgmt::sub_commands::UPDATE_USER_INFORMATION,
            sub_command_params: Some(cred_mgmt::CredMgmtParams {
                rp_id_hash: None,
                credential_id: Some(enum_cred_resp.credential_id.clone()),
                user: Some(User {
                    id: b"user1".to_vec(),
                    name: Some("updated@rp1.com".to_string()),
                    display_name: Some("Updated Name".to_string()),
                    icon_url: None,
                }),
            }),
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
        };
        let update_bytes = encode_cbor(&update_req).unwrap();
        let update_res = authenticator.process_command(0x0A, update_bytes).unwrap();
        assert!(update_res.is_empty());

        // 5. Delete credential
        let del_req = cred_mgmt::CredentialManagementRequest {
            sub_command: cred_mgmt::sub_commands::DELETE_CREDENTIAL,
            sub_command_params: Some(cred_mgmt::CredMgmtParams {
                rp_id_hash: None,
                credential_id: Some(enum_cred_resp.credential_id),
                user: None,
            }),
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
        };
        let del_bytes = encode_cbor(&del_req).unwrap();
        let del_res = authenticator.process_command(0x0A, del_bytes).unwrap();
        assert!(del_res.is_empty());
        assert_eq!(authenticator.get_storage().get_credentials_count(), 0);
    }
}
