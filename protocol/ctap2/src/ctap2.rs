use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use ciborium::de::from_reader;
use ciborium::ser::into_writer;
use ciborium::value::Integer;
use ciborium::Value;
use crypto::CryptoEngine;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use storage::{Credential, StorageEngine, CRED_PROTECT_UV_REQUIRED, MAX_LARGE_BLOBS_SIZE};

extern crate alloc;

use crate::attestation::{AttestationFormat, PackedAttestation, SelfAttestation};
use crate::client_pin;
use crate::cred_mgmt;
use crate::hmac_secret;
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
    #[serde(rename = "excludeList", default)]
    pub exclude_list: Vec<CredentialDescriptor>,
    pub extensions: Option<Extensions>,
    #[serde(default)]
    pub options: MakeCredentialOptions,
    /// MAC do `clientDataHash` produzido pelo `pinUvAuthToken`.
    #[serde(
        with = "serde_bytes",
        rename = "pinUvAuthParam",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pin_uv_auth_param: Option<Vec<u8>>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(rename = "icon", skip_serializing_if = "Option::is_none")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// Helpers serde para campos `Option<Vec<u8>>` que representam byte strings
/// CBOR.
///
/// `#[serde(with = "serde_bytes")]` sobre um campo opcional deserializa via
/// `Option<Vec<u8>>::deserialize`, que chega ao formato CBOR como sequência
/// (`deserialize_seq`) — o ciborium rejeita uma byte string nesse caminho e
/// a requisição vira `InvalidCbor`. O módulo abaixo força o caminho correto:
/// `deserialize_option` seguido de `deserialize_byte_buf`.
mod serde_bytes_opt {
    extern crate alloc;
    use alloc::vec::Vec;
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_bytes::ByteBuf;

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Option::<ByteBuf>::deserialize(deserializer)?.map(ByteBuf::into_vec))
    }

    pub(super) fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_some(&ByteBuf::from(bytes.as_slice())),
            None => serializer.serialize_none(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Extensions {
    // Campos opcionais exigem `default` explícito quando usam helper serde.
    /// Nível cru da extensão `credProtect` (CTAP 2.1 §12.2.2). O wire codifica
    /// um inteiro CBOR (1..3), não um enum com tags — portanto o campo é
    /// `u8` e a conversão para [`CredProtectPolicy`] acontece nos pontos de
    /// uso via [`From<u8>`].
    #[serde(rename = "credProtect", default)]
    pub cred_protect: Option<u8>,
    /// Blob customizado da credencial (`credBlob`, byte string CBOR).
    #[serde(with = "serde_bytes_opt", rename = "credBlob", default)]
    pub cred_blob: Option<Vec<u8>>,
    #[serde(rename = "minPinLength", default)]
    pub min_pin_length: bool,
    /// Entrada bruta da extensão `hmac-secret` (CTAP 2.1 §12.5): booleano no
    /// MakeCredential ou mapa `{1: keyAgreement, 2: saltEnc, 3: saltAuth,
    /// 4: pinUvAuthProtocol}` no GetAssertion. Interpretada por
    /// [`crate::hmac_secret`].
    #[serde(
        rename = "hmac-secret",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hmac_secret: Option<Value>,
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

/// Opções do comando MakeCredential (mapa `options` do CTAP2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MakeCredentialOptions {
    /// Resident key — credencial armazenada no autenticador.
    #[serde(default)]
    pub rk: bool,
    /// User verification — exigir PIN/biometria.
    #[serde(default)]
    pub uv: bool,
    /// User presence — exigir toque físico. Ausente ⇒ verdadeiro (CTAP 2.0 §5.1).
    #[serde(default = "default_true")]
    pub up: bool,
    /// Estendido — inclui dados adicionais no authData.
    #[serde(rename = "att", default)]
    pub extended: bool,
}

impl Default for MakeCredentialOptions {
    fn default() -> Self {
        Self {
            rk: false,
            uv: false,
            up: true,
            extended: false,
        }
    }
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
    // Campos opcionais exigem `default` explícito quando usam helper serde:
    // respostas podem carregar apenas um subconjunto das extensões.
    #[serde(rename = "credProtect", default)]
    pub cred_protect: Option<u8>,
    /// Comprimento mínimo de PIN aceito (extensão `minPinLength`).
    #[serde(rename = "minPinLength", default)]
    pub min_pin_length: Option<u32>,
    /// Blob customizado da credencial (extensão `credBlob`).
    #[serde(
        with = "serde_bytes",
        rename = "credBlob",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cred_blob: Option<Vec<u8>>,
    /// Segredo HMAC compartilhado (extensão `hmac-secret`): saída booleana
    /// no MakeCredential ou bytes cifrados sob o segredo compartilhado no
    /// GetAssertion (CTAP 2.1 §12.5).
    #[serde(rename = "hmac-secret", default)]
    pub hmac_secret: Option<Value>,
    /// Chave simétrica associada à credencial (extensão `largeBlobKey`).
    #[serde(
        with = "serde_bytes",
        rename = "largeBlobKey",
        default,
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
    #[serde(rename = "allowList", default)]
    pub credentials: Vec<CredentialDescriptor>,
    /// Alias interno legado; não é serializado no wire format.
    #[serde(skip)]
    pub allow_list: Option<Vec<CredentialDescriptor>>,
    /// Hash dos clientData JSON.
    #[serde(with = "serde_bytes", rename = "clientDataHash")]
    pub client_data_hash: Vec<u8>,
    /// Extensões WebAuthn ativas.
    pub extensions: Option<Extensions>,
    /// Opções do comando. Mapa ausente no request ⇒ default da spec.
    #[serde(default)]
    pub options: GetAssertionOptions,
    /// MAC do `clientDataHash` produzido pelo `pinUvAuthToken`.
    #[serde(
        with = "serde_bytes",
        rename = "pinUvAuthParam",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pin_uv_auth_param: Option<Vec<u8>>,
    /// Versão do protocolo PIN/UV auth.
    #[serde(rename = "pinUvAuthProtocol")]
    pub pin_protocol: Option<u8>,
    /// Indica se user verification foi realizada.
    pub uv: Option<bool>,
}

/// Opções do comando GetAssertion.
///
/// Campos ausentes no mapa `options` recebem os defaults da spec
/// (CTAP 2.1 §6.8.3): `up=true`, `uv=false`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAssertionOptions {
    /// User presence — exigir toque físico. Ausente ⇒ verdadeiro.
    #[serde(default = "default_true")]
    pub up: bool,
    /// User verification — exigir PIN/biometria. Ausente ⇒ falso.
    #[serde(default)]
    pub uv: bool,
}

fn default_true() -> bool {
    true
}

impl Default for GetAssertionOptions {
    fn default() -> Self {
        Self {
            up: true,
            uv: false,
        }
    }
}

/// Resposta do comando GetAssertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAssertionResponse {
    /// Credencial utilizada na assertion.
    #[serde(rename = "credential", skip_serializing_if = "Option::is_none")]
    pub credential: Option<CredentialDescriptor>,
    /// Authenticator Data CBOR serializado.
    #[serde(with = "serde_bytes", rename = "authData")]
    pub auth_data: Vec<u8>,
    /// Assinatura sobre `authData || clientDataHash`.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// Dados do usuário (quando credencial é discoverable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<User>,
    /// Total de credenciais encontradas (multi-assertion).
    #[serde(rename = "numberOfCredentials", skip_serializing_if = "Option::is_none")]
    pub number_of_credentials: Option<u16>,
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
    /// Protocolos PIN/UV suportados (e.g. `[1, 2]`).
    #[serde(rename = "pinUvAuthProtocols", default)]
    pub pin_uv_auth_protocols: Vec<u8>,
    /// Tamanho máximo de mensagem CTAP suportado.
    #[serde(default)]
    pub max_msg_size: u32,
    /// Número de relying parties com credenciais armazenadas (interno).
    #[serde(skip_serializing, default)]
    pub rp_count: u32,
    /// Comprimento máximo de credBlob em bytes.
    pub max_cred_blob_length: u32,
    /// Comprimento máximo de credential ID em bytes.
    pub max_credential_id_length: u16,
    /// Número máximo de credenciais residentes.
    pub max_credential_count: u16,
    /// Versão numérica do firmware no formato CTAP 2.1 (`firmwareVersion`).
    pub firmware_version: u32,
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
    /// AuthenticatorConfig (0x0D) — opções de configuração do autenticador.
    AuthenticatorConfig = 0x0D,
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
            0x0D => Ctap2Command::AuthenticatorConfig,
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
    /// Parâmetro obrigatório ausente.
    MissingParameter = 0x14,
    /// Payload CBOR malformado.
    InvalidCbor = 0x12,
    /// Comando inválido no estado atual (CTAP2_ERR_NOT_ALLOWED).
    ///
    /// 0x30 é o código da spec para operação não permitida no estado corrente
    /// (ex.: GetNextAssertion sem GetAssertion prévio). NÃO usar 0x05: na
    /// tabela CTAP esse valor significa CTAP1_ERR_TIMEOUT e hosts reais
    /// (python-fido2, Chrome, libfido2) o interpretam como timeout.
    InvalidState = 0x30,
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
    /// PIN incorreto (CTAP2_ERR_PIN_INVALID).
    PinInvalid = 0x31,
    /// PIN bloqueado após esgotar as tentativas (CTAP2_ERR_PIN_BLOCKED).
    PinBlocked = 0x32,
    /// Falha na verificação de `pinUvAuthParam` (CTAP2_ERR_PIN_AUTH_INVALID).
    PinAuthInvalid = 0x33,
    /// Autenticação de PIN bloqueada; requer power cycle (CTAP2_ERR_PIN_AUTH_BLOCKED).
    PinAuthBlocked = 0x34,
    /// Nenhum PIN configurado (CTAP2_ERR_PIN_NOT_SET).
    PinNotSet = 0x35,
    /// Um pinUvAuthToken é necessário (CTAP2_ERR_PUAT_REQUIRED / PIN_REQUIRED).
    PinRequired = 0x36,
    /// PIN viola política de segurança (CTAP2_ERR_PIN_POLICY_VIOLATION).
    PinPolicyViolation = 0x37,
    /// Token de autenticação expirado (CTAP2_ERR_PIN_TOKEN_EXPIRED).
    PinTokenExpired = 0x38,
    /// `permissions` contém permissão não autorizada (CTAP2_ERR_UNAUTHORIZED_PERMISSION).
    UnauthorizedPermission = 0x40,
    /// Verificação de usuário embutida desabilitada (CTAP2_ERR_UV_BLOCKED).
    UvBlocked = 0x3C,
    /// Token pendente de aprovação do usuário.
    PinTokenPending = 0x23,

    /// Request excede o tamanho máximo permitido.
    RequestTooLarge = 0x39,
    /// Array de large blobs está cheio ou excede o limite máximo.
    LargeBlobStorageFull = 0x18,
    /// Erro interno não categorizado (CTAP2 "unspecified failure").
    ///
    /// 0x7F é o único código seguro para falhas internas (ex.: falha ao
    /// codificar a resposta): hosts reais tratam como falha genérica. NÃO
    /// usar 0x04, que na tabela CTAP significa CTAP1_ERR_INVALID_SEQ e é
    /// interpretado como erro da camada de transporte.
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

impl core::error::Error for Ctap2Error {}

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
fn ctap2_error(error: Box<dyn core::error::Error>) -> Ctap2Error {
    error
        .downcast_ref::<Ctap2Error>()
        .copied()
        .unwrap_or(Ctap2Error::Unknown)
}

pub const AAGUID: [u8; 16] = [0u8; 16];

/// Chave do contador global de assinaturas no key-value store.
///
/// Compartilhado por todas as credenciais: cada GetAssertion/GetNextAssertion
/// o incrementa e persiste, para que asserções sucessivas nunca repitam valor
/// (mecanismo WebAuthn contra clonagem do autenticador).
const SIGN_COUNTER_STORAGE_KEY: &str = "global_sign_count";

const FIRMWARE_VERSION_COMPONENT_BASE: u32 = 1_000;

/// Política `credProtect` de nível 2 (CTAP 2.1 §12.2.2):
/// descobrível sem UV somente quando nomeada na allowList da requisição.
const CRED_PROTECT_ALLOWLIST_REQUIRED: u8 =
    CredProtectPolicy::UserVerificationOptionalWithCredentialIDList as u8;

/// Converte o núcleo numérico de uma versão semântica para `firmwareVersion`.
///
/// CTAP 2.1 deixa a codificação do inteiro a cargo do fabricante. Cada
/// componente `major.minor.patch` ocupa três dígitos decimais, preservando a
/// ordem e evitando colisões para componentes entre 0 e 999. Sufixos de
/// pré-lançamento ou build não são representáveis e, portanto, são ignorados.
fn firmware_version_to_ctap_integer(version: &str) -> Result<u32, Ctap2Error> {
    let numeric_core = version.split(['-', '+']).next().unwrap_or(version);
    let mut components = numeric_core.split('.');
    let parse_component = |component: Option<&str>| {
        component
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|value| *value < FIRMWARE_VERSION_COMPONENT_BASE)
            .ok_or(Ctap2Error::Unknown)
    };

    let major = parse_component(components.next())?;
    let minor = parse_component(components.next())?;
    let patch = parse_component(components.next())?;
    if components.next().is_some() {
        return Err(Ctap2Error::Unknown);
    }

    major
        .checked_mul(FIRMWARE_VERSION_COMPONENT_BASE.pow(2))
        .and_then(|value| value.checked_add(minor * FIRMWARE_VERSION_COMPONENT_BASE))
        .and_then(|value| value.checked_add(patch))
        .ok_or(Ctap2Error::Unknown)
}

fn hash_rp_id(rp_id: &str, crypto: &CryptoEngine) -> [u8; 32] {
    let result = crypto.sha256(rp_id.as_bytes());
    let mut rp_hash = [0u8; 32];
    rp_hash.copy_from_slice(&result);
    rp_hash
}

/// Retorna timestamp atual em milissegundos desde UNIX_EPOCH quando `std` está ativo.
///
/// Em alvos `no_std` (sem `std`) retorna `0` como fallback determinístico,
/// preservando compatibilidade: o pruning cai em ordem de inserção arbitrária
/// mas não quebra. Quando `std` está disponível (`host`, testes, simulador),
/// o valor real alimenta `prune_oldest_credential` para LRU correto.
///
/// Garantia de monotonicidade híbrida: combina millis do sistema com um contador
/// atômico para que duas credenciais criadas dentro do mesmo milissegundo não
/// colidam (`created_at`). Usa `max(last+1, millis)` com CAS loop, garantindo
/// ordem total estrita mesmo sob chamadas concorrentes ou clock skew.
#[cfg(feature = "std")]
fn current_timestamp() -> u64 {
    use core::sync::atomic::{AtomicU64, Ordering};
    static LAST_TS: AtomicU64 = AtomicU64::new(0);
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut prev = LAST_TS.load(Ordering::Relaxed);
    loop {
        let candidate = if millis > prev { millis } else { prev + 1 };
        match LAST_TS.compare_exchange_weak(prev, candidate, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return candidate,
            Err(actual) => prev = actual,
        }
    }
}

#[cfg(not(feature = "std"))]
fn current_timestamp() -> u64 {
    0
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
            // CTAP GetInfo encodes options as a map of capability names to
            // booleans. The public model stores enabled names as a Vec, so
            // adapt only this wire boundary instead of exposing a breaking API.
            let val = if type_name.contains("GetInfoResponse") {
                let is_options = if encode {
                    matches!(&key, Value::Text(name) if name == "options")
                } else {
                    matches!(&key, Value::Integer(n) if *n == 4.into())
                };
                if is_options {
                    if encode {
                        match val {
                            Value::Array(names)
                                if names.iter().all(|v| matches!(v, Value::Text(_))) =>
                            {
                                let mut entries: Vec<(Value, Value)> = names
                                    .into_iter()
                                    .filter_map(|name| match name {
                                        Value::Text(name) => {
                                            Some((Value::Text(name), Value::Bool(true)))
                                        }
                                        _ => None,
                                    })
                                    .collect();
                                // CTAP 2.0 / 2.1 §6.4: se clientPin não foi incluído como true
                                // (porque nenhum PIN está configurado), deve ser emitido como false
                                // para anunciar a capacidade do dispositivo de receber um PIN quando
                                // pinUvAuthToken está habilitado.
                                if entries
                                    .iter()
                                    .any(|(k, _)| matches!(k, Value::Text(name) if name == "pinUvAuthToken"))
                                    && !entries
                                        .iter()
                                        .any(|(k, _)| matches!(k, Value::Text(name) if name == "clientPin"))
                                {
                                    entries.push((
                                        Value::Text("clientPin".to_string()),
                                        Value::Bool(false),
                                    ));
                                }
                                Value::Map(entries)
                            }
                            other => other,
                        }
                    } else {
                        match val {
                            Value::Map(options)
                                if options.iter().all(|(_, v)| matches!(v, Value::Bool(_))) =>
                            {
                                Value::Array(
                                    options
                                        .into_iter()
                                        .filter_map(|(name, enabled)| match (name, enabled) {
                                            (Value::Text(name), Value::Bool(true)) => {
                                                Some(Value::Text(name))
                                            }
                                            _ => None,
                                        })
                                        .collect(),
                                )
                            }
                            other => other,
                        }
                    }
                } else {
                    val
                }
            } else if type_name.contains("CredentialManagementRequest") {
                let is_params = if encode {
                    matches!(&key, Value::Text(name) if name == "subCommandParams")
                } else {
                    matches!(&key, Value::Integer(n) if *n == 2.into())
                };
                if is_params {
                    if let Value::Map(params) = val {
                        Value::Map(
                            params
                                .into_iter()
                                .map(|(pk, pv)| {
                                    if encode {
                                        if let Value::Text(pname) = pk {
                                            let plabel = match pname.as_str() {
                                                "rpIDHash" => Some(1),
                                                "credentialId" => Some(2),
                                                "user" => Some(3),
                                                _ => None,
                                            };
                                            if let Some(n) = plabel {
                                                (Value::Integer(n.into()), pv)
                                            } else {
                                                (Value::Text(pname), pv)
                                            }
                                        } else {
                                            (pk, pv)
                                        }
                                    } else if let Value::Integer(pn) = pk {
                                        let pname = match i64::try_from(pn).ok() {
                                            Some(1) => Some("rpIDHash"),
                                            Some(2) => Some("credentialId"),
                                            Some(3) => Some("user"),
                                            _ => None,
                                        };
                                        if let Some(s) = pname {
                                            (Value::Text(s.to_string()), pv)
                                        } else {
                                            (Value::Integer(pn), pv)
                                        }
                                    } else {
                                        (pk, pv)
                                    }
                                })
                                .collect(),
                        )
                    } else {
                        val
                    }
                } else {
                    val
                }
            } else {
                val
            };
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
                        t if t.contains("GetInfoResponse") && name == "max_msg_size" => Some(0x05),
                        t if t.contains("GetInfoResponse") && name == "max_credential_count" => {
                            Some(0x07)
                        }
                        t if t.contains("GetInfoResponse")
                            && name == "max_credential_id_length" =>
                        {
                            Some(0x08)
                        }
                        t if t.contains("GetInfoResponse") && name == "firmware_version" => {
                            Some(0x0E)
                        }
                        t if t.contains("GetInfoResponse") && name == "max_cred_blob_length" => {
                            Some(0x0F)
                        }
                        t if t.contains("GetInfoResponse") && name == "maxLargeBlobDataSize" => {
                            Some(0x0B)
                        }
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
                        t if t.contains("EnumerateRpsEntryResponse") && name == "rp" => Some(0x03),
                        t if t.contains("EnumerateRpsEntryResponse") && name == "rpIDHash" => {
                            Some(0x04)
                        }
                        t if t.contains("EnumerateRpsEntryResponse") && name == "totalRPs" => {
                            Some(0x05)
                        }
                        t if t.contains("EnumerateCredentialsEntryResponse") && name == "user" => {
                            Some(0x06)
                        }
                        t if t.contains("EnumerateCredentialsEntryResponse")
                            && name == "credentialId" =>
                        {
                            Some(0x07)
                        }
                        t if t.contains("EnumerateCredentialsEntryResponse")
                            && name == "publicKey" =>
                        {
                            Some(0x08)
                        }
                        t if t.contains("EnumerateCredentialsEntryResponse")
                            && name == "totalCredentials" =>
                        {
                            Some(0x09)
                        }
                        t if t.contains("EnumerateCredentialsEntryResponse")
                            && name == "credProtect" =>
                        {
                            Some(0x0A)
                        }
                        t if t.contains("EnumerateCredentialsEntryResponse")
                            && name == "largeBlobKey" =>
                        {
                            Some(0x0B)
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
                            "max_credential_count",
                            "max_credential_id_length",
                            "",
                            "algorithms",
                            "maxLargeBlobDataSize",
                            "",
                            "",
                            "firmware_version",
                            "max_cred_blob_length",
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
                        t if t.contains("EnumerateRpsEntryResponse") => match n {
                            0x03 => Some("rp"),
                            0x04 => Some("rpIDHash"),
                            0x05 => Some("totalRPs"),
                            _ => None,
                        },
                        t if t.contains("EnumerateCredentialsEntryResponse") => match n {
                            0x06 => Some("user"),
                            0x07 => Some("credentialId"),
                            0x08 => Some("publicKey"),
                            0x09 => Some("totalCredentials"),
                            0x0A => Some("credProtect"),
                            0x0B => Some("largeBlobKey"),
                            _ => None,
                        },
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

fn canonicalize_cbor(value: Value) -> Value {
    match value {
        Value::Map(entries) => {
            let mut canonical_entries: Vec<(Value, Value, Vec<u8>)> = entries
                .into_iter()
                .filter_map(|(k, v)| {
                    // No CTAP2, campos ausentes/nulos NUNCA devem aparecer no mapa wire CBOR.
                    if matches!(v, Value::Null) {
                        return None;
                    }
                    let k_canon = canonicalize_cbor(k);
                    let v_canon = canonicalize_cbor(v);
                    if matches!(v_canon, Value::Null) {
                        return None;
                    }
                    let mut k_bytes = alloc::vec![];
                    let _ = into_writer(&k_canon, &mut k_bytes);
                    Some((k_canon, v_canon, k_bytes))
                })
                .collect();

            // RFC 7049 §3.9 / CTAP2 §6: Ordenação canônica por menor comprimento primeiro,
            // e desempate por comparação léxica de bytes.
            canonical_entries.sort_by(|(_, _, a_bytes), (_, _, b_bytes)| {
                a_bytes.len().cmp(&b_bytes.len()).then_with(|| a_bytes.cmp(b_bytes))
            });

            Value::Map(
                canonical_entries
                    .into_iter()
                    .map(|(k, v, _)| (k, v))
                    .collect(),
            )
        }
        Value::Array(entries) => {
            Value::Array(entries.into_iter().map(canonicalize_cbor).collect())
        }
        other => other,
    }
}

pub fn encode_cbor<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Ctap2Error> {
    let mut raw = Vec::new();
    ciborium::ser::into_writer(value, &mut raw).map_err(|_| Ctap2Error::Unknown)?;
    let parsed: Value = from_reader(raw.as_slice()).map_err(|_| Ctap2Error::Unknown)?;
    let normalized = root_ctap_keys(parsed, true, core::any::type_name::<T>());
    let canonical = canonicalize_cbor(normalized);
    let mut buf = alloc::vec![];
    into_writer(&canonical, &mut buf).map_err(|_| Ctap2Error::Unknown)?;
    Ok(buf)
}

pub fn decode_cbor<T: DeserializeOwned>(data: &[u8]) -> Result<T, Ctap2Error> {
    // A fatia é o próprio leitor (`ciborium_io::Read for &[u8]`, também via
    // blanket em host); após decodificar, `restante` guarda os bytes não
    // consumidos — equivalente ao `Cursor::position()` do modo host.
    let mut restante = data;
    let parsed: Value = from_reader(&mut restante).map_err(|_| Ctap2Error::InvalidCbor)?;
    if !restante.is_empty() {
        return Err(Ctap2Error::InvalidCbor);
    }
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
    pub pin_uv_auth_protocols: Vec<u8>,
    pub security: SecurityFeatures,
    pub max_large_blob_data_size: Option<u32>,
}

impl Default for Ctap2Capabilities {
    fn default() -> Self {
        Self {
            aaguid: AAGUID,
            versions: vec!["FIDO_2_0".to_string(), "FIDO_2_1".to_string()],
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
            pin_uv_auth_protocols: vec![1, 2],
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

/// Verificação de usuário embutida (ponto de injeção de mock de host).
///
/// Espelha [`UserPresence`]: o firmware de produção não tem hardware de
/// biometria/PIN-pad, então `user_verification` permanece `None` por padrão
/// e os subcomandos ClientPIN que exigem UV embutida continuam retornando
/// `UvBlocked`/`UnsupportedOption`. Hosts e testes podem injetar um mock via
/// [`Ctap2Authenticator::set_user_verification`]; o anúncio da option `uv` no
/// GetInfo exige adicionalmente a capability `uv`
/// (ver [`Ctap2Authenticator::get_info`]).
pub trait UserVerification: core::fmt::Debug + Send + Sync {
    /// Executa a verificação de usuário embutida; `Err` indica que o
    /// usuário não foi verificado (ex.: tentativas esgotadas).
    fn verify(&mut self) -> Result<(), Ctap2Error>;
    /// Tentativas restantes de UV embutida, reportadas pelo `getUVRetries` (0x07).
    fn retries(&self) -> u8;
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
    user_verification: Option<Box<dyn UserVerification>>,
    pin_uv_auth_token: Option<client_pin::PinUvAuthTokenState>,
    pin_agreement_key: Option<crypto::pin_protocol::PinAgreementKey>,
    pin_shared_secret: Option<(crypto::pin_protocol::Zeroizing<Vec<u8>>, u8)>,
    /// Sessão hmac-secret da transação corrente (ADR-0022): guarda o segredo
    /// compartilhado e os salts decifrados da asserção inicial com a extensão,
    /// para produzir a saída de cada asserção encadeada. Vive apenas em
    /// memória, pela duração de uma transação de user presence; é descartada
    /// por qualquer comando que não seja GetNextAssertion, ao fim da cadeia ou
    /// no Reset (Zeroizing apaga o material no drop).
    hmac_secret_session: Option<hmac_secret::HmacSecretSession>,
    /// Falhas consecutivas de PIN na sessão atual, base do bloqueio volátil
    /// `PIN_AUTH_BLOCKED`. Volátil por definição: nasce zerado em cada
    /// instância (um power cycle encerra o bloqueio — CTAP 2.1 §6.5.5.6).
    pin_failures_since_reset: u8,
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
    /// Hash do clientData assinado na asserção inicial; cada GetNextAssertion
    /// assina `authData || clientDataHash` com o mesmo valor (CTAP2 §6.2).
    client_data_hash: Vec<u8>,
    allow_list: Vec<CredentialDescriptor>,
    /// Flags UP/UV da asserção inicial, espelhados nas próximas respostas.
    flags: u8,
    /// Extensões da requisição inicial: a presença de `hmac-secret` define
    /// se as asserções encadeadas recebem saída da extensão (ADR-0022).
    extensions: Option<Extensions>,
    #[allow(dead_code)]
    options: GetAssertionOptions,
    #[allow(dead_code)]
    pin_protocol: Option<u8>,
    /// UV válido na asserção inicial — mantém o filtro `credProtect`
    /// consistente nas asserções seguintes (CTAP 2.1 §6.8.2).
    uv_satisfied: bool,
    current_index: usize,
}

impl Ctap2Authenticator {
    pub fn new(
        aaguid: [u8; 16],
        crypto: CryptoEngine,
        storage: StorageEngine,
    ) -> Result<Self, Box<dyn core::error::Error>> {
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
            user_verification: None,
            pin_uv_auth_token: None,
            pin_agreement_key: None,
            pin_shared_secret: None,
            hmac_secret_session: None,
            pin_failures_since_reset: 0,
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

    /// Define a verificação de usuário embutida (mock de host) usada pelo
    /// ClientPIN 0x06/0x07.
    ///
    /// Quando `None` (padrão), o comportamento é o atual sem hardware:
    /// 0x06 retorna `UvBlocked`, 0x07 retorna `UnsupportedOption` e o GetInfo
    /// não anuncia `uv`.
    pub fn set_user_verification(&mut self, verification: Option<Box<dyn UserVerification>>) {
        self.user_verification = verification;
    }

    /// Tentativas restantes de UV embutida quando há mock injetado **e** a
    /// capability `uv` está habilitada; `None` preserva o padrão (sem UV).
    ///
    /// O contador é persistente (`sys:uv_retries`), espelhando o de PIN —
    /// sobrevive a reboots; o valor volátil do mock serve apenas para semear
    /// o storage nos testes.
    pub(crate) fn builtin_uv_retries(&self) -> Option<u8> {
        self.user_verification.as_ref()?;
        if !self.capabilities.options.contains(&"uv".to_string()) {
            return None;
        }
        Some(self.get_uv_retries())
    }

    /// Contador persistente de tentativas de UV embutida.
    pub(crate) fn get_uv_retries(&self) -> u8 {
        client_pin::read_uv_retries(&self.storage)
    }

    /// Restaura o contador persistente de UV após verificação bem-sucedida.
    pub(crate) fn reset_uv_retries(&mut self) {
        let _ = self.storage.store(
            client_pin::UV_RETRIES_KEY,
            client_pin::UV_MAX_RETRIES.to_string().into_bytes(),
        );
    }

    /// Consome uma tentativa de UV embutida (persistente).
    pub(crate) fn decrement_uv_retries(&mut self) {
        let current = self.get_uv_retries();
        let new = current.saturating_sub(1);
        let _ = self
            .storage
            .store(client_pin::UV_RETRIES_KEY, new.to_string().into_bytes());
    }

    /// Executa a UV embutida para o `getPinUvAuthTokenUsingUvWithPermissions`
    /// (0x06). Sem mock injetado ou sem a capability `uv`, retorna
    /// `UvBlocked` (comportamento atual, CTAP 2.1 §6.5.5.7.3). Com contador
    /// zerado, bloqueia sem chamar o verificador; falha decrementa, sucesso
    /// reseta o contador persistente.
    pub(crate) fn perform_builtin_uv(&mut self) -> Result<(), Ctap2Error> {
        if !self.capabilities.options.contains(&"uv".to_string()) {
            return Err(Ctap2Error::UvBlocked);
        }
        if self.user_verification.is_none() {
            return Err(Ctap2Error::UvBlocked);
        }
        if self.get_uv_retries() == 0 {
            return Err(Ctap2Error::UvBlocked);
        }
        let result = self
            .user_verification
            .as_mut()
            .ok_or(Ctap2Error::UvBlocked)?
            .verify();
        match result {
            Ok(()) => {
                self.reset_uv_retries();
                Ok(())
            }
            Err(e) => {
                self.decrement_uv_retries();
                Err(e)
            }
        }
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
    ) -> Result<MakeCredentialResponse, Box<dyn core::error::Error>> {
        debug!("Processing MakeCredential request");

        let pin_authenticated = self
            .verify_pin_uv_auth_for_operation(
                request.pin_protocol,
                request.pin_uv_auth_param.as_deref(),
                &request.client_data_hash,
                client_pin::PERMISSION_MC,
                Some(&request.rp.id),
            )
            .map_err(|error| Box::new(error) as Box<dyn core::error::Error>)?;
        if request.options.uv && client_pin::is_pin_set(&self.storage) && !pin_authenticated {
            return Err(Box::new(Ctap2Error::PinRequired));
        }
        if crate::authnr_config::is_always_uv(&self.storage) && !request.options.uv {
            // alwaysUv exige uv em todo MakeCredential (CTAP 2.1 §6.11.2.3).
            return Err(Box::new(Ctap2Error::PinRequired));
        }

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
                    // Algoritmos RSA exigem geração de chave via a feature
                    // `rs256` da crate crypto; sem ela, caem no `_` e o
                    // MakeCredential responde UnsupportedAlgorithm.
                    #[cfg(feature = "rs256")]
                    -37 => Some(-37),
                    #[cfg(feature = "rs256")]
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
            .map(CredProtectPolicy::from)
            .unwrap_or_default();

        let credential_id = self.generate_credential_id();
        let (private_key, public_key) = match selected_alg {
            -7 => self.crypto.generate_p256_key_pair()?,
            -35 => self.crypto.generate_p384_key_pair()?,
            #[cfg(feature = "rs256")]
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

        // hmac-secret (CTAP 2.1 §12.5): entrada booleana no MakeCredential —
        // gera e associa `CredRandomWithUV`/`CredRandomWithoutUV` à credencial.
        let (cred_random_with_uv, cred_random_without_uv) = match request
            .extensions
            .as_ref()
            .and_then(|e| e.hmac_secret.as_ref())
        {
            Some(raw) => {
                if hmac_secret::parse_make_credential(raw)? {
                    (
                        Some(self.crypto.random_bytes(32)),
                        Some(self.crypto.random_bytes(32)),
                    )
                } else {
                    (None, None)
                }
            }
            None => (None, None),
        };

        let credential = Credential {
            credential_id: credential_id.clone(),
            public_key: public_key.clone(),
            private_key: private_key.clone(),
            sign_count: 0,
            rp_id_hash: rp_id_hash.to_vec(),
            user_handle: Some(request.user.id.clone()),
            cred_blob: cred_blob.clone(),
            created_at: current_timestamp(),
            algorithm: selected_alg,
            rp_id: request.rp.id.clone(),
            large_blob_key: large_blob_key.clone(),
            user_name: request.user.name.clone(),
            user_display_name: request.user.display_name.clone(),
            // Política `credProtect` persistida para ser aplicada em
            // GetAssertion e exposta pelo Credential Management (CTAP 2.1 §6.8.2).
            cred_protect: Some(cred_protect_policy.into()),
            cred_random_with_uv,
            cred_random_without_uv,
        };

        self.storage.store_credential(credential, &self.crypto)?;

        let mut flags: u8 = 0x40; // AT
        if request.options.up {
            flags |= 0x01;
        }
        // O bit UV reflete verificação REALIZADA nesta operação (WebAuthn
        // L3 §6.1: UVR=1 somente após verificação bem-sucedida). Pedir a
        // opção `uv` sem pinUvAuthToken autenticado não verifica nada —
        // alegar o bit deixaria o dispositivo mentir sobre seu estado e,
        // em GetAssertion, faria `hmac-secret` entregar o segredo
        // "com verificação" (CredRandomWithUV) a quem nunca se verificou.
        // Havendo PIN configurado, o gate acima já nega com PIN_REQUIRED.
        if pin_authenticated {
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
                ext_outputs.min_pin_length = Some(crate::authnr_config::get_min_pin_length(
                    &self.storage,
                    self.capabilities.min_pin_length.unwrap_or(4),
                ));
            }
            if request.extensions.as_ref().unwrap().cred_protect.is_some() {
                ext_outputs.cred_protect = Some(cred_protect_policy.into());
            }
            if !cred_blob.is_empty() {
                ext_outputs.cred_blob = Some(cred_blob);
            }
            // §12.5: MakeCredential responde apenas a confirmação booleana —
            // os CredRandom foram gerados e persistidos acima; a troca de
            // segredos ocorre no GetAssertion.
            if let Some(raw) = request.extensions.as_ref().unwrap().hmac_secret.as_ref() {
                if hmac_secret::parse_make_credential(raw)? {
                    ext_outputs.hmac_secret = Some(Value::Bool(true));
                }
            }
            if request.extensions.as_ref().unwrap().large_blob_key {
                ext_outputs.large_blob_key = large_blob_key.clone();
            }
        }

        // Enterprise attestation one-shot (CTAP 2.1 §6.11.1): flag `enableEnterpriseAttestation`
        // is consumed at the next MakeCredential; if set, the authenticator
        // returns `packed` attestation even when the default format is `none`.
        let enterprise_pending = crate::authnr_config::consume_ep_pending(&mut self.storage);

        let effective_format = if enterprise_pending {
            AttestationFormat::Packed
        } else {
            self.attestation_format
        };
        let (fmt, attestation_info) = match effective_format {
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
    ) -> Result<GetAssertionResponse, Box<dyn core::error::Error>> {
        debug!("Processing GetAssertion request");

        let pin_authenticated = self
            .verify_pin_uv_auth_for_operation(
                request.pin_protocol,
                request.pin_uv_auth_param.as_deref(),
                &request.client_data_hash,
                client_pin::PERMISSION_GA,
                Some(&request.rp_id),
            )
            .map_err(|error| Box::new(error) as Box<dyn core::error::Error>)?;
        if request.options.uv && client_pin::is_pin_set(&self.storage) && !pin_authenticated {
            return Err(Box::new(Ctap2Error::PinRequired));
        }
        if crate::authnr_config::is_always_uv(&self.storage) && !request.options.uv {
            // alwaysUv exige uv em todo GetAssertion (CTAP 2.1 §6.11.2.3).
            return Err(Box::new(Ctap2Error::PinRequired));
        }

        if request.options.up {
            if let Some(presence) = self.user_presence.as_mut() {
                if !presence.is_present() {
                    return Err(Box::new(Ctap2Error::OperationDenied));
                }
            }
        }

        // Credenciais `userVerificationRequired` só são elegíveis quando a
        // requisição carrega UV válido (CTAP 2.1 §6.8.2/§12.2.2).
        let uv_satisfied = self.cred_protect_uv_satisfied(pin_authenticated);

        let rp_id_hash = hash_rp_id(&request.rp_id, &self.crypto);
        let mut selected: Option<Credential> = None;

        // Lista efetiva de descritores nomeados: o alias interno
        // `allow_list` ou o campo wire `allowList`. Ambos representam a
        // allowList (CTAP 2.1 §6.8.3); vazios ⇒ descoberta por RP.
        let named_credentials: Vec<CredentialDescriptor> = match request.allow_list.as_deref() {
            Some(list) if !list.is_empty() => list.to_vec(),
            _ => request.credentials.clone(),
        };

        // Credenciais nomeadas são elegíveis por ID; cada candidata deve
        // pertencer ao RP solicitado e passar no filtro `credProtect`
        // (nomeada na lista ⇒ regra do nível 2 se aplica — §12.2.2).
        if !named_credentials.is_empty() {
            for desc in &named_credentials {
                if let Some(credential) = self.storage.get_credential(&desc.id, &self.crypto)? {
                    if credential.rp_id_hash == rp_id_hash.to_vec()
                        && self.is_cred_protect_allowed(&credential, uv_satisfied, true)
                    {
                        selected = Some(credential);
                        break;
                    }
                }
            }
        }

        let credential = match selected {
            Some(c) => c,
            None => {
                // Descoberta por RP: credenciais de níveis 2 e 3 não são
                // retornáveis sem UV (CTAP 2.1 §12.2.2).
                let mut rp_creds = self.storage.find_by_rp_id(&request.rp_id, &self.crypto);
                rp_creds.retain(|c| self.is_cred_protect_allowed(c, uv_satisfied, false));
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
        // Mesma regra do MakeCredential: bit UV somente com autenticação
        // real desta operação (pinUvAuthToken com permissão `ga`) — nunca
        // pela mera presença da opção `uv` no request.
        if pin_authenticated {
            flags |= 0x04;
        }
        let sign_count = self.next_sign_count()?;

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
            #[cfg(feature = "rs256")]
            -37 => self
                .crypto
                .sign_rsa_pss(&credential.private_key, &data_to_sign)?,
            #[cfg(feature = "rs256")]
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
            if let Some(raw_hmac) = request.extensions.as_ref().unwrap().hmac_secret.as_ref() {
                // §12.5: a extensão no GetAssertion exige evidência de
                // user presence ("up" falso → UNSUPPORTED_OPTION).
                if !request.options.up {
                    return Err(Box::new(Ctap2Error::UnsupportedOption));
                }
                let get_request = hmac_secret::parse_get_assertion(raw_hmac)?;
                // §12.5: o CredRandom é escolhido pela verificação REAL da
                // operação — pinUvAuthToken autenticado → WithUV; caso
                // contrário WithoutUV. O bit uv da resposta espelha esse
                // estado (flags acima); a mera opção `uv` pedida sem
                // autenticação nunca seleciona o segredo "com verificação".
                let cred_random = if pin_authenticated {
                    credential.cred_random_with_uv.as_deref()
                } else {
                    credential.cred_random_without_uv.as_deref()
                };
                // §12.5: sem CredRandom associado (credencial criada antes da
                // extensão ou com entrada falsa), a extensão é ignorada — a
                // asserção prossegue sem saída para ela.
                if let Some(cred_random) = cred_random {
                    // ADR-0022: a sessão de transação retém o segredo
                    // compartilhado e os salts decifrados para as asserções
                    // encadeadas; o acordo P-256 em si permanece de uso único
                    // (consumido dentro de `begin_session`).
                    let session = hmac_secret::begin_session(self, &get_request)?;
                    let encrypted =
                        hmac_secret::session_output(self.get_crypto(), &session, cred_random)?;
                    self.hmac_secret_session = Some(session);
                    ext_outputs.hmac_secret = Some(Value::Bytes(encrypted));
                }
            }
            if !credential.cred_blob.is_empty() {
                ext_outputs.cred_blob = Some(credential.cred_blob.clone());
            }
            if request.extensions.as_ref().unwrap().large_blob_key {
                if let Some(ref key) = credential.large_blob_key {
                    ext_outputs.large_blob_key = Some(key.clone());
                }
            }
        }

        let matching =
            self.find_matching_credentials(&request.rp_id, &named_credentials, uv_satisfied);
        let total = matching.len();
        let current_index = matching
            .iter()
            .position(|id| id == &credential.credential_id)
            .unwrap_or(0);

        if total > 1 {
            self.get_next_assertion_state = Some(GetNextAssertionState {
                rp_id: request.rp_id.clone(),
                client_data_hash: request.client_data_hash.clone(),
                allow_list: named_credentials.clone(),
                flags,
                extensions: request.extensions.clone(),
                options: request.options.clone(),
                pin_protocol: request.pin_protocol,
                // O filtro de credProtect da asserção inicial vale para todas
                // as próximas: GetNextAssertion não carrega autenticação própria.
                uv_satisfied,
                current_index,
            });
        } else {
            // Transação de asserção única: nada a encadear, a sessão
            // hmac-secret termina aqui (ADR-0022).
            self.hmac_secret_session = None;
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
            extensions: if has_ext { Some(ext_outputs) } else { None },
        })
    }

    pub fn get_info(&self) -> Result<GetInfoResponse, Box<dyn core::error::Error>> {
        debug!("Processing GetInfo request");

        let security = if self.capabilities.security.has_any_features() {
            Some(self.capabilities.security.clone())
        } else {
            None
        };

        // Opções dinâmicas: `clientPin` indica o *suporte* à funcionalidade
        // (obrigatório para que plataformas possam definir o PIN inicial) e
        // `pinUvAuthToken` o suporte a tokens.
        let mut options = self.capabilities.options.clone();
        // Mock de UV embutida restrito a host: `uv` só é anunciado com um
        // verificador injetado; sem ele, a option é removida para que hosts
        // não tentem 0x06/0x07 (comportamento padrão, sem hardware).
        if self.user_verification.is_none() {
            options.retain(|option| option != "uv");
        }
        if !self.capabilities.pin_uv_auth_protocols.is_empty() {
            if !options.contains(&"pinUvAuthToken".to_string()) {
                options.push("pinUvAuthToken".to_string());
            }
            if client_pin::is_pin_set(&self.storage) {
                if !options.contains(&"clientPin".to_string()) {
                    options.push("clientPin".to_string());
                }
            } else {
                options.retain(|option| option != "clientPin");
            }
        } else {
            options.retain(|option| option != "clientPin" && option != "pinUvAuthToken");
        }

        // Algoritmos anunciados no GetInfo: ES256, EdDSA e ES384 sempre; os
        // algoritmos RSA (PS256/RS256) apenas com a feature `rs256`, pois sem
        // ela não há geração de chaves RSA.
        // `mut` só é usado quando a feature adiciona as entradas RSA abaixo.
        #[cfg_attr(not(feature = "rs256"), allow(unused_mut))]
        let mut algorithms = vec![
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
        ];
        #[cfg(feature = "rs256")]
        algorithms.extend([
            CoseAlgorithmEntry {
                alg: -37,
                key_type: "public-key".to_string(),
            },
            CoseAlgorithmEntry {
                alg: -257,
                key_type: "public-key".to_string(),
            },
        ]);

        Ok(GetInfoResponse {
            versions: self.capabilities.versions.clone(),
            extensions: self.capabilities.extensions.clone(),
            aaguid: self.capabilities.aaguid.to_vec(),
            options,
            pin_uv_auth_protocols: self.capabilities.pin_uv_auth_protocols.clone(),
            max_msg_size: 1200,
            rp_count: self.capabilities.rp_count,
            max_cred_blob_length: self.capabilities.max_cred_blob_length,
            max_credential_id_length: self.capabilities.max_credential_id_length,
            max_credential_count: self.capabilities.max_credential_count,
            firmware_version: firmware_version_to_ctap_integer(
                &self.capabilities.firmware_version,
            )?,
            algorithms,
            security,
            max_large_blob_data_size: self.capabilities.max_large_blob_data_size,
        })
    }

    pub fn get_version(&self) -> Result<GetVersionResponse, Box<dyn core::error::Error>> {
        debug!("Processing GetVersion request");

        Ok(GetVersionResponse {
            firmware_version: "0.1.0".to_string(),
            firmware_commit_id: "0000000".to_string(),
            firmware_build_id: "00000000".to_string(),
        })
    }

    pub fn process_command(&mut self, cmd: u8, data: Vec<u8>) -> Result<Vec<u8>, Ctap2Error> {
        let command = Ctap2Command::from_u8(cmd);

        // ADR-0022: qualquer comando diferente de GetNextAssertion encerra a
        // transação hmac-secret corrente — a sessão vive apenas dentro de uma
        // transação de user presence (GetAssertion → cadeia de GetNextAssertion).
        if !matches!(command, Ctap2Command::GetNextAssertion) {
            self.hmac_secret_session = None;
        }

        match command {
            Ctap2Command::MakeCredential => {
                let request: MakeCredentialRequest = decode_cbor(&data)?;
                let response = self.make_credential(request).map_err(ctap2_error)?;
                let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::Unknown)?;
                Ok(encoded)
            }
            Ctap2Command::GetAssertion => {
                let request: GetAssertionRequest = decode_cbor(&data)?;
                let response = self.get_assertion(request).map_err(ctap2_error)?;
                let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::Unknown)?;
                Ok(encoded)
            }
            Ctap2Command::GetInfo => {
                let response = self.get_info().map_err(|_| Ctap2Error::Unknown)?;
                let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::Unknown)?;
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
            Ctap2Command::AuthenticatorConfig => {
                crate::authnr_config::handle_authnr_config(self, &data)
            }
            Ctap2Command::EnumerateRPsInitial => self.handle_enumerate_rps_initial(),
            Ctap2Command::EnumerateRPsNext => self.handle_enumerate_rps_next(),
            Ctap2Command::Unknown(_) => Err(Ctap2Error::InvalidCommand),
        }
    }

    fn handle_selection(&self) -> Result<Vec<u8>, Ctap2Error> {
        self.handle_get_version()
    }

    fn handle_get_version(&self) -> Result<Vec<u8>, Ctap2Error> {
        let response = self.get_version().map_err(|_| Ctap2Error::Unknown)?;
        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::Unknown)?;
        Ok(encoded)
    }

    fn handle_client_pin(&mut self, data: &[u8]) -> Result<Vec<u8>, Ctap2Error> {
        client_pin::handle_client_pin(self, data)
    }

    fn handle_reset(&mut self) -> Result<Vec<u8>, Ctap2Error> {
        // CTAP 2.1 §6.9: reset exige confirmação de presença física, no mesmo
        // padrão de MakeCredential/GetAssertion — sem fonte de presença
        // configurada (ex.: simulador), o default permanece "sempre presente".
        if let Some(presence) = self.user_presence.as_mut() {
            if !presence.is_present() {
                return Err(Ctap2Error::OperationDenied);
            }
        }

        self.storage.clear();
        self.storage.clear_large_blobs();
        self.enumerate_rps_state = None;
        self.cred_mgmt_rps_state = None;
        self.cred_mgmt_creds_state = None;
        self.get_next_assertion_state = None;

        // Reset invalida TODO o estado de sessão PIN/crypto (CTAP 2.1 §6.9.1):
        // um pinUvAuthToken emitido antes do reset não pode mais autorizar
        // operações no dispositivo limpo. A sessão hmac-secret (ADR-0022) é
        // estado volátil de sessão e morre com o reset, junto com as
        // credenciais que ela referencia.
        self.pin_uv_auth_token = None;
        self.pin_agreement_key = None;
        self.pin_shared_secret = None; // Zeroizing: material sensível é apagado no drop
        self.hmac_secret_session = None;
        self.pin_failures_since_reset = 0;

        info!("Reset: all credentials and state cleared");
        Ok(Vec::new())
    }

    fn handle_get_next_assertion(&mut self) -> Result<Vec<u8>, Ctap2Error> {
        let state = self
            .get_next_assertion_state
            .take()
            .ok_or(Ctap2Error::InvalidState)?;

        let matching =
            self.find_matching_credentials(&state.rp_id, &state.allow_list, state.uv_satisfied);

        if matching.is_empty() {
            // Sem credenciais a transação termina: a sessão hmac-secret é
            // descartada (ADR-0022; Zeroizing apaga o material no drop).
            self.hmac_secret_session = None;
            return Err(Ctap2Error::NoCredentials);
        }

        let next_index = state.current_index + 1;
        if next_index >= matching.len() {
            // Cadeia esgotada: a última asserção já foi servida e a sessão
            // hmac-secret termina junto com a transação (ADR-0022).
            self.hmac_secret_session = None;
            return Err(Ctap2Error::NoCredentials);
        }
        let has_more = next_index + 1 < matching.len();

        let credential_id = &matching[next_index];
        let credential = self
            .storage
            .get_credential(credential_id, &self.crypto)
            .map_err(|_| Ctap2Error::Unknown)?
            .ok_or(Ctap2Error::NoCredentials)?;

        // Extrai o contexto da asserção inicial antes de restaurar o estado,
        // pois a reconstrução consome `state`.
        let client_data_hash = state.client_data_hash.clone();
        let flags = state.flags;

        // Saída `hmac-secret` encadeada (CTAP 2.1 §12.5 + ADR-0022): presente
        // apenas quando a requisição inicial pediu a extensão e a sessão
        // sobreviveu aos limites da transação (nenhum outro comando no meio).
        // O CredRandom segue a MESMA seleção UV da asserção inicial — cada
        // saída usa o CredRandom da própria credencial assinalada.
        let mut chained_hmac: Option<Value> = None;
        let requested_hmac = state
            .extensions
            .as_ref()
            .map(|e| e.hmac_secret.is_some())
            .unwrap_or(false);
        if requested_hmac {
            let cred_random = if state.uv_satisfied {
                credential.cred_random_with_uv.as_deref()
            } else {
                credential.cred_random_without_uv.as_deref()
            };
            if let (Some(cred_random), Some(session)) =
                (cred_random, self.hmac_secret_session.as_ref())
            {
                let encrypted =
                    hmac_secret::session_output(self.get_crypto(), session, cred_random)?;
                chained_hmac = Some(Value::Bytes(encrypted));
            }
        }

        if !has_more {
            // Última asserção da cadeia: nada mais a produzir, a sessão
            // encerra aqui (ADR-0022).
            self.hmac_secret_session = None;
        }

        self.get_next_assertion_state = Some(GetNextAssertionState {
            current_index: next_index,
            ..state
        });

        let response = self
            .build_get_assertion_response(
                &credential,
                matching.len(),
                &client_data_hash,
                flags,
                chained_hmac,
            )
            .map_err(|_| Ctap2Error::Unknown)?;

        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::Unknown)?;
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
            let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::Unknown)?;
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

        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::Unknown)?;
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

        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::Unknown)?;
        Ok(encoded)
    }

    // ── LargeBlobs (0x0C) ────────────────────────────────────────────────

    fn handle_large_blobs(&mut self, data: &[u8]) -> Result<Vec<u8>, Ctap2Error> {
        let request: large_blobs::LargeBlobsRequest =
            decode_cbor(data).map_err(|_| Ctap2Error::InvalidParameter)?;

        // Read operation: `set` is None, `get` is Some
        if request.set.is_none() {
            let count = request.get.unwrap_or(0) as usize;
            // `offset` é u64 no wire: em alvos 32 bits um cast truncaria e
            // poderia apontar para dentro do array; rejeita sem truncar.
            let offset =
                usize::try_from(request.offset).map_err(|_| Ctap2Error::InvalidParameter)?;
            let fragment = self.storage.read_large_blobs(offset, count);
            let response = large_blobs::LargeBlobsResponse {
                config: Some(fragment),
            };
            let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::Unknown)?;
            return Ok(encoded);
        }

        // Write operation: `set` is Some
        let blob_data = request.set.unwrap();
        let expected_len: Option<usize> = request
            .length
            .map(|v| usize::try_from(v).map_err(|_| Ctap2Error::InvalidParameter))
            .transpose()?;
        let offset = usize::try_from(request.offset).map_err(|_| Ctap2Error::InvalidParameter)?;

        // CTAP 2.1 §6.10: valida offset e length contra a capacidade máxima
        // ANTES de qualquer redimensionamento/alocação — um único comando não
        // autenticado não pode inflar o buffer em memória (DoS).
        let max_size = self
            .capabilities
            .max_large_blob_data_size
            .unwrap_or(MAX_LARGE_BLOBS_SIZE as u32) as usize;
        let write_end = offset
            .checked_add(blob_data.len())
            .ok_or(Ctap2Error::InvalidParameter)?;
        if write_end > max_size {
            return Err(Ctap2Error::InvalidParameter);
        }
        if let Some(exp) = expected_len {
            if exp > max_size {
                return Err(Ctap2Error::InvalidParameter);
            }
            if write_end > exp {
                return Err(Ctap2Error::InvalidParameter);
            }
        }

        self.storage
            .write_large_blobs(offset, &blob_data, expected_len)
            .map_err(|e| {
                if let Some(se) = e.downcast_ref::<storage::StorageError>() {
                    match se {
                        storage::StorageError::InvalidParameter(_) => Ctap2Error::InvalidParameter,
                        storage::StorageError::BackendError(msg)
                            if msg.contains("exceeds sector capacity") =>
                        {
                            Ctap2Error::LargeBlobStorageFull
                        }
                        _ => Ctap2Error::Unknown,
                    }
                } else {
                    let msg = e.to_string();
                    if msg.contains("InvalidParameter")
                        || msg.contains("sparse")
                        || msg.contains("exceeds")
                    {
                        // Validação de LargeBlobs (gap, expected_len, capacidade)
                        Ctap2Error::InvalidParameter
                    } else if msg.contains("exceeds sector capacity") {
                        Ctap2Error::LargeBlobStorageFull
                    } else {
                        Ctap2Error::Unknown
                    }
                }
            })?;

        let response = large_blobs::LargeBlobsResponse { config: None };
        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::Unknown)?;
        Ok(encoded)
    }

    // ── Credential Management (0x0A) ─────────────────────────────────────

    fn handle_credential_management(&mut self, data: &[u8]) -> Result<Vec<u8>, Ctap2Error> {
        let request: cred_mgmt::CredentialManagementRequest =
            decode_cbor(data).map_err(|_| Ctap2Error::InvalidParameter)?;

        let auth_message = credential_management_auth_message(data)?;
        let pin_authenticated = self.verify_pin_uv_auth_for_operation(
            request.pin_uv_auth_protocol,
            request.pin_uv_auth_param.as_deref(),
            &auth_message,
            client_pin::PERMISSION_CM,
            None,
        )?;
        if !pin_authenticated {
            // CTAP 2.1 §6.8 / §6.12: todo subcomando de Credential Management exige um
            // pinUvAuthToken com permissão `cm`. Se nenhum PIN estiver configurado,
            // deve retornar CTAP2_ERR_PIN_NOT_SET (0x35); se houver PIN configurado,
            // retorna CTAP2_ERR_PUAT_REQUIRED / PinRequired (0x36).
            if !client_pin::is_pin_set(&self.storage) {
                return Err(Ctap2Error::PinNotSet);
            }
            return Err(Ctap2Error::PinRequired);
        }

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
        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::Unknown)?;
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
                id: first_rp_id.clone(),
                name: Some(first_rp_id),
                icon: None,
            },
            rp_id_hash: first_rp_hash,
            total_rps: total as u32,
        };
        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::Unknown)?;
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
                name: Some(rp_id.clone()),
                icon: None,
            },
            rp_id_hash: rp_hash.clone(),
            total_rps: state.total as u32,
        };
        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::Unknown)?;
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

        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::Unknown)?;
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
        let encoded = encode_cbor(&response).map_err(|_| Ctap2Error::Unknown)?;
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
            .map_err(|_| Ctap2Error::Unknown)?;
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
            public_key: cose_key_value(credential),
            total_credentials: total,
            // Política real da credencial; a enumeração exige token `cm`
            // autenticado, então expô-la aqui é seguro (CTAP 2.1 §6.12.2).
            cred_protect: credential.cred_protect,
            large_blob_key: credential.large_blob_key.clone(),
        }
    }

    /// Indica se a operação atual satisfaz user verification para o filtro
    /// `credProtect` (CTAP 2.1 §6.8.2): um pinUvAuthToken autenticado com a
    /// permissão necessária, ou a configuração `alwaysUv`, que torna UV
    /// obrigatório em toda operação.
    fn cred_protect_uv_satisfied(&self, pin_authenticated: bool) -> bool {
        pin_authenticated || crate::authnr_config::is_always_uv(&self.storage)
    }

    /// Filtro `credProtect` da descoberta de credenciais (CTAP 2.1 §12.2.2):
    ///
    /// - nível 1 (default): sempre elegível;
    /// - nível 2 (`userVerificationOptionalWithCredentialIDList`): exige UV
    ///   válida OU ter sido nomeada explicitamente na allowList — a
    ///   descoberta por RP (listas vazias) não a revela;
    /// - nível 3: somente com UV válida.
    fn is_cred_protect_allowed(
        &self,
        credential: &Credential,
        uv_satisfied: bool,
        named_in_allow_list: bool,
    ) -> bool {
        if uv_satisfied {
            return true;
        }
        match credential.cred_protect {
            Some(CRED_PROTECT_UV_REQUIRED) => false,
            Some(CRED_PROTECT_ALLOWLIST_REQUIRED) => named_in_allow_list,
            _ => true,
        }
    }

    fn find_matching_credentials(
        &self,
        rp_id: &str,
        allow_list: &[CredentialDescriptor],
        uv_satisfied: bool,
    ) -> Vec<Vec<u8>> {
        if allow_list.is_empty() {
            // Descoberta por RP: níveis 2 e 3 ficam ocultos sem UV.
            return self
                .storage
                .find_by_rp_id(rp_id, &self.crypto)
                .into_iter()
                .filter(|c| self.is_cred_protect_allowed(c, uv_satisfied, false))
                .map(|c| c.credential_id.clone())
                .collect();
        }

        // AllowList presente: cada entrada é uma nomeação explícita, o que
        // habilita credenciais de nível 2 mesmo sem UV (§12.2.2).
        allow_list
            .iter()
            .filter_map(|desc| {
                self.storage
                    .get_credential(&desc.id, &self.crypto)
                    .ok()
                    .flatten()
                    .filter(|c| c.rp_id == rp_id)
                    .filter(|c| self.is_cred_protect_allowed(c, uv_satisfied, true))
                    .map(|c| c.credential_id.clone())
            })
            .collect()
    }

    /// Monta a resposta de um GetNextAssertion.
    ///
    /// Assina `authData || clientDataHash` com o mesmo clientDataHash da
    /// asserção inicial (armazenado no estado), espelha as flags UP/UV e
    /// incrementa o contador global de assinaturas, persistindo-o — mesmo
    /// mecanismo do [`Ctap2Authenticator::get_assertion`] (CTAP 2.1 §6.2.1).
    ///
    /// `chained_hmac` carrega a saída `hmac-secret` já cifrada para esta
    /// credencial da cadeia (ADR-0022), com a mesma forma do mapa de extensões
    /// da asserção inicial.
    #[allow(clippy::too_many_arguments)]
    fn build_get_assertion_response(
        &mut self,
        credential: &Credential,
        total: usize,
        client_data_hash: &[u8],
        flags: u8,
        chained_hmac: Option<Value>,
    ) -> Result<GetAssertionResponse, Box<dyn core::error::Error>> {
        let sign_count = self.next_sign_count()?;
        self.storage
            .update_sign_count(&credential.credential_id, sign_count)?;

        let rp_id_hash_vec = self.crypto.sha256(credential.rp_id.as_bytes());
        let rp_id_hash: [u8; 32] = rp_id_hash_vec
            .try_into()
            .map_err(|_| "rp_id_hash must be 32 bytes")?;

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
        data_to_sign.extend_from_slice(client_data_hash);

        let signature = match credential.algorithm {
            -7 => self
                .crypto
                .sign_p256(&credential.private_key, &data_to_sign)?,
            -35 => self
                .crypto
                .sign_p384(&credential.private_key, &data_to_sign)?,
            #[cfg(feature = "rs256")]
            -37 => self
                .crypto
                .sign_rsa_pss(&credential.private_key, &data_to_sign)?,
            #[cfg(feature = "rs256")]
            -257 => self
                .crypto
                .sign_rsa(&credential.private_key, &data_to_sign)?,
            _ => self.crypto.sign(&data_to_sign, &credential.private_key)?,
        };

        Ok(GetAssertionResponse {
            credential: Some(CredentialDescriptor {
                r#type: "public-key".to_string(),
                id: credential.credential_id.clone(),
                transports: None,
            }),
            auth_data,
            signature,
            // CTAP 2.1 §6.2: a asserção encadeada carrega a mesma entidade
            // `user` (0x04) da asserção inicial — antes omitida aqui.
            user: Some(User {
                id: credential.user_handle.clone().unwrap_or_default(),
                name: None,
                display_name: None,
                icon_url: None,
            }),
            number_of_credentials: Some(total as u16),
            extensions: chained_hmac.map(|output| ExtensionOutputs {
                hmac_secret: Some(output),
                ..Default::default()
            }),
        })
    }

    fn generate_credential_id(&self) -> Vec<u8> {
        self.crypto.random_bytes(16)
    }

    fn build_auth_data(
        &self,
        params: &AuthDataParams,
    ) -> Result<Vec<u8>, Box<dyn core::error::Error>> {
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
                #[cfg(feature = "rs256")]
                -37 => {
                    let (n, e) = CryptoEngine::rsa_public_key_parts(params.public_key)?;
                    build_cose_key_rsa_pss(&n, &e)
                        .map_err(|_| "failed to build RSA-PSS COSE key".to_string())?
                }
                #[cfg(feature = "rs256")]
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
        client_pin::read_retries(&self.storage)
    }

    /// Armazena `LEFT(SHA-256(pin), 16)` — o formato `CurrentStoredPIN`
    /// exigido pelo CTAP 2.1 §6.5.5.5. O PIN nunca é armazenado em claro.
    fn set_pin(&mut self, pin: &[u8]) -> Result<(), Ctap2Error> {
        if pin.len() < client_pin::PIN_MIN_LENGTH {
            return Err(Ctap2Error::PinPolicyViolation);
        }
        if pin.len() > client_pin::PIN_MAX_LENGTH {
            return Err(Ctap2Error::PinPolicyViolation);
        }

        let full_hash = self.crypto.sha256(pin);
        let stored_hash = full_hash[..16].to_vec();
        self.storage
            .store(client_pin::PIN_STORAGE_KEY, stored_hash)
            .map_err(|_| Ctap2Error::Unknown)?;

        self.reset_pin_retries();
        self.pin_uv_auth_token = None;

        Ok(())
    }

    fn change_pin(&mut self, old_pin: &[u8], new_pin: &[u8]) -> Result<(), Ctap2Error> {
        if new_pin.len() < client_pin::PIN_MIN_LENGTH || new_pin.len() > client_pin::PIN_MAX_LENGTH
        {
            return Err(Ctap2Error::PinPolicyViolation);
        }

        let stored_hash = self
            .storage
            .retrieve(client_pin::PIN_STORAGE_KEY)
            .map_err(|_| Ctap2Error::PinNotSet)?;

        let old_full_hash = self.crypto.sha256(old_pin);
        if !crypto::constant_time_eq(&old_full_hash[..16], &stored_hash) {
            self.decrement_pin_retries();
            return Err(self.register_pin_failure());
        }

        self.reset_pin_retries();

        let new_full_hash = self.crypto.sha256(new_pin);
        self.storage
            .store(client_pin::PIN_STORAGE_KEY, new_full_hash[..16].to_vec())
            .map_err(|_| Ctap2Error::Unknown)?;

        self.pin_uv_auth_token = None;

        Ok(())
    }

    fn reset_pin_retries(&mut self) {
        // Sucesso (ou novo PIN) encerra o bloqueio volátil da sessão junto com
        // a restauração do contador persistente.
        self.pin_failures_since_reset = 0;
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
            return Err(Ctap2Error::PinNotSet);
        }
        if client_pin::is_pin_blocked(self) {
            return Err(Ctap2Error::PinBlocked);
        }
        let stored_hash = self
            .storage
            .retrieve(client_pin::PIN_STORAGE_KEY)
            .map_err(|_| Ctap2Error::PinNotSet)?;
        let submitted_full_hash = self.crypto.sha256(pin);
        if !crypto::constant_time_eq(&submitted_full_hash[..16], &stored_hash) {
            self.decrement_pin_retries();
            return Err(self.register_pin_failure());
        }
        self.reset_pin_retries();
        Ok(())
    }
}

impl Ctap2Authenticator {
    /// Obtém o próximo valor do contador global de assinaturas, persistindo-o.
    ///
    /// O contador é compartilhado por todas as credenciais: cada asserção o
    /// incrementa em uma unidade e grava no storage, garantindo valores
    /// estritamente crescentes entre asserções sucessivas — sinal de
    /// autenticador autêntico para os relying parties (WebAuthn L3 §6.1.1;
    /// CTAP 2.1 §6.2.1).
    fn next_sign_count(&mut self) -> Result<u32, Box<dyn core::error::Error>> {
        let current = self
            .storage
            .retrieve(SIGN_COUNTER_STORAGE_KEY)
            .ok()
            .and_then(|data| String::from_utf8(data).ok())
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0);
        let next = current
            .checked_add(1)
            .ok_or("signature counter exhausted")?;
        self.storage
            .store(SIGN_COUNTER_STORAGE_KEY, next.to_string().into_bytes())?;
        Ok(next)
    }

    /// Indica o bloqueio volátil de PIN (`PIN_AUTH_BLOCKED`) da sessão atual.
    ///
    /// O bloqueio nasce limpo em cada instância do autenticador — um power
    /// cycle o encerra, enquanto o contador persistente de tentativas
    /// permanece (CTAP 2.1 §6.5.5.6).
    pub(crate) fn is_pin_auth_blocked(&self) -> bool {
        self.pin_failures_since_reset >= client_pin::PIN_BLOCK_THRESHOLD
    }

    /// Registra uma falha consecutiva de PIN e devolve o erro correspondente.
    ///
    /// O chamador já consumiu a tentativa persistente (`decrement_pin_retries`);
    /// aqui apenas avança o estado volátil que materializa o bloqueio.
    pub(crate) fn register_pin_failure(&mut self) -> Ctap2Error {
        self.pin_failures_since_reset = self.pin_failures_since_reset.saturating_add(1);
        if client_pin::read_retries(&self.storage) == 0 {
            return Ctap2Error::PinBlocked;
        }
        if self.is_pin_auth_blocked() {
            return Ctap2Error::PinAuthBlocked;
        }
        Ctap2Error::PinInvalid
    }

    /// Armazena o pinUvAuthToken da sessão atual (CTAP 2.1 §6.5.2.1).
    pub(crate) fn set_pin_uv_auth_token(
        &mut self,
        token: Vec<u8>,
        permissions: u8,
        permissions_rp_id: Option<String>,
        protocol: u8,
    ) {
        self.pin_uv_auth_token = Some(client_pin::PinUvAuthTokenState::new(
            token,
            permissions,
            permissions_rp_id,
            protocol,
        ));
    }

    /// Invalida o pinUvAuthToken da sessão (resetPinUvAuthToken).
    pub(crate) fn invalidate_pin_uv_auth_token(&mut self) {
        self.pin_uv_auth_token = None;
    }

    /// Armazena o segredo compartilhado usado na emissão do pinUvAuthToken.
    ///
    /// Usado pelo `setMinPINLength` para decifrar o `currentPIN` (ADR-0021).
    /// Material sensível: zeroizado no drop.
    pub(crate) fn set_pin_shared_secret(&mut self, secret: Vec<u8>, protocol: u8) {
        self.pin_shared_secret = Some((crypto::pin_protocol::Zeroizing::new(secret), protocol));
    }

    /// Consome o segredo compartilhado da sessão (uso único por transação).
    pub(crate) fn take_pin_shared_secret(
        &mut self,
    ) -> Option<(crypto::pin_protocol::Zeroizing<Vec<u8>>, u8)> {
        self.pin_shared_secret.take()
    }

    /// Registra a chave de acordo P-256 anunciada em getKeyAgreement.
    /// A mesma chave privada é usada no subcomando seguinte da transação
    /// (`decapsulate`, CTAP 2.1 §6.5.4).
    pub(crate) fn set_pin_agreement_key(&mut self, key: crypto::pin_protocol::PinAgreementKey) {
        self.pin_agreement_key = Some(key);
    }

    /// Consome a chave de acordo P-256 da transação atual. Cada chave é usada
    /// uma única vez (CTAP 2.1 §6.5.5.4: novo segredo a cada transação).
    pub(crate) fn take_pin_agreement_key(
        &mut self,
    ) -> Option<crypto::pin_protocol::PinAgreementKey> {
        self.pin_agreement_key.take()
    }

    /// Verifica um `pinUvAuthParam` contra o pinUvAuthToken da sessão.
    ///
    /// O argumento autenticado é o `clientDataHash` (32 bytes), conforme
    /// CTAP 2.1 §6.5.8. Retorna [`Ctap2Error::PinAuthInvalid`] se o token
    /// estiver ausente, expirado ou o MAC não conferir (comparação em tempo
    /// constante via [`crypto::constant_time_eq`]).
    pub fn verify_pin_uv_auth_param(
        &self,
        pin_protocol: u8,
        pin_uv_auth_param: &[u8],
        client_data_hash: &[u8],
    ) -> Result<(), Ctap2Error> {
        self.verify_pin_uv_auth_message(pin_protocol, pin_uv_auth_param, client_data_hash)
    }

    fn verify_pin_uv_auth_message(
        &self,
        pin_protocol: u8,
        pin_uv_auth_param: &[u8],
        message: &[u8],
    ) -> Result<(), Ctap2Error> {
        let state = self
            .pin_uv_auth_token
            .as_ref()
            .ok_or(Ctap2Error::PinAuthInvalid)?;
        if state.protocol != pin_protocol {
            return Err(Ctap2Error::PinAuthInvalid);
        }
        let mac = crypto::pin_protocol::PinUvProtocol::new(state.protocol)
            .map_err(|_| Ctap2Error::PinAuthInvalid)?
            .authenticate(&state.token, message)
            .map_err(|_| Ctap2Error::PinAuthInvalid)?;
        if !crypto::constant_time_eq(&mac, pin_uv_auth_param) {
            return Err(Ctap2Error::PinAuthInvalid);
        }
        Ok(())
    }

    /// Verifica um `pinUvAuthParam` e as permissões/RP associados ao token.
    pub(crate) fn verify_pin_uv_auth_for_operation(
        &self,
        pin_protocol: Option<u8>,
        pin_uv_auth_param: Option<&[u8]>,
        message: &[u8],
        required_permission: u8,
        rp_id: Option<&str>,
    ) -> Result<bool, Ctap2Error> {
        match (pin_protocol, pin_uv_auth_param) {
            (None, None) => return Ok(false),
            (Some(_), None) | (None, Some(_)) => return Err(Ctap2Error::MissingParameter),
            (Some(protocol), Some(param)) => {
                self.verify_pin_uv_auth_message(protocol, param, message)?;
            }
        }

        let state = self
            .pin_uv_auth_token
            .as_ref()
            .ok_or(Ctap2Error::PinAuthInvalid)?;
        if state.permissions & required_permission != required_permission {
            return Err(Ctap2Error::UnauthorizedPermission);
        }
        if let Some(bound_rp_id) = state.permissions_rp_id.as_deref() {
            if rp_id != Some(bound_rp_id) {
                return Err(Ctap2Error::UnauthorizedPermission);
            }
        }

        Ok(true)
    }
}

/// Reconstitui a mensagem autenticada de Credential Management.
///
/// A mensagem é `subCommand || subCommandParams`, usando os bytes CBOR do
/// mapa de parâmetros exatamente como chegaram no request. Isso evita alterar
/// a codificação de descritores ou entidades de usuário durante a verificação.
fn credential_management_auth_message(data: &[u8]) -> Result<Vec<u8>, Ctap2Error> {
    let mut restante = data;
    let value: Value = from_reader(&mut restante).map_err(|_| Ctap2Error::InvalidCbor)?;
    if !restante.is_empty() {
        return Err(Ctap2Error::InvalidCbor);
    }

    let Value::Map(entries) = value else {
        return Err(Ctap2Error::InvalidCbor);
    };

    let mut sub_command = None;
    let mut sub_command_params = None;
    for (key, value) in entries {
        match key {
            Value::Integer(number) if number == 1.into() => sub_command = Some(value),
            Value::Text(name) if name == "subCommand" => sub_command = Some(value),
            Value::Integer(number) if number == 2.into() => sub_command_params = Some(value),
            Value::Text(name) if name == "subCommandParams" => sub_command_params = Some(value),
            _ => {}
        }
    }

    let sub_command = sub_command
        .and_then(|value| match value {
            Value::Integer(number) => u8::try_from(number).ok(),
            _ => None,
        })
        .ok_or(Ctap2Error::InvalidParameter)?;

    let mut message = vec![sub_command];
    if let Some(params) = sub_command_params {
        into_writer(&params, &mut message).map_err(|_| Ctap2Error::InvalidCbor)?;
    }
    Ok(message)
}

/// Builds a COSE_Key CBOR map for an Ed25519 (EdDSA, alg -8) public key.
fn cose_key_value(credential: &Credential) -> Value {
    match credential.algorithm {
        -7 => {
            let (x, y) = if credential.public_key.len() == 65 && credential.public_key[0] == 0x04 {
                (&credential.public_key[1..33], &credential.public_key[33..65])
            } else if credential.public_key.len() == 64 {
                (&credential.public_key[0..32], &credential.public_key[32..64])
            } else {
                (&credential.public_key[..], &[][..])
            };
            Value::Map(vec![
                (Value::Integer(1.into()), Value::Integer(2.into())),
                (Value::Integer(3.into()), Value::Integer((-7).into())),
                (Value::Integer((-1).into()), Value::Integer(1.into())),
                (Value::Integer((-2).into()), Value::Bytes(x.to_vec())),
                (Value::Integer((-3).into()), Value::Bytes(y.to_vec())),
            ])
        }
        _ => Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(1.into())),
            (Value::Integer(3.into()), Value::Integer((-8).into())),
            (Value::Integer((-1).into()), Value::Integer(6.into())),
            (Value::Integer((-2).into()), Value::Bytes(credential.public_key.clone())),
        ]),
    }
}

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
#[cfg(feature = "rs256")]
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
#[cfg(feature = "rs256")]
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
    fn test_decode_cbor_rejects_trailing_bytes() {
        let request = MakeCredentialRequest {
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
                algorithms: -7,
            }],
            exclude_list: vec![],
            extensions: None,
            options: MakeCredentialOptions {
                rk: false,
                uv: false,
                up: true,
                extended: false,
            },
            pin_uv_auth_param: None,
            pin_protocol: None,
            enterprise_protections: None,
        };
        let mut encoded = encode_cbor(&request).unwrap();
        encoded.push(0);

        assert!(matches!(
            decode_cbor::<MakeCredentialRequest>(&encoded),
            Err(Ctap2Error::InvalidCbor)
        ));
    }

    #[test]
    fn test_make_credential_minimal_request_omits_optional_fields() {
        use ciborium::Value;
        // CBOR com apenas campos obrigatórios: 1=clientDataHash, 2=rp, 3=user, 4=pubKeyCredParams
        let mut map = Vec::new();
        map.push((Value::Integer(1.into()), Value::Bytes(vec![0xAA; 32])));
        map.push((
            Value::Integer(2.into()),
            Value::Map(vec![(
                Value::Text("id".to_string()),
                Value::Text("webauthn.io".to_string()),
            )]),
        ));
        map.push((
            Value::Integer(3.into()),
            Value::Map(vec![
                (Value::Text("id".to_string()), Value::Bytes(vec![1, 2, 3])),
                (Value::Text("name".to_string()), Value::Text("zequina".to_string())),
            ]),
        ));
        map.push((
            Value::Integer(4.into()),
            Value::Array(vec![Value::Map(vec![
                (Value::Text("type".to_string()), Value::Text("public-key".to_string())),
                (Value::Text("alg".to_string()), Value::Integer((-7).into())),
            ])]),
        ));
        let mut raw = Vec::new();
        ciborium::ser::into_writer(&Value::Map(map), &mut raw).unwrap();

        let req: MakeCredentialRequest = decode_cbor(&raw).expect("deve decodificar sem excludeList e options");
        assert_eq!(req.rp.id, "webauthn.io");
        assert_eq!(req.user.name.as_deref(), Some("zequina"));
        assert!(req.exclude_list.is_empty());
        assert!(req.options.up);
        assert!(!req.options.uv);
    }

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
            pin_uv_auth_param: None,
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
            pin_uv_auth_param: None,
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
    fn test_reset_denied_without_user_presence() {
        // CTAP 2.1 §6.9: sem presença física o reset é negado e as
        // credenciais permanecem intactas.
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        authenticator.set_user_presence(Some(Box::new(TestUserPresence { present: false })));

        // Credencial criada sem exigir up — só o Reset é que exige presença aqui.
        assert!(authenticator
            .make_credential(make_credential_request(false))
            .is_ok());
        assert_eq!(authenticator.get_storage().list_credentials().len(), 1);

        let error = authenticator.process_command(0x07, vec![]).unwrap_err();
        assert_eq!(error, Ctap2Error::OperationDenied);
        assert_eq!(authenticator.get_storage().list_credentials().len(), 1);
    }

    #[test]
    fn test_reset_with_presence_invalidates_issued_pin_token() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        authenticator.set_user_presence(Some(Box::new(TestUserPresence { present: true })));
        client_pin::ClientPin::set_pin(&mut authenticator, b"1234").unwrap();

        // Token emitido antes do reset autoriza MakeCredential.
        let token = vec![0xA5; 32];
        authenticator.set_pin_uv_auth_token(token.clone(), client_pin::PERMISSION_MC, None, 2);
        let mut make_request = make_credential_request(false);
        make_request.pin_protocol = Some(2);
        make_request.pin_uv_auth_param =
            Some(pin_uv_auth_param(&token, 2, &make_request.client_data_hash));
        assert!(authenticator.make_credential(make_request.clone()).is_ok());

        // Reset com presença: apaga credenciais e invalida a sessão PIN.
        let result = authenticator.process_command(0x07, vec![]).unwrap();
        assert!(result.is_empty());
        assert!(authenticator.get_storage().list_credentials().is_empty());

        // O mesmo request autenticado pelo token antigo não passa mais.
        let error = authenticator
            .make_credential(make_request)
            .expect_err("stale pinUvAuthToken must not survive Reset");
        assert_eq!(
            error.downcast_ref::<Ctap2Error>(),
            Some(&Ctap2Error::PinAuthInvalid)
        );
    }

    #[test]
    fn test_reset_clears_session_pin_state() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        authenticator.set_user_presence(Some(Box::new(TestUserPresence { present: true })));

        client_pin::ClientPin::set_pin(&mut authenticator, b"1234").unwrap();
        authenticator.set_pin_uv_auth_token(vec![0x77; 32], client_pin::PERMISSION_MC_GA, None, 2);
        authenticator
            .set_pin_agreement_key(crypto::pin_protocol::PinAgreementKey::generate().unwrap());
        authenticator.set_pin_shared_secret(vec![0x88u8; 32], 2);
        let _ = authenticator.register_pin_failure();

        authenticator.process_command(0x07, vec![]).unwrap();

        assert!(authenticator.pin_uv_auth_token.is_none());
        assert!(authenticator.pin_agreement_key.is_none());
        assert!(authenticator.pin_shared_secret.is_none());
        assert_eq!(authenticator.pin_failures_since_reset, 0);
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
                cred_protect: Some(CredProtectPolicy::UserVerificationRequired.into()),
                ..Default::default()
            }),
            options: MakeCredentialOptions {
                rk: false,
                uv: true,
                up: true,
                extended: false,
            },
            pin_uv_auth_param: None,
            pin_protocol: None,
            enterprise_protections: None,
        };

        let response = authenticator.make_credential(request).unwrap();
        let ext = response.extensions.unwrap();
        assert_eq!(ext.cred_protect, Some(0x03));
    }

    /// Extrai o credential ID do attestedCredentialData no authData:
    /// rpHash(32) || flags(1) || signCount(4) || aaguid(16) || len(2) || credId.
    fn credential_id_from_auth_data(auth_data: &[u8]) -> Vec<u8> {
        auth_data[55..71].to_vec()
    }

    fn get_assertion_request(rp_id: &str, client_data_hash: Vec<u8>) -> GetAssertionRequest {
        GetAssertionRequest {
            rp_id: rp_id.to_string(),
            credentials: vec![],
            allow_list: None,
            client_data_hash,
            extensions: None,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_protocol: None,
            uv: None,
        }
    }

    /// Credencial com credProtect=3 não pode ser asserada sem UV (silêncio →
    /// NO_CREDENTIALS); com pinUvAuthToken autenticado (permissão ga), é
    /// retornada normalmente (CTAP 2.1 §6.8.2/§12.2.2).
    #[test]
    fn test_cred_protect_uv_required_blocks_plain_get_assertion() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let mut request = make_credential_request(false);
        request.extensions = Some(Extensions {
            cred_protect: Some(CredProtectPolicy::UserVerificationRequired.into()),
            ..Default::default()
        });
        authenticator.make_credential(request).unwrap();

        // Sem token: a credencial é silenciosamente ignorada.
        let plain = get_assertion_request("example.com", b"challenge".to_vec());
        let error = authenticator.get_assertion(plain).unwrap_err();
        assert_eq!(
            error.downcast_ref::<Ctap2Error>(),
            Some(&Ctap2Error::NoCredentials)
        );

        // Com token autenticado (permissão ga): a credencial é retornada.
        let token = vec![0xC3; 32];
        authenticator.set_pin_uv_auth_token(token.clone(), client_pin::PERMISSION_GA, None, 2);
        let mut authenticated = get_assertion_request("example.com", vec![0x42; 32]);
        authenticated.pin_protocol = Some(2);
        authenticated.pin_uv_auth_param = Some(pin_uv_auth_param(
            &token,
            2,
            &authenticated.client_data_hash,
        ));
        let response = authenticator.get_assertion(authenticated).unwrap();
        assert!(response.credential.is_some());
    }

    /// RP com credenciais de políticas mistas: sem UV apenas a de nível
    /// padrão aparece; com UV válido ambas são retornadas.
    #[test]
    fn test_cred_protect_mixed_policies_filter_plain_and_authenticated() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let mut default_request = make_credential_request(false);
        default_request.user.id = b"user-l1".to_vec();
        let default_response = authenticator.make_credential(default_request).unwrap();
        let l1_id = credential_id_from_auth_data(&default_response.auth_data);

        let mut uv_request = make_credential_request(false);
        uv_request.user.id = b"user-l3".to_vec();
        uv_request.extensions = Some(Extensions {
            cred_protect: Some(CredProtectPolicy::UserVerificationRequired.into()),
            ..Default::default()
        });
        let uv_response = authenticator.make_credential(uv_request).unwrap();
        let l3_id = credential_id_from_auth_data(&uv_response.auth_data);

        // Sem UV: só a credencial de nível padrão é elegível — a UV-required
        // não é retornada e não entra na contagem de multi-assertion.
        let plain = get_assertion_request("example.com", b"challenge".to_vec());
        let response = authenticator.get_assertion(plain).unwrap();
        assert_eq!(response.credential.unwrap().id, l1_id);
        // Estado de multi-assertion nem chega a ser criado (total == 1).
        let next = authenticator.process_command(0x08, vec![]);
        assert!(matches!(next, Err(Ctap2Error::InvalidState)));

        // Com UV válido: ambas aparecem.
        let token = vec![0xC4; 32];
        authenticator.set_pin_uv_auth_token(token.clone(), client_pin::PERMISSION_GA, None, 2);
        let mut authenticated = get_assertion_request("example.com", vec![0x43; 32]);
        authenticated.pin_protocol = Some(2);
        authenticated.pin_uv_auth_param = Some(pin_uv_auth_param(
            &token,
            2,
            &authenticated.client_data_hash,
        ));
        let response = authenticator.get_assertion(authenticated).unwrap();
        assert_eq!(response.number_of_credentials, Some(2));
        assert!(matches!(&response.credential.unwrap().id, id if id == &l1_id || id == &l3_id));
    }

    /// Regra de descoberta do nível 2 (CTAP 2.1 §12.2.2): sem UV a
    /// credencial só é retornável quando nomeada na allowList da requisição;
    /// a descoberta por RP (listas vazias) deve ocultá-la.
    #[test]
    fn test_cred_protect_level2_discovery_rules() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto.clone(), storage).unwrap();

        // Credencial de nível 2 criada pelo wire format (`credProtect` como
        // inteiro CBOR).
        let raw_level2 = mc_wire_request_bytes(Value::Map(vec![(
            Value::Text("credProtect".into()),
            Value::Integer(2.into()),
        )]));
        let encoded = authenticator.process_command(0x01, raw_level2).unwrap();
        let response: Value = decode_cbor(&encoded).unwrap();
        let auth_data = cbor_bytes_field(&response, "2");
        let l2_id = credential_id_from_auth_data(&auth_data);

        // 1. Descoberta por RP (sem allowList) sem UV: silêncio total —
        //    NO_CREDENTIALS mesmo sendo a única credencial do RP.
        let plain = get_assertion_request("example.com", b"challenge-l2".to_vec());
        let error = authenticator.get_assertion(plain).unwrap_err();
        assert_eq!(
            error.downcast_ref::<Ctap2Error>(),
            Some(&Ctap2Error::NoCredentials)
        );

        // 2. AllowList nomeando a credencial de nível 2, sem UV: sucesso.
        let mut named = get_assertion_request("example.com", vec![0x51; 32]);
        named.allow_list = Some(vec![CredentialDescriptor {
            r#type: "public-key".to_string(),
            id: l2_id.clone(),
            transports: None,
        }]);
        let response = authenticator.get_assertion(named).unwrap();
        assert_eq!(response.credential.unwrap().id, l2_id);

        // 3. Descoberta por RP com UV válida: sucesso.
        let token = vec![0xD9; 32];
        authenticator.set_pin_uv_auth_token(token.clone(), client_pin::PERMISSION_GA, None, 2);
        let mut with_uv = get_assertion_request("example.com", vec![0x52; 32]);
        with_uv.pin_protocol = Some(2);
        with_uv.pin_uv_auth_param = Some(pin_uv_auth_param(&token, 2, &with_uv.client_data_hash));
        let response = authenticator.get_assertion(with_uv).unwrap();
        assert_eq!(response.credential.unwrap().id, l2_id);
    }

    /// GetNextAssertion aplica o mesmo filtro `credProtect` da asserção
    /// inicial: a credencial UV-required nunca entra na rotação sem UV.
    #[test]
    fn test_cred_protect_get_next_assertion_respects_filter() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        // Duas credenciais de nível padrão e uma UV-required no mesmo RP.
        for i in 0..2u8 {
            let mut request = make_credential_request(false);
            request.user.id = vec![i; 8];
            authenticator.make_credential(request).unwrap();
        }
        let mut uv_request = make_credential_request(false);
        uv_request.user.id = b"user-l3".to_vec();
        uv_request.extensions = Some(Extensions {
            cred_protect: Some(CredProtectPolicy::UserVerificationRequired.into()),
            ..Default::default()
        });
        authenticator.make_credential(uv_request).unwrap();

        // Sem UV: apenas as duas de nível padrão participam da multi-assertion.
        let plain = get_assertion_request("example.com", b"challenge".to_vec());
        let response = authenticator.get_assertion(plain).unwrap();
        assert_eq!(response.number_of_credentials, Some(2));

        let next = authenticator.process_command(0x08, vec![]).unwrap();
        let next_response: GetAssertionResponse = decode_cbor(&next).unwrap();
        assert_eq!(next_response.number_of_credentials, Some(2));

        // Terceira asserção não existe sem UV — a UV-required fica oculta.
        let exhausted = authenticator.process_command(0x08, vec![]);
        assert!(matches!(exhausted, Err(Ctap2Error::NoCredentials)));

        // Com UV válido: as três credenciais entram na rotação.
        let token = vec![0xC5; 32];
        authenticator.set_pin_uv_auth_token(token.clone(), client_pin::PERMISSION_GA, None, 2);
        let mut authenticated = get_assertion_request("example.com", vec![0x44; 32]);
        authenticated.pin_protocol = Some(2);
        authenticated.pin_uv_auth_param = Some(pin_uv_auth_param(
            &token,
            2,
            &authenticated.client_data_hash,
        ));
        let response = authenticator.get_assertion(authenticated).unwrap();
        assert_eq!(response.number_of_credentials, Some(3));

        assert!(authenticator.process_command(0x08, vec![]).is_ok());
        assert!(authenticator.process_command(0x08, vec![]).is_ok());
        let exhausted = authenticator.process_command(0x08, vec![]);
        assert!(matches!(exhausted, Err(Ctap2Error::NoCredentials)));
    }

    /// Credential Management deve reportar a política real por credencial em
    /// vez de omiti-la (CTAP 2.1 §6.12.2).
    #[test]
    fn test_credential_management_enumerate_reports_cred_protect() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let mut request = make_credential_request(false);
        request.options.rk = true;
        request.extensions = Some(Extensions {
            cred_protect: Some(CredProtectPolicy::UserVerificationRequired.into()),
            ..Default::default()
        });
        authenticator.make_credential(request).unwrap();

        let cm_token = vec![0xC9; 32];
        authenticator.set_pin_uv_auth_token(cm_token.clone(), client_pin::PERMISSION_CM, None, 2);

        let rp_hash = authenticator.get_crypto().sha256(b"example.com");
        let enum_req = cred_mgmt::CredentialManagementRequest {
            sub_command: cred_mgmt::sub_commands::ENUMERATE_CREDENTIALS_BEGIN,
            sub_command_params: Some(cred_mgmt::CredMgmtParams {
                rp_id_hash: Some(rp_hash),
                credential_id: None,
                user: None,
            }),
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
        };
        let encoded = authenticator
            .process_command(0x0A, signed_cred_mgmt_request(enum_req, &cm_token, 2))
            .unwrap();
        // Decodifica como Value genérico: o wire format CTAP omite campos
        // opcionais (skip_serializing_if), e o roundtrip tipado com
        // serde_bytes não é obrigatório para validar o conteúdo.
        let value: Value = ciborium::de::from_reader(encoded.as_slice()).unwrap();
        let cred_protect = cbor_field(&value, "10"); // chave CTAP 2.1 (0x0A) de credProtect
        assert_eq!(cred_protect, Some(&Value::Integer(3.into())));
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
    fn test_firmware_version_mapping() {
        assert_eq!(firmware_version_to_ctap_integer("0.1.0"), Ok(1_000));
        assert_eq!(firmware_version_to_ctap_integer("3.1.0"), Ok(3_001_000));
        assert_eq!(
            firmware_version_to_ctap_integer("1.2.3-beta+build.7"),
            Ok(1_002_003)
        );
        assert_eq!(
            firmware_version_to_ctap_integer("1000.0.0"),
            Err(Ctap2Error::Unknown)
        );
    }

    #[test]
    fn test_get_info_firmware_version_is_integer_on_wire() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        let info = authenticator.get_info().unwrap();

        let wire = encode_cbor(&info).unwrap();
        let Value::Map(entries) = ciborium::de::from_reader(wire.as_slice()).unwrap() else {
            panic!("GetInfo não é mapa");
        };
        let firmware_version = entries.into_iter().find_map(|(key, value)| match key {
            Value::Integer(number) if number == 0x0E.into() => Some(value),
            _ => None,
        });

        assert_eq!(firmware_version, Some(Value::Integer(1_000.into())));
    }

    #[test]
    fn test_get_info_options_use_ctap_map_on_wire() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        let info = authenticator.get_info().unwrap();

        let wire = encode_cbor(&info).unwrap();
        let value: Value = ciborium::de::from_reader(wire.as_slice()).unwrap();
        let Value::Map(entries) = value else {
            panic!("GetInfo não é mapa")
        };
        let options = entries
            .into_iter()
            .find_map(|(key, value)| match key {
                Value::Integer(n) if n == 4.into() => Some(value),
                _ => None,
            })
            .expect("GetInfo deve conter options na chave 0x04");
        let Value::Map(options) = options else {
            panic!("options deve ser mapa CTAP")
        };
        assert!(options.iter().any(|(key, value)| {
            matches!((key, value), (Value::Text(name), Value::Bool(true)) if name == "rk")
        }));
        assert!(options.iter().any(|(key, value)| {
            matches!((key, value), (Value::Text(name), Value::Bool(true)) if name == "up")
        }));
    }

    #[test]
    fn test_get_info_cbor_is_strictly_canonical() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        let info = authenticator.get_info().unwrap();
        let wire = encode_cbor(&info).unwrap();

        let value: ciborium::Value = ciborium::de::from_reader(wire.as_slice()).unwrap();
        let ciborium::Value::Map(entries) = value else {
            panic!("GetInfo deve ser mapa");
        };
        for window in entries.windows(2) {
            let mut a_bytes = Vec::new();
            let mut b_bytes = Vec::new();
            ciborium::ser::into_writer(&window[0].0, &mut a_bytes).unwrap();
            ciborium::ser::into_writer(&window[1].0, &mut b_bytes).unwrap();
            assert!(
                a_bytes.len() < b_bytes.len() || (a_bytes.len() == b_bytes.len() && a_bytes < b_bytes),
                "Chaves do GetInfo devem estar em ordem canônica estrita"
            );
        }
    }

    #[test]
    fn test_get_assertion_cbor_omits_null_fields_and_is_strictly_canonical() {
        let resp = GetAssertionResponse {
            credential: Some(CredentialDescriptor {
                r#type: "public-key".to_string(),
                id: vec![1, 2, 3, 4],
                transports: None,
            }),
            auth_data: vec![0u8; 37],
            signature: vec![1u8; 64],
            user: Some(User {
                id: b"test-user".to_vec(),
                name: None,
                display_name: None,
                icon_url: None,
            }),
            number_of_credentials: None,
            extensions: None,
        };
        let wire = encode_cbor(&resp).unwrap();
        let value: ciborium::Value = ciborium::de::from_reader(wire.as_slice()).unwrap();
        let ciborium::Value::Map(entries) = value else {
            panic!("GetAssertion deve ser mapa");
        };
        fn assert_no_nulls(val: &ciborium::Value) {
            match val {
                ciborium::Value::Null => panic!("Valor Null encontrado em CBOR do CTAP2!"),
                ciborium::Value::Map(m) => {
                    for (k, v) in m {
                        assert_no_nulls(k);
                        assert_no_nulls(v);
                    }
                }
                ciborium::Value::Array(a) => {
                    for v in a {
                        assert_no_nulls(v);
                    }
                }
                _ => {}
            }
        }
        assert_no_nulls(&ciborium::Value::Map(entries.clone()));
        for window in entries.windows(2) {
            let mut a_bytes = Vec::new();
            let mut b_bytes = Vec::new();
            ciborium::ser::into_writer(&window[0].0, &mut a_bytes).unwrap();
            ciborium::ser::into_writer(&window[1].0, &mut b_bytes).unwrap();
            assert!(
                a_bytes.len() < b_bytes.len() || (a_bytes.len() == b_bytes.len() && a_bytes < b_bytes),
                "Chaves do GetAssertion devem estar em ordem canônica estrita"
            );
        }
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
            pin_uv_auth_param: None,
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
            pin_uv_auth_param: None,
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
            pin_uv_auth_param: None,
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
            pin_uv_auth_param: None,
            pin_protocol: None,
            enterprise_protections: None,
        };

        let response = authenticator.make_credential(request).unwrap();
        let ext = response.extensions.unwrap();
        assert_eq!(ext.min_pin_length, Some(4));
    }

    // ── hmac-secret (CTAP 2.1 §12.5) ─────────────────────────────────────

    /// Request MakeCredential no formato de wire da spec (chaves inteiras na
    /// raiz, extensões aninhadas com `"hmac-secret": true`) decodifica sem
    /// exigir campos de outras extensões.
    #[test]
    fn test_mc_wire_request_with_hmac_secret_decodes() {
        let root = Value::Map(vec![
            (Value::Integer(1.into()), Value::Bytes(b"test".to_vec())),
            (
                Value::Integer(2.into()),
                Value::Map(vec![(
                    Value::Text("id".into()),
                    Value::Text("example.com".into()),
                )]),
            ),
            (
                Value::Integer(3.into()),
                Value::Map(vec![(
                    Value::Text("id".into()),
                    Value::Bytes(b"user123".to_vec()),
                )]),
            ),
            (
                Value::Integer(4.into()),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                    (Value::Text("alg".into()), Value::Integer((-7).into())),
                ])]),
            ),
            (Value::Integer(5.into()), Value::Array(vec![])),
            (
                Value::Integer(6.into()),
                Value::Map(vec![(Value::Text("hmac-secret".into()), Value::Bool(true))]),
            ),
            (
                Value::Integer(7.into()),
                Value::Map(vec![
                    (Value::Text("rk".into()), Value::Bool(false)),
                    (Value::Text("uv".into()), Value::Bool(false)),
                    (Value::Text("up".into()), Value::Bool(true)),
                ]),
            ),
        ]);
        let mut raw = Vec::new();
        into_writer(&root, &mut raw).unwrap();
        match decode_cbor::<MakeCredentialRequest>(&raw) {
            Ok(request) => assert_eq!(
                request.extensions.unwrap().hmac_secret,
                Some(Value::Bool(true))
            ),
            Err(error) => panic!("decode falhou: {error:?}"),
        }
    }

    use crate::client_pin::{self, ClientPinRequest, ClientPinSubCommand};
    use crypto::pin_protocol::{PinAgreementKey, PinUvProtocol, Zeroizing};

    /// Request MakeCredential canônico (chaves inteiras na raiz) com o mapa
    /// de extensões fornecido — formato real enviado pelas plataformas.
    fn mc_wire_request_bytes(extensions: Value) -> Vec<u8> {
        let root = Value::Map(vec![
            (Value::Integer(1.into()), Value::Bytes(b"test".to_vec())),
            (
                Value::Integer(2.into()),
                Value::Map(vec![(
                    Value::Text("id".into()),
                    Value::Text("example.com".into()),
                )]),
            ),
            (
                Value::Integer(3.into()),
                Value::Map(vec![(
                    Value::Text("id".into()),
                    Value::Bytes(b"user123".to_vec()),
                )]),
            ),
            (
                Value::Integer(4.into()),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                    (Value::Text("alg".into()), Value::Integer((-7).into())),
                ])]),
            ),
            (Value::Integer(5.into()), Value::Array(vec![])),
            (Value::Integer(6.into()), extensions),
            (
                Value::Integer(7.into()),
                Value::Map(vec![
                    (Value::Text("rk".into()), Value::Bool(false)),
                    (Value::Text("uv".into()), Value::Bool(false)),
                    (Value::Text("up".into()), Value::Bool(true)),
                ]),
            ),
        ]);
        let mut raw = Vec::new();
        into_writer(&root, &mut raw).unwrap();
        raw
    }

    #[test]
    fn test_extensions_wire_cred_protect_decodes_from_integer() {
        // CTAP 2.1 §12.2.2: `"credProtect"` chega como inteiro CBOR no mapa
        // de extensões; todos os níveis da spec devem decodificar para o
        // nível correspondente.
        let expected = [
            (1u64, CredProtectPolicy::UserVerificationOptional),
            (
                2,
                CredProtectPolicy::UserVerificationOptionalWithCredentialIDList,
            ),
            (3, CredProtectPolicy::UserVerificationRequired),
        ];
        for (level, policy) in expected {
            let extensions = Value::Map(vec![(
                Value::Text("credProtect".into()),
                Value::Integer(level.into()),
            )]);
            let raw = mc_wire_request_bytes(extensions);
            let request: MakeCredentialRequest = decode_cbor(&raw)
                .unwrap_or_else(|error| panic!("decode falhou para nível {level}: {error:?}"));
            let ext = request.extensions.expect("extensões perdidas no decode");
            assert_eq!(
                ext.cred_protect,
                Some(level as u8),
                "nível {level} não decodificado"
            );
            assert_eq!(CredProtectPolicy::from(ext.cred_protect.unwrap()), policy);
        }
    }

    #[test]
    fn test_extensions_wire_cred_blob_decodes_alone_and_combined() {
        // `"credBlob"` é byte string CBOR; deve decodificar sozinha e em um
        // mapa combinado com as demais extensões anunciadas pelo GetInfo.
        let blob = b"blob-bytes".to_vec();

        let alone = Value::Map(vec![(
            Value::Text("credBlob".into()),
            Value::Bytes(blob.clone()),
        )]);
        let raw = mc_wire_request_bytes(alone);
        let request: MakeCredentialRequest =
            decode_cbor(&raw).expect("`credBlob` isolado deve decodificar");
        let ext = request.extensions.expect("extensões ausentes");
        assert_eq!(ext.cred_blob.as_deref(), Some(blob.as_slice()));

        let combined = Value::Map(vec![
            (Value::Text("credProtect".into()), Value::Integer(3.into())),
            (Value::Text("credBlob".into()), Value::Bytes(blob.clone())),
            (Value::Text("minPinLength".into()), Value::Bool(true)),
            (Value::Text("largeBlobKey".into()), Value::Bool(true)),
        ]);
        let raw = mc_wire_request_bytes(combined);
        let request: MakeCredentialRequest =
            decode_cbor(&raw).expect("mapa combinado de extensões deve decodificar");
        let ext = request.extensions.expect("extensões ausentes");
        assert_eq!(ext.cred_protect, Some(3));
        assert_eq!(ext.cred_blob.as_deref(), Some(blob.as_slice()));
        assert!(ext.min_pin_length);
        assert!(ext.large_blob_key);
    }

    /// GetAssertion mínimo da spec (`{1: rpId, 2: clientDataHash}`, sem
    /// allowList nem options) deve decodificar e seguir o fluxo normal até
    /// NO_CREDENTIALS em vez de falhar com InvalidCbor (CTAP 2.1 §6.8.3).
    #[test]
    fn test_get_assertion_minimal_spec_request_decodes() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let root = Value::Map(vec![
            (Value::Integer(1.into()), Value::Text("example.com".into())),
            (
                Value::Integer(2.into()),
                Value::Bytes(b"challenge".to_vec()),
            ),
        ]);
        let mut raw = Vec::new();
        into_writer(&root, &mut raw).unwrap();

        match authenticator.process_command(0x02, raw) {
            Err(Ctap2Error::NoCredentials) => {}
            Err(error) => panic!("erro errado para request mínimo: {error:?}"),
            Ok(_) => panic!("request mínimo não deveria ter credenciais"),
        }
    }

    fn mc_request_with(extensions: Option<Extensions>) -> MakeCredentialRequest {
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
            extensions,
            options: MakeCredentialOptions {
                rk: false,
                uv: false,
                up: true,
                extended: false,
            },
            pin_uv_auth_param: None,
            pin_protocol: None,
            enterprise_protections: None,
        }
    }

    /// Lado plataforma da extensão: chave pública COSE, protocolo e segredo
    /// compartilhado derivado do getKeyAgreement do autenticador.
    struct PlatformSide {
        protocol: PinUvProtocol,
        secret: Zeroizing<Vec<u8>>,
        public_cose: client_pin::CoseEc2Key,
    }

    impl PlatformSide {
        /// Executa getKeyAgreement (0x02) e deriva o segredo compartilhado,
        /// espelhando `fido2.ctap2.pin.ClientPin._get_shared_secret`.
        fn start(authenticator: &mut Ctap2Authenticator, version: u8) -> Self {
            let request = ClientPinRequest {
                pin_protocol: Some(version),
                sub_command: ClientPinSubCommand::GetKeyAgreement as u8,
                ..Default::default()
            };
            let encoded = client_pin::encode_client_pin_request_array(&request).unwrap();
            let response_bytes = client_pin::handle_client_pin(authenticator, &encoded).unwrap();
            let response = client_pin::decode_client_pin_response(&response_bytes).unwrap();
            let cose_bytes = response.key_agreement.expect("keyAgreement ausente");
            let auth_cose_value: Value = from_reader(cose_bytes.as_slice()).unwrap();
            let auth_cose = client_pin::CoseEc2Key::from_cose_value(&auth_cose_value).unwrap();

            let platform_key = PinAgreementKey::generate().unwrap();
            let public = platform_key.public_key_bytes().unwrap();
            let public_cose = client_pin::CoseEc2Key {
                x: public[1..33].to_vec(),
                y: public[33..65].to_vec(),
            };
            let z = Zeroizing::new(
                platform_key
                    .agree(&auth_cose.to_uncompressed().unwrap())
                    .unwrap(),
            );
            let protocol = PinUvProtocol::new(version).unwrap();
            let secret = Zeroizing::new(protocol.kdf(&z).unwrap());
            Self {
                protocol,
                secret,
                public_cose,
            }
        }

        /// Acordo "órfão": a plataforma deriva um segredo sem getKeyAgreement
        /// prévio — o autenticador não possui a chave efêmera correspondente.
        fn orphan(version: u8) -> Self {
            let protocol = PinUvProtocol::new(version).unwrap();
            let key = PinAgreementKey::generate().unwrap();
            let public = key.public_key_bytes().unwrap();
            let public_cose = client_pin::CoseEc2Key {
                x: public[1..33].to_vec(),
                y: public[33..65].to_vec(),
            };
            let z = Zeroizing::new(key.agree(&public).unwrap());
            let secret = Zeroizing::new(protocol.kdf(&z).unwrap());
            Self {
                protocol,
                secret,
                public_cose,
            }
        }

        /// Monta o mapa de entrada da extensão para os salts dados.
        fn extension(&self, salts: &[u8]) -> Extensions {
            let salt_enc = self.protocol.encrypt(&self.secret, salts).unwrap();
            let salt_auth = self.protocol.authenticate(&self.secret, &salt_enc).unwrap();
            let version = self.protocol.version();
            Extensions {
                hmac_secret: Some(Value::Map(vec![
                    (Value::Integer(1.into()), self.public_cose.to_cose_value()),
                    (Value::Integer(2.into()), Value::Bytes(salt_enc)),
                    (Value::Integer(3.into()), Value::Bytes(salt_auth)),
                    // §12.5: plataformas CTAP 2.1 incluem pinUvAuthProtocol
                    // sempre que o valor não é 1.
                    (
                        Value::Integer(4.into()),
                        Value::Integer((version as i64).into()),
                    ),
                ])),
                ..Default::default()
            }
        }

        fn ga_request(
            &self,
            credential_id: Vec<u8>,
            crypto: &CryptoEngine,
            uv: bool,
        ) -> GetAssertionRequest {
            GetAssertionRequest {
                rp_id: "example.com".to_string(),
                credentials: vec![CredentialDescriptor {
                    r#type: "public-key".to_string(),
                    id: credential_id,
                    transports: None,
                }],
                allow_list: None,
                client_data_hash: crypto.sha256(b"client data hash"),
                extensions: None,
                options: GetAssertionOptions { up: true, uv },
                pin_uv_auth_param: None,
                pin_protocol: None,
                uv: Some(uv),
            }
        }

        fn decrypt_output(&self, value: Option<Value>) -> Vec<u8> {
            match value.expect("saída hmac-secret ausente") {
                Value::Bytes(bytes) => self.protocol.decrypt(&self.secret, &bytes).unwrap(),
                other => panic!("saída inesperada da extensão: {:?}", other),
            }
        }
    }

    fn expected_outputs(crypto: &CryptoEngine, cred_random: &[u8], salts: &[u8]) -> Vec<u8> {
        let mut outputs = Vec::new();
        for salt in salts.chunks(32) {
            outputs.extend_from_slice(&crypto.compute_hmac(salt, cred_random).unwrap());
        }
        outputs
    }

    #[test]
    fn test_hmac_secret_mc_returns_true_and_persists_cred_random() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto.clone(), storage).unwrap();

        let request = mc_request_with(Some(Extensions {
            hmac_secret: Some(Value::Bool(true)),
            ..Default::default()
        }));
        let response = authenticator.make_credential(request).unwrap();

        // §12.5: MakeCredential responde apenas a confirmação booleana.
        assert_eq!(
            response.extensions.unwrap().hmac_secret,
            Some(Value::Bool(true))
        );

        let stored = authenticator.get_storage().list_credentials();
        let with_uv = stored[0].cred_random_with_uv.as_ref().unwrap();
        let without_uv = stored[0].cred_random_without_uv.as_ref().unwrap();
        assert_eq!(with_uv.len(), 32);
        assert_eq!(without_uv.len(), 32);
        assert_ne!(with_uv, without_uv);
        assert!(with_uv.iter().any(|b| *b != 0));
        assert!(without_uv.iter().any(|b| *b != 0));

        // Sem a extensão, nenhum CredRandom é gerado.
        authenticator
            .make_credential(mc_request_with(None))
            .unwrap();
        let stored = authenticator.get_storage().list_credentials();
        let second = stored
            .iter()
            .find(|c| c.cred_random_with_uv.is_none())
            .expect("segunda credencial sem hmac-secret");
        assert!(second.cred_random_without_uv.is_none());
    }

    #[test]
    fn test_hmac_secret_mc_false_generates_nothing() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let request = mc_request_with(Some(Extensions {
            hmac_secret: Some(Value::Bool(false)),
            ..Default::default()
        }));
        let response = authenticator.make_credential(request).unwrap();
        assert_eq!(response.extensions.unwrap().hmac_secret, None);

        let stored = authenticator.get_storage().list_credentials();
        assert!(stored[0].cred_random_with_uv.is_none());
        assert!(stored[0].cred_random_without_uv.is_none());
    }

    fn full_get_assertion_roundtrip(version: u8) {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto.clone(), storage).unwrap();

        authenticator
            .make_credential(mc_request_with(Some(Extensions {
                hmac_secret: Some(Value::Bool(true)),
                ..Default::default()
            })))
            .unwrap();
        let credential = authenticator
            .get_storage()
            .list_credentials()
            .into_iter()
            .next()
            .unwrap()
            .clone();
        let with_uv = credential.cred_random_with_uv.clone().unwrap();

        // Bit UV verdadeiro: selecionar CredRandomWithUV exige autenticação
        // real — cada GetAssertion abaixo carrega pinUvAuthToken(ga).
        let token = vec![0xD1u8; 32];
        authenticator.set_pin_uv_auth_token(
            token.clone(),
            client_pin::PERMISSION_GA,
            None,
            version,
        );

        let salt1 = [0x11u8; 32];
        let salt2 = [0x22u8; 32];
        for salts in [
            salt1.to_vec(),
            [salt1.as_slice(), salt2.as_slice()].concat(),
        ] {
            // Cada GetAssertion usa um getKeyAgreement fresco, como faz o
            // python-fido2 (`_get_shared_secret` antes de cada operação).
            let platform = PlatformSide::start(&mut authenticator, version);
            let mut request = platform.ga_request(credential.credential_id.clone(), &crypto, true);
            request.pin_protocol = Some(version);
            request.pin_uv_auth_param = Some(pin_uv_auth_param(
                &token,
                version,
                &request.client_data_hash,
            ));
            request.extensions = Some(platform.extension(&salts));
            let assertion = authenticator.get_assertion(request).unwrap();

            let decrypted = platform.decrypt_output(assertion.extensions.unwrap().hmac_secret);
            assert_eq!(decrypted, expected_outputs(&crypto, &with_uv, &salts));
            assert_eq!(decrypted.len(), if salts.len() == 32 { 32 } else { 64 });
        }
    }

    #[test]
    fn test_hmac_secret_roundtrip_protocol_1() {
        full_get_assertion_roundtrip(1);
    }

    #[test]
    fn test_hmac_secret_roundtrip_protocol_2() {
        full_get_assertion_roundtrip(2);
    }

    /// §12.5 com bit UV verdadeiro: a saída usa CredRandomWithUV somente
    /// quando a operação foi autenticada (pinUvAuthToken); sem autenticação,
    /// mesmo com `uv` pedido, deriva de CredRandomWithoutUV.
    #[test]
    fn test_hmac_secret_selects_cred_random_by_uv_bit() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto.clone(), storage).unwrap();

        authenticator
            .make_credential(mc_request_with(Some(Extensions {
                hmac_secret: Some(Value::Bool(true)),
                ..Default::default()
            })))
            .unwrap();
        let credential = authenticator
            .get_storage()
            .list_credentials()
            .into_iter()
            .next()
            .unwrap()
            .clone();
        let with_uv = credential.cred_random_with_uv.clone().unwrap();
        let without_uv = credential.cred_random_without_uv.clone().unwrap();

        let salts = [0x33u8; 32];

        // Sem autenticação real, mesmo pedindo uv=1 a resposta não pode
        // alegar verificação — saída deriva de CredRandomWithoutUV.
        let platform = PlatformSide::start(&mut authenticator, 2);
        let mut request = platform.ga_request(credential.credential_id.clone(), &crypto, true);
        request.extensions = Some(platform.extension(&salts));
        let assertion = authenticator.get_assertion(request).unwrap();
        let out_without_uv = platform.decrypt_output(assertion.extensions.unwrap().hmac_secret);
        assert_eq!(
            out_without_uv,
            expected_outputs(&crypto, &without_uv, &salts)
        );

        // Com pinUvAuthToken(ga) autenticado para esta operação:
        // verificação satisfeita → CredRandomWithUV.
        let token = vec![0xC6; 32];
        authenticator.set_pin_uv_auth_token(token.clone(), client_pin::PERMISSION_GA, None, 2);
        let platform = PlatformSide::start(&mut authenticator, 2);
        let mut request = platform.ga_request(credential.credential_id.clone(), &crypto, true);
        request.pin_protocol = Some(2);
        request.pin_uv_auth_param = Some(pin_uv_auth_param(&token, 2, &request.client_data_hash));
        request.extensions = Some(platform.extension(&salts));
        let assertion = authenticator.get_assertion(request).unwrap();
        let out_with_uv = platform.decrypt_output(assertion.extensions.unwrap().hmac_secret);
        assert_eq!(out_with_uv, expected_outputs(&crypto, &with_uv, &salts));

        assert_ne!(out_with_uv, out_without_uv);
    }

    /// O bit UV do authData reflete apenas verificação REALIZADA (WebAuthn
    /// L3 §6.1): pedir `options.uv = true` sem PIN configurado e sem
    /// pinUvAuthToken não verifica usuário algum — a operação prossegue SEM
    /// alegar UV; com token autenticado para a operação, o bit é setado.
    #[test]
    fn test_uv_flag_requires_actual_verification() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto.clone(), storage).unwrap();

        // MakeCredential pedindo uv sem nenhum verificador disponível.
        let mut make_request = make_credential_request(true);
        make_request.options.uv = true;
        let response = authenticator.make_credential(make_request).unwrap();
        assert_eq!(
            response.auth_data[32] & 0x04,
            0,
            "bit UV não pode ser alegado sem verificação"
        );
        assert_ne!(response.auth_data[32] & 0x01, 0);

        // GetAssertion na mesma situação.
        let mut plain = get_assertion_request("example.com", b"challenge".to_vec());
        plain.options.uv = true;
        let response = authenticator.get_assertion(plain).unwrap();
        assert_eq!(response.auth_data[32] & 0x04, 0);

        // Com pinUvAuthToken(ga) autenticando esta operação: bit UV setado.
        let token = vec![0xD7; 32];
        authenticator.set_pin_uv_auth_token(token.clone(), client_pin::PERMISSION_GA, None, 2);
        let mut verified = get_assertion_request("example.com", vec![0x71; 32]);
        verified.pin_protocol = Some(2);
        verified.pin_uv_auth_param = Some(pin_uv_auth_param(&token, 2, &verified.client_data_hash));
        let response = authenticator.get_assertion(verified).unwrap();
        assert_ne!(response.auth_data[32] & 0x04, 0);
    }

    /// Com PIN configurado existe verificador disponível: pedir `uv` sem
    /// autenticação continua negando com PIN_REQUIRED (gate existente).
    #[test]
    fn test_uv_requested_with_pin_set_still_requires_authentication() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto.clone(), storage).unwrap();

        // Credencial pré-existente criada antes do PIN.
        let mut seed = make_credential_request(false);
        seed.options.uv = false;
        authenticator.make_credential(seed).unwrap();
        client_pin::ClientPin::set_pin(&mut authenticator, b"1234").unwrap();

        let mut make_request = make_credential_request(true);
        make_request.options.uv = true;
        let error = authenticator.make_credential(make_request).unwrap_err();
        assert_eq!(
            error.downcast_ref::<Ctap2Error>(),
            Some(&Ctap2Error::PinRequired)
        );

        let plain = get_assertion_request("example.com", b"challenge".to_vec());
        let mut plain = plain;
        plain.options.uv = true;
        let error = authenticator.get_assertion(plain).unwrap_err();
        assert_eq!(
            error.downcast_ref::<Ctap2Error>(),
            Some(&Ctap2Error::PinRequired)
        );
    }

    /// §12.5 com bit UV verdadeiro: sem verificação real (nem token), mesmo
    /// pedindo `uv`, a saída deriva de CredRandomWithoutUV; com
    /// pinUvAuthToken(ga) autenticado, deriva de CredRandomWithUV.
    #[test]
    fn test_hmac_secret_withuv_output_requires_authentication() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto.clone(), storage).unwrap();

        authenticator
            .make_credential(mc_request_with(Some(Extensions {
                hmac_secret: Some(Value::Bool(true)),
                ..Default::default()
            })))
            .unwrap();
        let credential = authenticator
            .get_storage()
            .list_credentials()
            .into_iter()
            .next()
            .unwrap()
            .clone();
        let with_uv = credential.cred_random_with_uv.clone().unwrap();
        let without_uv = credential.cred_random_without_uv.clone().unwrap();
        let salts = [0x3Bu8; 32];

        // Sem token (uv pedido e não atendido): WithoutUV.
        let platform = PlatformSide::start(&mut authenticator, 2);
        let mut request = platform.ga_request(credential.credential_id.clone(), &crypto, true);
        request.extensions = Some(platform.extension(&salts));
        let assertion = authenticator.get_assertion(request).unwrap();
        let out_without_uv = platform.decrypt_output(assertion.extensions.unwrap().hmac_secret);
        assert_eq!(
            out_without_uv,
            expected_outputs(&crypto, &without_uv, &salts)
        );

        // Token ga autenticado: WithUV.
        let token = vec![0xD8; 32];
        authenticator.set_pin_uv_auth_token(token.clone(), client_pin::PERMISSION_GA, None, 2);
        let platform = PlatformSide::start(&mut authenticator, 2);
        let mut request = platform.ga_request(credential.credential_id.clone(), &crypto, true);
        request.pin_protocol = Some(2);
        request.pin_uv_auth_param = Some(pin_uv_auth_param(&token, 2, &request.client_data_hash));
        request.extensions = Some(platform.extension(&salts));
        let assertion = authenticator.get_assertion(request).unwrap();
        let out_with_uv = platform.decrypt_output(assertion.extensions.unwrap().hmac_secret);
        assert_eq!(out_with_uv, expected_outputs(&crypto, &with_uv, &salts));

        assert_ne!(out_with_uv, out_without_uv);
    }

    #[test]
    fn test_hmac_secret_saltauth_mismatch_fails() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto.clone(), storage).unwrap();

        authenticator
            .make_credential(mc_request_with(Some(Extensions {
                hmac_secret: Some(Value::Bool(true)),
                ..Default::default()
            })))
            .unwrap();
        let credential = authenticator
            .get_storage()
            .list_credentials()
            .into_iter()
            .next()
            .unwrap()
            .clone();

        // §12.5: verify(shared secret, saltEnc, saltAuth) falho → PIN_AUTH_INVALID.
        let platform = PlatformSide::start(&mut authenticator, 1);
        let mut extensions = platform.extension(&[0x44u8; 32]);
        if let Some(Value::Map(entries)) = extensions.hmac_secret.as_mut() {
            for (key, value) in entries.iter_mut() {
                if *key == Value::Integer(3.into()) {
                    if let Value::Bytes(tag) = value {
                        tag[0] ^= 0xFF;
                    }
                }
            }
        }
        let mut request = platform.ga_request(credential.credential_id.clone(), &crypto, true);
        request.extensions = Some(extensions);

        let error = authenticator.get_assertion(request).unwrap_err();
        assert_eq!(
            error.downcast_ref::<Ctap2Error>().unwrap(),
            &Ctap2Error::PinAuthInvalid
        );
    }

    #[test]
    fn test_hmac_secret_invalid_salt_length_fails() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto.clone(), storage).unwrap();

        authenticator
            .make_credential(mc_request_with(Some(Extensions {
                hmac_secret: Some(Value::Bool(true)),
                ..Default::default()
            })))
            .unwrap();
        let credential = authenticator
            .get_storage()
            .list_credentials()
            .into_iter()
            .next()
            .unwrap()
            .clone();

        // §12.5: plaintext não 32/64 bytes → CTAP1_ERR_INVALID_PARAMETER.
        let platform = PlatformSide::start(&mut authenticator, 2);
        let extensions = platform.extension(&[0x55u8; 48]);
        let mut request = platform.ga_request(credential.credential_id.clone(), &crypto, true);
        request.extensions = Some(extensions);

        let error = authenticator.get_assertion(request).unwrap_err();
        assert_eq!(
            error.downcast_ref::<Ctap2Error>().unwrap(),
            &Ctap2Error::InvalidParameter
        );
    }

    #[test]
    fn test_hmac_secret_without_cred_random_is_ignored() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto.clone(), storage).unwrap();

        // Credencial criada sem a extensão: nenhum CredRandom persistido.
        authenticator
            .make_credential(mc_request_with(None))
            .unwrap();
        let credential = authenticator
            .get_storage()
            .list_credentials()
            .into_iter()
            .next()
            .unwrap()
            .clone();
        assert!(credential.cred_random_with_uv.is_none());

        // §12.5: sem CredRandom associado a extensão é ignorada — a asserção
        // prossegue sem saída para ela.
        let platform = PlatformSide::start(&mut authenticator, 1);
        let mut request = platform.ga_request(credential.credential_id.clone(), &crypto, true);
        request.extensions = Some(platform.extension(&[0x66u8; 32]));
        let assertion = authenticator.get_assertion(request).unwrap();
        assert_eq!(assertion.extensions.unwrap().hmac_secret, None);
    }

    #[test]
    fn test_hmac_secret_requires_up_option() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto.clone(), storage).unwrap();

        authenticator
            .make_credential(mc_request_with(Some(Extensions {
                hmac_secret: Some(Value::Bool(true)),
                ..Default::default()
            })))
            .unwrap();
        let credential = authenticator
            .get_storage()
            .list_credentials()
            .into_iter()
            .next()
            .unwrap()
            .clone();

        // §12.5: "up" falso no GetAssertion → UNSUPPORTED_OPTION.
        let platform = PlatformSide::start(&mut authenticator, 1);
        let mut request = platform.ga_request(credential.credential_id.clone(), &crypto, true);
        request.options.up = false;
        request.extensions = Some(platform.extension(&[0x77u8; 32]));
        let error = authenticator.get_assertion(request).unwrap_err();
        assert_eq!(
            error.downcast_ref::<Ctap2Error>().unwrap(),
            &Ctap2Error::UnsupportedOption
        );
    }

    #[test]
    fn test_hmac_secret_orphan_agreement_fails() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto.clone(), storage).unwrap();

        authenticator
            .make_credential(mc_request_with(Some(Extensions {
                hmac_secret: Some(Value::Bool(true)),
                ..Default::default()
            })))
            .unwrap();
        let credential = authenticator
            .get_storage()
            .list_credentials()
            .into_iter()
            .next()
            .unwrap()
            .clone();

        // Sem getKeyAgreement prévio o autenticador não tem a chave efêmera
        // desta transação: o processamento falha com PIN_AUTH_INVALID.
        let platform = PlatformSide::orphan(2);
        let mut request = platform.ga_request(credential.credential_id.clone(), &crypto, true);
        request.extensions = Some(platform.extension(&[0x88u8; 32]));
        let error = authenticator.get_assertion(request).unwrap_err();
        assert_eq!(
            error.downcast_ref::<Ctap2Error>().unwrap(),
            &Ctap2Error::PinAuthInvalid
        );
    }

    #[test]
    fn test_hmac_secret_fresh_nonce_per_request() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto.clone(), storage).unwrap();

        authenticator
            .make_credential(mc_request_with(Some(Extensions {
                hmac_secret: Some(Value::Bool(true)),
                ..Default::default()
            })))
            .unwrap();
        let credential = authenticator
            .get_storage()
            .list_credentials()
            .into_iter()
            .next()
            .unwrap()
            .clone();

        // Duas requisições idênticas: ciphertexts diferentes (IV fresco via
        // SystemRandom no protocolo 2), plaintexts iguais.
        let salts = [0x99u8; 32];
        let first_side = PlatformSide::start(&mut authenticator, 2);
        let mut first = first_side.ga_request(credential.credential_id.clone(), &crypto, true);
        first.extensions = Some(first_side.extension(&salts));
        let out_first = authenticator.get_assertion(first).unwrap();
        let enc_first = match out_first.extensions.unwrap().hmac_secret.unwrap() {
            Value::Bytes(v) => v,
            other => panic!("saída inesperada: {:?}", other),
        };

        let second_side = PlatformSide::start(&mut authenticator, 2);
        let mut second = second_side.ga_request(credential.credential_id.clone(), &crypto, true);
        second.extensions = Some(second_side.extension(&salts));
        let out_second = authenticator.get_assertion(second).unwrap();
        let enc_second = match out_second.extensions.unwrap().hmac_secret.unwrap() {
            Value::Bytes(v) => v,
            other => panic!("saída inesperada: {:?}", other),
        };

        assert_ne!(enc_first, enc_second);
        assert_eq!(
            first_side
                .protocol
                .decrypt(&first_side.secret, &enc_first)
                .unwrap(),
            second_side
                .protocol
                .decrypt(&second_side.secret, &enc_second)
                .unwrap()
        );
    }

    /// GetAssertion de descoberta por RP (listas vazias) com a extensão —
    /// forma necessária para encadear (matching contém todas as credenciais
    /// do RP), distinta do request nomeado de [`PlatformSide::ga_request`].
    fn ga_discovery_request(
        platform: &PlatformSide,
        crypto: &CryptoEngine,
        salts: &[u8],
    ) -> GetAssertionRequest {
        GetAssertionRequest {
            rp_id: "example.com".to_string(),
            credentials: vec![],
            allow_list: None,
            client_data_hash: crypto.sha256(b"client data hash"),
            extensions: Some(platform.extension(salts)),
            options: GetAssertionOptions {
                up: true,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_protocol: None,
            uv: Some(false),
        }
    }

    fn raw_hmac_bytes(value: Option<Value>) -> Vec<u8> {
        match value.expect("saída hmac-secret ausente") {
            Value::Bytes(bytes) => bytes,
            other => panic!("saída inesperada da extensão: {:?}", other),
        }
    }

    /// Asserções encadeadas com hmac-secret (CTAP 2.1 §12.5 + ADR-0022): a
    /// saída do GetNextAssertion é `HMAC(CredRandom_da_segunda_credencial,
    /// salt)` cifrada sob o MESMO segredo compartilhado da asserção inicial
    /// (a plataforma não repete o getKeyAgreement no meio da transação).
    /// Sem autenticação, ambas derivam de CredRandomWithoutUV.
    fn chained_get_next_assertion_roundtrip(version: u8) {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto.clone(), storage).unwrap();

        // Duas credenciais residentes, mesmo RP, usuários distintos.
        for user_id in [b"user-one".as_slice(), b"user-two".as_slice()] {
            let mut request = mc_request_with(Some(Extensions {
                hmac_secret: Some(Value::Bool(true)),
                ..Default::default()
            }));
            request.user.id = user_id.to_vec();
            authenticator.make_credential(request).unwrap();
        }
        let stored = authenticator.get_storage().list_credentials();
        assert_eq!(stored.len(), 2);
        let cred_randoms: Vec<(Vec<u8>, Vec<u8>)> = stored
            .iter()
            .map(|c| {
                (
                    c.credential_id.clone(),
                    c.cred_random_without_uv.clone().unwrap(),
                )
            })
            .collect();

        let salts = [0x5Au8; 32];
        let platform = PlatformSide::start(&mut authenticator, version);
        let assertion = authenticator
            .get_assertion(ga_discovery_request(&platform, &crypto, &salts))
            .unwrap();
        assert_eq!(assertion.number_of_credentials, Some(2));
        let first_id = assertion.credential.as_ref().unwrap().id.clone();
        let first_enc = raw_hmac_bytes(
            assertion
                .extensions
                .as_ref()
                .and_then(|e| e.hmac_secret.clone()),
        );

        // Identifica os CredRandoms de cada posição da cadeia.
        let first_entry = cred_randoms
            .iter()
            .find(|(id, _)| *id == first_id)
            .expect("asserção inicial deve usar uma das credenciais");
        let second_entry = cred_randoms
            .iter()
            .find(|(id, _)| *id != first_id)
            .expect("exatamente uma outra credencial na cadeia");
        let first_random = &first_entry.1;
        let second_random = &second_entry.1;
        let second_id = &second_entry.0;

        let decrypted_first = platform.decrypt_output(Some(Value::Bytes(first_enc.clone())));
        assert_eq!(
            decrypted_first,
            expected_outputs(&crypto, first_random, &salts)
        );

        // GetNextAssertion: a cadeia produz saída para a segunda credencial.
        let encoded = authenticator.process_command(0x08, vec![]).unwrap();
        let chained: GetAssertionResponse = decode_cbor(&encoded).unwrap();
        assert_eq!(&chained.credential.as_ref().unwrap().id, second_id);
        assert_eq!(chained.number_of_credentials, Some(2));
        let chained_enc = raw_hmac_bytes(
            chained
                .extensions
                .as_ref()
                .and_then(|e| e.hmac_secret.clone()),
        );

        // IV fresco por resposta: ciphertexts diferem embora os tamanhos
        // coincidam (32B); decifram sob o MESMO segredo compartilhado.
        assert_ne!(first_enc, chained_enc);
        assert_eq!(
            platform
                .protocol
                .decrypt(&platform.secret, &chained_enc)
                .unwrap(),
            expected_outputs(&crypto, second_random, &salts)
        );
        // Determinismo da derivação: plaintexts distintos entre credenciais.
        assert_ne!(
            expected_outputs(&crypto, first_random, &salts),
            expected_outputs(&crypto, second_random, &salts)
        );

        // Cadeia esgotada: erro e sessão descartada.
        let exhausted = authenticator.process_command(0x08, vec![]);
        assert!(matches!(exhausted, Err(Ctap2Error::NoCredentials)));
        assert!(authenticator.hmac_secret_session.is_none());
        // Estado consumido na exaustão: nova tentativa não tem transação.
        assert!(matches!(
            authenticator.process_command(0x08, vec![]),
            Err(Ctap2Error::InvalidState)
        ));
    }

    #[test]
    fn test_hmac_secret_chained_get_next_assertion_protocol_1() {
        chained_get_next_assertion_roundtrip(1);
    }

    #[test]
    fn test_hmac_secret_chained_get_next_assertion_protocol_2() {
        chained_get_next_assertion_roundtrip(2);
    }

    /// Qualquer comando que não seja GetNextAssertion encerra a sessão
    /// hmac-secret (ADR-0022). O encadeamento em si permanece intacto — a
    /// asserção seguinte sai SEM a extensão, como antes da sessão existir.
    #[test]
    fn test_hmac_secret_chain_cleared_by_other_command() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto.clone(), storage).unwrap();

        for user_id in [b"user-a".as_slice(), b"user-b".as_slice()] {
            let mut request = mc_request_with(Some(Extensions {
                hmac_secret: Some(Value::Bool(true)),
                ..Default::default()
            }));
            request.user.id = user_id.to_vec();
            authenticator.make_credential(request).unwrap();
        }

        let platform = PlatformSide::start(&mut authenticator, 2);
        let assertion = authenticator
            .get_assertion(ga_discovery_request(&platform, &crypto, &[0x71u8; 32]))
            .unwrap();
        assert!(assertion.extensions.unwrap().hmac_secret.is_some());
        assert!(authenticator.hmac_secret_session.is_some());

        // Comando intermediário (GetInfo) quebra a sessão hmac-secret…
        assert!(authenticator.process_command(0x04, vec![]).is_ok());
        assert!(authenticator.hmac_secret_session.is_none());

        // …sem alterar a semântica preexistente do encadeamento.
        let encoded = authenticator.process_command(0x08, vec![]).unwrap();
        let chained: GetAssertionResponse = decode_cbor(&encoded).unwrap();
        assert!(matches!(
            authenticator.process_command(0x08, vec![]),
            Err(Ctap2Error::NoCredentials)
        ));
        assert!(chained.extensions.is_none());
    }

    /// Reset limpa a sessão hmac-secret junto com as credenciais (ADR-0022).
    #[test]
    fn test_hmac_secret_session_cleared_on_reset() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto.clone(), storage).unwrap();

        for user_id in [b"user-a".as_slice(), b"user-b".as_slice()] {
            let mut request = mc_request_with(Some(Extensions {
                hmac_secret: Some(Value::Bool(true)),
                ..Default::default()
            }));
            request.user.id = user_id.to_vec();
            authenticator.make_credential(request).unwrap();
        }

        let platform = PlatformSide::start(&mut authenticator, 1);
        let assertion = authenticator
            .get_assertion(ga_discovery_request(&platform, &crypto, &[0x82u8; 64]))
            .unwrap();
        assert!(assertion.extensions.is_some());
        assert!(authenticator.hmac_secret_session.is_some());

        assert!(authenticator.process_command(0x07, vec![]).is_ok());
        assert!(authenticator.hmac_secret_session.is_none());
    }

    /// Transação de asserção única: a sessão não sobrevive ao fim do próprio
    /// GetAssertion — só existe enquanto houver cadeia (ADR-0022).
    #[test]
    fn test_hmac_secret_single_assertion_keeps_no_session() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto.clone(), storage).unwrap();

        authenticator
            .make_credential(mc_request_with(Some(Extensions {
                hmac_secret: Some(Value::Bool(true)),
                ..Default::default()
            })))
            .unwrap();
        let credential = authenticator
            .get_storage()
            .list_credentials()
            .into_iter()
            .next()
            .unwrap()
            .clone();

        let platform = PlatformSide::start(&mut authenticator, 2);
        let mut request = platform.ga_request(credential.credential_id.clone(), &crypto, false);
        request.options.up = true;
        request.extensions = Some(platform.extension(&[0x9Bu8; 32]));
        let assertion = authenticator.get_assertion(request).unwrap();
        assert!(assertion.extensions.unwrap().hmac_secret.is_some());
        assert!(authenticator.hmac_secret_session.is_none());
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
            pin_uv_auth_param: None,
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

    // A negociação abaixo seleciona RS256, que só existe com a feature
    // `rs256` (geração de chave RSA indisponível sem ela).
    #[test]
    #[cfg(all(test, feature = "rs256"))]
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
            pin_uv_auth_param: None,
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
            pin_uv_auth_param: None,
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
    #[cfg(all(test, feature = "rs256"))]
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
    #[cfg(all(test, feature = "rs256"))]
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
    #[cfg(all(test, feature = "rs256"))]
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
            pin_uv_auth_param: None,
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
                pin_uv_auth_param: None,
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
            pin_uv_auth_param: None,
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
                pin_uv_auth_param: None,
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
                    pin_uv_auth_param: None,
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
            pin_uv_auth_param: None,
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

    /// GetNextAssertion inclui a entidade `user` (0x04) de cada asserção
    /// encadeada (CTAP 2.1 §6.2) e não emite a chave extra `next` no wire.
    #[test]
    fn test_get_next_assertion_includes_user_and_no_next_key() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        for i in 0..2u8 {
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
                    pin_uv_auth_param: None,
                    pin_protocol: None,
                    enterprise_protections: None,
                })
                .unwrap();
        }

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
            pin_uv_auth_param: None,
            pin_protocol: None,
            uv: None,
        };

        let encoded = encode_cbor(&get_assertion_req).unwrap();
        let first_raw = authenticator.process_command(0x02, encoded).unwrap();
        let first: GetAssertionResponse = decode_cbor(&first_raw).unwrap();
        let first_user_id = first.user.map(|u| u.id).unwrap_or_default();
        assert!(!first_user_id.is_empty());

        let next_raw = authenticator.process_command(0x08, vec![]).unwrap();
        let next_response: GetAssertionResponse = decode_cbor(&next_raw).unwrap();
        let next_user_id = next_response.user.map(|u| u.id).unwrap_or_default();
        assert!(!next_user_id.is_empty());
        assert_ne!(next_user_id, first_user_id);
        assert_eq!(next_response.number_of_credentials, Some(2));

        // Wire: chave inteira 0x04 presente, nenhuma chave de texto `next`.
        let wire: Value = decode_cbor(&next_raw).unwrap();
        let Value::Map(entries) = &wire else {
            panic!("resposta GetNextAssertion não é um mapa CBOR");
        };
        assert!(
            entries
                .iter()
                .any(|(k, _)| matches!(k, Value::Integer(n) if *n == 4.into())),
            "wire sem a entidade user (0x04): {:?}",
            wire
        );
        assert!(
            entries
                .iter()
                .all(|(k, _)| !matches!(k, Value::Text(t) if t == "next")),
            "wire com chave extra `next`: {:?}",
            wire
        );
    }

    /// Localiza um campo em um mapa CBOR decodificado. No wire format, as
    /// chaves do mapa de topo viram inteiros CTAP (`root_ctap_keys`) e os
    /// mapas aninhados preservam os nomes de texto dos campos serde.
    fn cbor_field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
        let entries = match value {
            Value::Map(entries) => entries,
            _ => return None,
        };
        entries.iter().find_map(|(k, v)| match k {
            Value::Text(t) if t == key => Some(v),
            Value::Integer(n) if i64::try_from(*n).map(|i| i.to_string()).as_deref() == Ok(key) => {
                Some(v)
            }
            _ => None,
        })
    }

    fn cbor_bytes_field(value: &Value, key: &str) -> Vec<u8> {
        match cbor_field(value, key) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            other => panic!("campo '{}' ausente ou não é bytes: {:?}", key, other),
        }
    }

    /// Contador de assinaturas codificado no authData (bytes 33..37, big-endian).
    fn auth_data_sign_count(auth_data: &[u8]) -> u32 {
        u32::from_be_bytes(auth_data[33..37].try_into().unwrap())
    }

    /// GetNextAssertion deve assinar `authData || clientDataHash` com o mesmo
    /// clientDataHash da asserção inicial (CTAP2 §6.2), incrementar o contador
    /// a cada resposta persistindo-o e espelhar as flags UP/UV. Exaurida a
    /// lista, GetNextAssertion retorna NO_CREDENTIALS.
    #[test]
    fn test_get_next_assertion_signature_counters_and_flags() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        for i in 0..2u8 {
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
                        algorithms: -7, // ES256 — assinaturas verificáveis via verify_p256
                    }],
                    exclude_list: vec![],
                    extensions: None,
                    options: MakeCredentialOptions {
                        rk: true,
                        uv: true,
                        up: true,
                        extended: false,
                    },
                    pin_uv_auth_param: None,
                    pin_protocol: None,
                    enterprise_protections: None,
                })
                .unwrap();
        }

        let client_data_hash = b"client data hash".to_vec();
        let get_assertion_req = GetAssertionRequest {
            rp_id: "example.com".to_string(),
            credentials: vec![],
            allow_list: None,
            client_data_hash: client_data_hash.clone(),
            extensions: None,
            options: GetAssertionOptions { up: true, uv: true },
            pin_uv_auth_param: None,
            pin_protocol: None,
            uv: None,
        };

        let encoded = encode_cbor(&get_assertion_req).unwrap();
        let first_raw = authenticator.process_command(0x02, encoded).unwrap();
        let second_raw = authenticator.process_command(0x08, vec![]).unwrap();

        // Exauridas as credenciais, GetNextAssertion falha.
        assert!(matches!(
            authenticator.process_command(0x08, vec![]),
            Err(Ctap2Error::NoCredentials)
        ));

        // Cada resposta: assinatura válida sobre authData || clientDataHash,
        // contador estritamente crescente e flags espelhadas da inicial.
        let mut previous_count: Option<u32> = None;
        for raw in [&first_raw, &second_raw] {
            let value: Value = decode_cbor(raw).unwrap();
            let auth_data = cbor_bytes_field(&value, "2");
            let signature = cbor_bytes_field(&value, "3");
            let credential_id = cbor_bytes_field(cbor_field(&value, "1").unwrap(), "id");

            // Flags espelhadas da asserção inicial: up=1; o bit UV não é
            // alegado sem autenticação real (uv=true foi apenas pedido).
            assert_eq!(auth_data[32], 0x01);

            let credential = authenticator
                .get_storage()
                .get_credential(&credential_id, authenticator.get_crypto())
                .unwrap()
                .expect("credencial deve existir");

            let mut data_to_sign = Vec::new();
            data_to_sign.extend_from_slice(&auth_data[..37]);
            data_to_sign.extend_from_slice(&client_data_hash);
            authenticator
                .get_crypto()
                .verify_p256(&credential.public_key, &data_to_sign, &signature)
                .expect("assinatura deve validar sobre authData || clientDataHash");

            let sign_count = auth_data_sign_count(&auth_data);
            if let Some(previous) = previous_count {
                assert!(sign_count > previous, "contador não é crescente");
            }
            previous_count = Some(sign_count);
        }

        // O último contador foi persistido no storage.
        let last_value: Value = decode_cbor(&second_raw).unwrap();
        let last_id = cbor_bytes_field(cbor_field(&last_value, "1").unwrap(), "id");
        let persisted = authenticator
            .get_storage()
            .get_credential(&last_id, authenticator.get_crypto())
            .unwrap()
            .unwrap();
        assert_eq!(persisted.sign_count, previous_count.unwrap());
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
                    pin_uv_auth_param: None,
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
                    pin_uv_auth_param: None,
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
    #[cfg(all(test, feature = "rs256"))]
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
            pin_uv_auth_param: None,
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
            pin_uv_auth_param: None,
            pin_protocol: None,
            uv: None,
        };

        let assert_resp = authenticator.get_assertion(get_req).unwrap();
        assert!(!assert_resp.signature.is_empty());
    }

    #[test]
    #[cfg(all(test, feature = "rs256"))]
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
            pin_uv_auth_param: None,
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
            pin_uv_auth_param: None,
            pin_protocol: None,
            uv: None,
        };

        let assert_resp = authenticator.get_assertion(get_req).unwrap();
        assert!(!assert_resp.signature.is_empty());
    }

    fn pin_uv_auth_param(token: &[u8], protocol: u8, message: &[u8]) -> Vec<u8> {
        crypto::pin_protocol::PinUvProtocol::new(protocol)
            .unwrap()
            .authenticate(token, message)
            .unwrap()
    }

    /// Codifica um request de Credential Management autenticado por um
    /// pinUvAuthToken (MAC sobre `subCommand || subCommandParams`).
    fn signed_cred_mgmt_request(
        mut request: cred_mgmt::CredentialManagementRequest,
        token: &[u8],
        protocol: u8,
    ) -> Vec<u8> {
        request.pin_uv_auth_protocol = Some(protocol);
        let unsigned_bytes = encode_cbor(&request).unwrap();
        let auth_message = credential_management_auth_message(&unsigned_bytes).unwrap();
        request.pin_uv_auth_param = Some(pin_uv_auth_param(token, protocol, &auth_message));
        encode_cbor(&request).unwrap()
    }

    #[test]
    fn test_pin_uv_auth_param_is_verified_by_make_and_get_assertion() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        let token = vec![0xA5; 32];
        let client_data_hash = vec![0x42; 32];

        authenticator.set_pin_uv_auth_token(token.clone(), client_pin::PERMISSION_MC_GA, None, 2);

        let mut make_request = make_credential_request(false);
        make_request.client_data_hash = client_data_hash.clone();
        make_request.options.uv = false;
        make_request.pin_protocol = Some(2);
        make_request.pin_uv_auth_param = Some(pin_uv_auth_param(&token, 2, &client_data_hash));

        let response = authenticator.make_credential(make_request).unwrap();
        assert_ne!(response.auth_data[32] & 0x04, 0);

        let credential_id = authenticator.get_storage().list_credentials()[0]
            .credential_id
            .clone();
        let assertion_hash = vec![0x24; 32];
        let assertion = authenticator
            .get_assertion(GetAssertionRequest {
                rp_id: "example.com".to_string(),
                credentials: vec![CredentialDescriptor {
                    r#type: "public-key".to_string(),
                    id: credential_id,
                    transports: None,
                }],
                allow_list: None,
                client_data_hash: assertion_hash.clone(),
                extensions: None,
                options: GetAssertionOptions {
                    up: false,
                    uv: false,
                },
                pin_uv_auth_param: Some(pin_uv_auth_param(&token, 2, &assertion_hash)),
                pin_protocol: Some(2),
                uv: None,
            })
            .unwrap();
        assert_ne!(assertion.auth_data[32] & 0x04, 0);
    }

    #[test]
    fn test_pin_uv_auth_param_rejects_invalid_or_incomplete_authentication() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        let token = vec![0x5A; 32];
        authenticator.set_pin_uv_auth_token(token, client_pin::PERMISSION_MC, None, 2);

        let mut invalid = make_credential_request(false);
        invalid.options.uv = false;
        invalid.pin_protocol = Some(2);
        invalid.pin_uv_auth_param = Some(vec![0u8; 32]);
        let error = authenticator.make_credential(invalid).unwrap_err();
        assert_eq!(
            error.downcast_ref::<Ctap2Error>(),
            Some(&Ctap2Error::PinAuthInvalid)
        );

        let mut incomplete = make_credential_request(false);
        incomplete.options.uv = false;
        incomplete.pin_protocol = Some(2);
        let error = authenticator.make_credential(incomplete).unwrap_err();
        assert_eq!(
            error.downcast_ref::<Ctap2Error>(),
            Some(&Ctap2Error::MissingParameter)
        );
        assert!(authenticator.get_storage().list_credentials().is_empty());
    }

    #[test]
    fn test_pin_uv_auth_is_required_when_pin_is_configured() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        client_pin::ClientPin::set_pin(&mut authenticator, b"1234").unwrap();

        let mut make_request = make_credential_request(false);
        make_request.options.uv = true;
        let error = authenticator.make_credential(make_request).unwrap_err();
        assert_eq!(
            error.downcast_ref::<Ctap2Error>(),
            Some(&Ctap2Error::PinRequired)
        );

        let request = cred_mgmt::CredentialManagementRequest {
            sub_command: cred_mgmt::sub_commands::GET_CREDS_METADATA,
            sub_command_params: None,
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
        };
        let error = authenticator
            .process_command(0x0A, encode_cbor(&request).unwrap())
            .unwrap_err();
        assert_eq!(error, Ctap2Error::PinRequired);
    }

    #[test]
    fn test_pin_uv_auth_permissions_and_rp_binding_are_enforced() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        let token = vec![0x3C; 32];
        let client_data_hash = vec![0x11; 32];

        authenticator.set_pin_uv_auth_token(token.clone(), client_pin::PERMISSION_GA, None, 2);
        let mut make_request = make_credential_request(false);
        make_request.options.uv = false;
        make_request.pin_protocol = Some(2);
        make_request.pin_uv_auth_param =
            Some(pin_uv_auth_param(&token, 2, &make_request.client_data_hash));
        let error = authenticator.make_credential(make_request).unwrap_err();
        assert_eq!(
            error.downcast_ref::<Ctap2Error>(),
            Some(&Ctap2Error::UnauthorizedPermission)
        );

        authenticator.set_pin_uv_auth_token(
            token.clone(),
            client_pin::PERMISSION_MC,
            Some("other.example".to_string()),
            2,
        );
        let mut bound_request = make_credential_request(false);
        bound_request.options.uv = false;
        bound_request.client_data_hash = client_data_hash.clone();
        bound_request.pin_protocol = Some(2);
        bound_request.pin_uv_auth_param = Some(pin_uv_auth_param(&token, 2, &client_data_hash));
        let error = authenticator.make_credential(bound_request).unwrap_err();
        assert_eq!(
            error.downcast_ref::<Ctap2Error>(),
            Some(&Ctap2Error::UnauthorizedPermission)
        );
    }

    #[test]
    fn test_pin_uv_auth_param_is_verified_by_credential_management() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();
        let token = vec![0xC3; 32];
        authenticator.set_pin_uv_auth_token(token.clone(), client_pin::PERMISSION_CM, None, 2);

        let unsigned = cred_mgmt::CredentialManagementRequest {
            sub_command: cred_mgmt::sub_commands::GET_CREDS_METADATA,
            sub_command_params: None,
            pin_uv_auth_protocol: Some(2),
            pin_uv_auth_param: None,
        };
        let unsigned_bytes = encode_cbor(&unsigned).unwrap();
        let auth_message = credential_management_auth_message(&unsigned_bytes).unwrap();
        let request = cred_mgmt::CredentialManagementRequest {
            pin_uv_auth_param: Some(pin_uv_auth_param(&token, 2, &auth_message)),
            ..unsigned
        };

        let response = authenticator
            .process_command(0x0A, encode_cbor(&request).unwrap())
            .unwrap();
        let metadata: cred_mgmt::CredsMetadataResponse = decode_cbor(&response).unwrap();
        assert_eq!(metadata.existing_resident_credentials_count, 0);

        let invalid = cred_mgmt::CredentialManagementRequest {
            pin_uv_auth_param: Some(vec![0u8; 32]),
            ..request
        };
        assert_eq!(
            authenticator
                .process_command(0x0A, encode_cbor(&invalid).unwrap())
                .unwrap_err(),
            Ctap2Error::PinAuthInvalid
        );
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
    fn test_large_blobs_write_rejects_offset_beyond_max() {
        // CTAP 2.1 §6.10: offset além da capacidade máxima é rejeitado antes
        // de qualquer alocação — um único comando não pode inflar o buffer.
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        // Estado prévio conhecido: 16 bytes escritos em offset 0.
        let seed = large_blobs::LargeBlobsRequest {
            offset: 0,
            get: None,
            set: Some(vec![0x41u8; 16]),
            length: Some(16),
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        authenticator
            .process_command(0x0C, encode_cbor(&seed).unwrap())
            .unwrap();

        let write_req = large_blobs::LargeBlobsRequest {
            offset: 4097, // além do maxLargeBlobDataSize (4096)
            get: None,
            set: Some(vec![0x42u8; 16]),
            length: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let error = authenticator
            .process_command(0x0C, encode_cbor(&write_req).unwrap())
            .unwrap_err();
        assert_eq!(error, Ctap2Error::InvalidParameter);
        assert_eq!(authenticator.get_storage().get_large_blobs_len(), 16);
        assert_eq!(
            authenticator.get_storage().read_large_blobs(0, 16),
            vec![0x41u8; 16]
        );
    }

    #[test]
    fn test_large_blobs_write_boundary_at_max_succeeds() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        // Escrita terminando exatamente no limite (4096) é permitida via fragmentos contíguos
        let prefix_len = (4096 - 64) as u64;
        // Primeiro fragmento preenche até o offset de forma contígua
        let prefix_req = large_blobs::LargeBlobsRequest {
            offset: 0,
            get: None,
            set: Some(vec![0x42u8; prefix_len as usize]),
            length: Some(4096),
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        authenticator
            .process_command(0x0C, encode_cbor(&prefix_req).unwrap())
            .unwrap();
        let write_req = large_blobs::LargeBlobsRequest {
            offset: prefix_len,
            get: None,
            set: Some(vec![0x42u8; 64]),
            length: Some(4096),
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        authenticator
            .process_command(0x0C, encode_cbor(&write_req).unwrap())
            .unwrap();
        assert_eq!(authenticator.get_storage().get_large_blobs_len(), 4096,);

        // Um byte a mais já estoura a capacidade.
        let overflow_req = large_blobs::LargeBlobsRequest {
            offset: (4096 - 63) as u64,
            get: None,
            set: Some(vec![0x43u8; 64]),
            length: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let error = authenticator
            .process_command(0x0C, encode_cbor(&overflow_req).unwrap())
            .unwrap_err();
        assert_eq!(error, Ctap2Error::InvalidParameter);
        assert_eq!(authenticator.get_storage().get_large_blobs_len(), 4096,);

        // Offset u64 enorme não pode causar overflow/truncamento.
        let huge_offset_req = large_blobs::LargeBlobsRequest {
            offset: u64::MAX,
            get: None,
            set: Some(vec![0x44u8; 8]),
            length: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let error = authenticator
            .process_command(0x0C, encode_cbor(&huge_offset_req).unwrap())
            .unwrap_err();
        assert_eq!(error, Ctap2Error::InvalidParameter);
    }

    #[test]
    fn test_credential_management_requires_authenticated_token_without_pin() {
        // CTAP 2.1 §6.12: mesmo sem PIN configurado, os subcomandos de
        // Credential Management exigem pinUvAuthToken com permissão `cm` —
        // as respostas expõem user handles/nomes e permitem exclusão.
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        // Uma credencial residente existe no dispositivo.
        let mut rk_request = make_credential_request(false);
        rk_request.options.rk = true;
        assert!(authenticator.make_credential(rk_request).is_ok());
        assert_eq!(authenticator.get_storage().get_credentials_count(), 1);

        let request = cred_mgmt::CredentialManagementRequest {
            sub_command: cred_mgmt::sub_commands::GET_CREDS_METADATA,
            sub_command_params: None,
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
        };
        let error = authenticator
            .process_command(0x0A, encode_cbor(&request).unwrap())
            .unwrap_err();
        assert_eq!(error, Ctap2Error::PinNotSet);
        assert_eq!(error.as_u8(), 0x35);
        // Nada vazou nem foi apagado.
        assert_eq!(authenticator.get_storage().get_credentials_count(), 1);
    }

    #[test]
    fn test_credential_management_full_flow() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        // Fluxo correto segundo a especificação: PIN configurado e token com
        // permissão `cm` autenticando cada subcomando.
        client_pin::ClientPin::set_pin(&mut authenticator, b"1234").unwrap();
        let cm_token = vec![0xC9; 32];
        authenticator.set_pin_uv_auth_token(cm_token.clone(), client_pin::PERMISSION_CM, None, 2);

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
            pin_uv_auth_param: None,
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
        let meta_res = authenticator
            .process_command(0x0A, signed_cred_mgmt_request(meta_req, &cm_token, 2))
            .unwrap();
        let meta_resp: cred_mgmt::CredsMetadataResponse = decode_cbor(&meta_res).unwrap();
        assert_eq!(meta_resp.existing_resident_credentials_count, 1);

        // 2. Enumerate RPs
        let enum_rp_req = cred_mgmt::CredentialManagementRequest {
            sub_command: cred_mgmt::sub_commands::ENUMERATE_RPS_BEGIN,
            sub_command_params: None,
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
        };
        let enum_rp_res = authenticator
            .process_command(0x0A, signed_cred_mgmt_request(enum_rp_req, &cm_token, 2))
            .unwrap();
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
        let enum_cred_res = authenticator
            .process_command(0x0A, signed_cred_mgmt_request(enum_cred_req, &cm_token, 2))
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
        let update_res = authenticator
            .process_command(0x0A, signed_cred_mgmt_request(update_req, &cm_token, 2))
            .unwrap();
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
        let del_res = authenticator
            .process_command(0x0A, signed_cred_mgmt_request(del_req, &cm_token, 2))
            .unwrap();
        assert!(del_res.is_empty());
        assert_eq!(authenticator.get_storage().get_credentials_count(), 0);
    }

    // -------------------------------------------------------------------------
    // Configuração SEM a feature `rs256`: algoritmos RSA devem ser tratados
    // como não suportados na negociação e ausentes do GetInfo (CTAP 2.1 §6.4.1
    // — o autenticador anuncia apenas o que consegue gerar).
    //
    // Rodar com: cargo test -p ctap2 --no-default-features
    // -------------------------------------------------------------------------

    /// Request mínimo de MakeCredential com a lista de algoritmos dada.
    #[cfg(all(test, not(feature = "rs256")))]
    fn mc_request_for_algs(algs: &[i32]) -> MakeCredentialRequest {
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
            pub_key_cred_params: algs
                .iter()
                .map(|alg| PublicKeyCredParams {
                    r#type: "public-key".to_string(),
                    algorithms: *alg,
                })
                .collect(),
            exclude_list: vec![],
            extensions: None,
            options: MakeCredentialOptions {
                rk: false,
                uv: false,
                up: true,
                extended: false,
            },
            pin_uv_auth_param: None,
            pin_protocol: None,
            enterprise_protections: None,
        }
    }

    #[test]
    #[cfg(all(test, not(feature = "rs256")))]
    fn test_get_info_without_rs256_omits_rsa_algorithms() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let info = authenticator.get_info().unwrap();
        let algs: Vec<i32> = info.algorithms.iter().map(|e| e.alg).collect();
        assert_eq!(
            algs,
            vec![-7, -8, -35],
            "sem rs256 apenas ES256, EdDSA e ES384 podem ser anunciados"
        );
    }

    #[test]
    #[cfg(all(test, not(feature = "rs256")))]
    fn test_rs256_negotiation_unsupported_without_feature() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let result = authenticator.make_credential(mc_request_for_algs(&[-257]));
        assert_eq!(
            *result
                .err()
                .expect("RS256 deve ser rejeitado sem a feature")
                .downcast_ref::<Ctap2Error>()
                .unwrap(),
            Ctap2Error::UnsupportedAlgorithm
        );
    }

    #[test]
    #[cfg(all(test, not(feature = "rs256")))]
    fn test_ps256_negotiation_unsupported_without_feature() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        let result = authenticator.make_credential(mc_request_for_algs(&[-37]));
        assert_eq!(
            *result
                .err()
                .expect("PS256 deve ser rejeitado sem a feature")
                .downcast_ref::<Ctap2Error>()
                .unwrap(),
            Ctap2Error::UnsupportedAlgorithm
        );
    }

    #[test]
    #[cfg(all(test, not(feature = "rs256")))]
    fn test_negotiation_skips_rsa_and_falls_back_to_es256_without_feature() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto, storage).unwrap();

        // RS256 listado primeiro deve ser pulado; ES256 é selecionado em vez
        // de abortar com UnsupportedAlgorithm.
        let response = authenticator
            .make_credential(mc_request_for_algs(&[-257, -7]))
            .expect("fallback para ES256 deve funcionar sem rs256");

        let stored = authenticator.get_storage().list_credentials();
        assert_eq!(stored[0].algorithm, -7);
        let _ = response;
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_created_at_is_nonzero_and_monotonic() {
        let crypto = CryptoEngine::new().unwrap();
        let storage = StorageEngine::new().unwrap();
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto.clone(), storage).unwrap();

        let resp1 = authenticator
            .make_credential(make_credential_request(false))
            .unwrap();
        let id1 = credential_id_from_auth_data(&resp1.auth_data);
        let cred1 = authenticator
            .get_storage()
            .get_credential(&id1, &crypto)
            .unwrap()
            .unwrap();
        assert!(
            cred1.created_at > 0,
            "created_at deve ser timestamp real quando std ativo"
        );

        // Sem sleep: monotonicidade híbrida garante timestamp estritamente crescente
        // mesmo dentro do mesmo millis (AtomicU64 max(last+1, millis))
        let mut req2 = make_credential_request(false);
        req2.user.id = b"user2".to_vec();
        let resp2 = authenticator.make_credential(req2).unwrap();
        let id2 = credential_id_from_auth_data(&resp2.auth_data);
        let cred2 = authenticator
            .get_storage()
            .get_credential(&id2, &crypto)
            .unwrap()
            .unwrap();
        assert!(
            cred2.created_at > cred1.created_at,
            "segundo credential deve ter timestamp > primeiro (monotonic hybrid)"
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_created_at_lru_pruning_uses_timestamp_order() {
        let crypto = CryptoEngine::new().unwrap();
        let mut storage = StorageEngine::new().unwrap();
        storage.set_max_credential_count(2);
        let mut authenticator = Ctap2Authenticator::new(AAGUID, crypto.clone(), storage).unwrap();

        // Cria 3 credenciais back-to-back sem sleep; monotonic hybrid garante ordem LRU
        let resp1 = authenticator
            .make_credential(make_credential_request(false))
            .unwrap();
        let id1 = credential_id_from_auth_data(&resp1.auth_data);

        let mut req2 = make_credential_request(false);
        req2.user.id = b"user2".to_vec();
        let resp2 = authenticator.make_credential(req2).unwrap();
        let id2 = credential_id_from_auth_data(&resp2.auth_data);

        let mut req3 = make_credential_request(false);
        req3.user.id = b"user3".to_vec();
        let resp3 = authenticator.make_credential(req3).unwrap();
        let id3 = credential_id_from_auth_data(&resp3.auth_data);

        let stored = authenticator.get_storage().list_credentials();
        assert_eq!(stored.len(), 2, "max 2 deve manter apenas 2 credenciais");
        let ids: Vec<Vec<u8>> = stored.iter().map(|c| c.credential_id.clone()).collect();
        assert!(
            !ids.contains(&id1),
            "credencial mais antiga (id1) deve ter sido podada por LRU"
        );
        assert!(ids.contains(&id2), "id2 deve permanecer");
        assert!(ids.contains(&id3), "id3 deve permanecer");
    }
}
