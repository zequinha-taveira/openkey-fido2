use alloc::collections::BTreeMap;
use alloc::string::ToString;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtapCommand {
    pub cmd: u8,
    #[serde(with = "serde_bytes")]
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CtapResponse {
    MakeCredential(MakeCredentialResponse),
    GetAssertion(GetAssertionResponse),
    GetInfo(GetInfoResponse),
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
}

impl Extensions {
    pub fn has_any(&self) -> bool {
        self.cred_protect.is_some()
            || self.cred_blob.is_some()
            || self.min_pin_length
            || self.hmac_secret.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HmacSecretInput {
    #[serde(with = "serde_bytes", rename = "saltEnc")]
    pub salt_enc: Vec<u8>,
    #[serde(rename = "pinUvAuthProtocol")]
    pub pin_uv_auth_protocol: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MakeCredentialOptions {
    #[serde(default)]
    pub rk: bool,
    #[serde(default)]
    pub uv: bool,
    #[serde(default)]
    pub up: bool,
    #[serde(rename = "att", default)]
    pub extended: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MakeCredentialResponse {
    pub fmt: String,
    #[serde(with = "serde_bytes", rename = "authData")]
    pub auth_data: Vec<u8>,
    /// CBOR map (attStmt). Kept as a map so the encoded response matches
    /// CTAP2's `{fmt, attStmt, authData}` structure.
    #[serde(rename = "attStmt")]
    pub attestation_info: BTreeMap<i64, Value>,
    #[serde(rename = "extensions", skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ExtensionOutputs>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExtensionOutputs {
    #[serde(rename = "credProtect", skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<u8>,
    #[serde(rename = "minPinLength", skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<u32>,
    #[serde(
        with = "serde_bytes",
        rename = "credBlob",
        skip_serializing_if = "Option::is_none"
    )]
    pub cred_blob: Option<Vec<u8>>,
    #[serde(
        with = "serde_bytes",
        rename = "hmac-secret",
        skip_serializing_if = "Option::is_none"
    )]
    pub hmac_secret: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialData {
    #[serde(with = "serde_bytes")]
    pub aaguid: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub credential_id: Vec<u8>,
    pub credential_type: String,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    pub sign_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAssertionRequest {
    #[serde(rename = "rpId")]
    pub rp_id: String,
    pub credentials: Vec<CredentialDescriptor>,
    #[serde(rename = "allowList")]
    pub allow_list: Option<Vec<CredentialDescriptor>>,
    #[serde(with = "serde_bytes", rename = "clientDataHash")]
    pub client_data_hash: Vec<u8>,
    pub extensions: Option<Extensions>,
    pub options: GetAssertionOptions,
    #[serde(rename = "pinUvAuthProtocol")]
    pub pin_protocol: Option<u8>,
    pub uv: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAssertionOptions {
    pub up: bool,
    pub uv: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAssertionResponse {
    #[serde(rename = "credential")]
    pub credential: Option<CredentialDescriptor>,
    #[serde(with = "serde_bytes", rename = "authData")]
    pub auth_data: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    pub user: Option<User>,
    #[serde(rename = "numberOfCredentials")]
    pub number_of_credentials: Option<u16>,
    pub next: Option<bool>,
    #[serde(rename = "extensions", skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ExtensionOutputs>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetInfoResponse {
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    #[serde(with = "serde_bytes")]
    pub aaguid: Vec<u8>,
    pub options: Vec<String>,
    pub rp_count: u32,
    pub max_cred_blob_length: u32,
    pub max_credential_id_length: u16,
    pub max_credential_count: u16,
    pub firmware_version: String,
    pub algorithms: Vec<CoseAlgorithmEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<SecurityFeatures>,
}

/// COSE algorithm entry for GetInfo response (CTAP2 §6.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoseAlgorithmEntry {
    pub alg: i32,
    #[serde(rename = "type")]
    pub key_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetVersionResponse {
    pub firmware_version: String,
    pub firmware_commit_id: String,
    pub firmware_build_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BioEnrollRequest {
    #[serde(rename = "subCommand")]
    pub sub_command: u8,
    #[serde(rename = "subCommandParams")]
    pub sub_command_params: Option<BTreeMap<String, Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BioEnrollResponse {
    #[serde(rename = "fingerprintKind")]
    pub fingerprint_kind: u8,
    #[serde(rename = "maxEnrollments")]
    pub max_enrollments: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumerateRPsResponse {
    pub rp: RelyingParty,
    #[serde(with = "serde_bytes", rename = "rpHash")]
    pub rp_hash: Vec<u8>,
    #[serde(rename = "totalRPs")]
    pub total_rps: u8,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ctap2Command {
    MakeCredential = 0x01,
    GetAssertion = 0x02,
    GetInfo = 0x04,
    ClientPIN = 0x06,
    Reset = 0x07,
    GetNextAssertion = 0x08,
    BioEnroll = 0x09,
    EnumerateRPsInitial = 0x3B,
    EnumerateRPsNext = 0x3C,
    Selection = 0x0B,
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
            0x3B => Ctap2Command::EnumerateRPsInitial,
            0x3C => Ctap2Command::EnumerateRPsNext,
            0x0B => Ctap2Command::Selection,
            _ => Ctap2Command::Unknown(value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ctap2Error {
    Success = 0x00,
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    InvalidData = 0x04,
    InvalidState = 0x05,
    InvalidOption = 0x06,
    Timeout = 0x08,
    ResourceBusy = 0x09,
    CredentialExists = 0x0A,
    Processing = 0x0B,
    UnsupportedAlgorithm = 0x0C,
    UnsupportedOption = 0x0D,
    InvalidKey = 0x11,
    NoCredentials = 0x0E,
    PinInvalid = 0x31,
    PinInvalidRetries = 0x32,
    PinRequired = 0x33,
    PinPolicyViolation = 0x34,
    PinTokenRequired = 0x35,
    PinTokenExpired = 0x36,
    PinTokenPending = 0x37,
    PinTokenFailure = 0x38,
    RequestTooLarge = 0x40,
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

pub fn encode_cbor<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Ctap2Error> {
    let mut buf = alloc::vec![];
    into_writer(value, &mut buf).map_err(|_| Ctap2Error::InvalidData)?;
    Ok(buf)
}

pub fn decode_cbor<T: DeserializeOwned>(data: &[u8]) -> Result<T, Ctap2Error> {
    from_reader(data).map_err(|_| Ctap2Error::InvalidData)
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
            ],
            options: vec!["rk".to_string(), "up".to_string()],
            rp_count: 0,
            max_cred_blob_length: 32,
            max_credential_id_length: 64,
            max_credential_count: 10,
            firmware_version: "0.1.0".to_string(),
            min_pin_length: Some(4),
            security: SecurityFeatures::default(),
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

#[derive(Debug)]
pub struct Ctap2Authenticator {
    crypto: CryptoEngine,
    storage: StorageEngine,
    capabilities: Ctap2Capabilities,
    attestation_format: AttestationFormat,
    attestation_cert: Option<crate::attestation::AttestationCertificate>,
    enumerate_rps_state: Option<EnumerateRPsState>,
    get_next_assertion_state: Option<GetNextAssertionState>,
}

#[derive(Debug)]
struct EnumerateRPsState {
    rps: Vec<(String, Vec<u8>)>,
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
            enumerate_rps_state: None,
            get_next_assertion_state: None,
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
            -257 => {
                // RSA: keep the PKCS#1 DER public key so both the COSE key and
                // signature verification can be derived from it.
                let (pkcs8, n, e) = self.crypto.generate_rsa_key_pair()?;
                let public_key = CryptoEngine::rsa_public_key_der(&n, &e)?;
                (pkcs8, public_key)
            }
            _ => self.crypto.generate_key_pair()?,
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
                    alg: -257,
                    key_type: "public-key".to_string(),
                },
            ],
            security,
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
            Ctap2Command::ClientPIN => self.handle_client_pin(&data),
            Ctap2Command::Reset => self.handle_reset(),
            Ctap2Command::GetNextAssertion => self.handle_get_next_assertion(),
            Ctap2Command::BioEnroll => self.handle_bio_enroll(&data),
            Ctap2Command::EnumerateRPsInitial => self.handle_enumerate_rps_initial(),
            Ctap2Command::EnumerateRPsNext => self.handle_enumerate_rps_next(),
            Ctap2Command::Unknown(_) => Err(Ctap2Error::InvalidCommand),
        }
    }

    fn handle_selection(&self) -> Result<Vec<u8>, Ctap2Error> {
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
        self.enumerate_rps_state = None;
        self.get_next_assertion_state = None;
        info!("Reset: all credentials and state cleared");
        Ok(vec![Ctap2Error::Success.as_u8()])
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
        if old_hash != stored_hash {
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
        if submitted_hash != stored_hash {
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
        assert_eq!(result, vec![0x00]);
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
        assert_eq!(info.algorithms.len(), 3);
        assert_eq!(info.algorithms[0].alg, -7);
        assert_eq!(info.algorithms[0].key_type, "public-key");
        assert_eq!(info.algorithms[1].alg, -8);
        assert_eq!(info.algorithms[1].key_type, "public-key");
        assert_eq!(info.algorithms[2].alg, -257);
        assert_eq!(info.algorithms[2].key_type, "public-key");
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
        assert_eq!(result.unwrap(), vec![0x00]);
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

        let response: EnumerateRPsResponse =
            ciborium::de::from_reader(result.unwrap().as_slice()).unwrap();
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
        let response: EnumerateRPsResponse =
            ciborium::de::from_reader(result.unwrap().as_slice()).unwrap();
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

        let response: BioEnrollResponse =
            ciborium::de::from_reader(result.unwrap().as_slice()).unwrap();
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
}
