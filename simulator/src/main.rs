use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process;

use authenticator::{
    register_multiprotocol_applets, EmbeddedAuthenticator, InsecureHostStorage, ManagementApplet,
    OathApplet, OpenPgpApplet, PivApplet,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ciborium::Value as CborValue;
use crypto::CryptoEngine;
use ctap2::{
    AttestationCertificate, AttestationFormat, CredentialDescriptor, Ctap2Error, Extensions,
    GetAssertionOptions, GetAssertionRequest, MakeCredentialOptions, MakeCredentialRequest,
    PublicKeyCredParams, RelyingParty, User,
};
use device_profile::{DeviceProfile, DeviceProfileBuilder, PinPolicy};
use serde_json::{json, Value};
use std::cell::RefCell;
use storage::{FileStorageBackend, StorageEngine};
use transport::iso7816::CardRouter;

const ERR_JSON_INVALID: u8 = 0x02;

/// Placeholder DER blob used as the packed attestation certificate in tests.
const TEST_ATTESTATION_CERT: &[u8] = &[0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];

/// Perfil do simulador: habilita o clientPin para que o GetInfo anuncie
/// `clientPin`/`pinUvAuthToken` e o fluxo PIN possa ser exercitado.
fn simulator_profile() -> DeviceProfile {
    DeviceProfileBuilder::new()
        .pin_policy(PinPolicy::Optional)
        .build()
}

struct Simulator {
    auth: EmbeddedAuthenticator,
    storage_path: Option<PathBuf>,
    /// Roteador ISO 7816 multi-protocolo (Management + OATH + PIV + OpenPGP).
    ///
    /// Os applets referenciados pelo roteador vivem em `Box::leak` (`'static`);
    /// o `reset` reconstrói o roteador com vazamento novo — aceitável no
    /// simulador, cujo tempo de vida é o do processo. Com `--storage-path`,
    /// os applets usam o mesmo arquivo do storage CTAP2 (mesma identidade
    /// entre reinícios); sem ele, o storage dos applets é em memória.
    card_router: CardRouter<'static>,
    /// Engine persistente dos applets (`Some` com `--storage-path`).
    ///
    /// Aponta para o `RefCell` vazado que sustenta os applets; o `reset`
    /// reconstrói o roteador sobre o MESMO engine (sessões VERIFY/PW1 caem,
    /// estados `sys:*` permanecem). `None` = memória (comportamento legado).
    applet_storage: Option<&'static RefCell<StorageEngine>>,
    /// Chave-mestra dos applets persistentes, derivada do caminho.
    applet_key: Option<[u8; 32]>,
}

/// Deriva a chave-mestra dos applets a partir do caminho do storage.
///
/// Espelha `derive_key_from_path` do CTAP2 com separação de domínio
/// (`":applets"`): mesma identidade entre reinícios, sem reutilizar a chave
/// do CTAP2. **Inseguro por construção** como o `InsecureHostStorage` —
/// restrito ao simulador e a testes; nunca logar o material derivado.
fn derive_applet_key_from_path(path: &Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    // `sha256` independe da chave do motor; o motor aleatório é descartado.
    let probe = CryptoEngine::new()?;
    let mut input = path.to_string_lossy().into_owned().into_bytes();
    input.extend_from_slice(b":applets");
    let hash = probe.sha256(&input);
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    Ok(key)
}

/// Monta um roteador multi-protocolo novo sobre storage em memória.
///
/// Cada applet recebe um `CryptoEngine` próprio com chave aleatória; o estado
/// cifrado (`sys:*`) mora no `StorageEngine` vazado junto dos applets.
fn new_card_router() -> Result<CardRouter<'static>, Box<dyn std::error::Error>> {
    let storage: &'static RefCell<StorageEngine> =
        Box::leak(Box::new(RefCell::new(StorageEngine::new()?)));
    let management: &'static mut ManagementApplet<'static> = Box::leak(Box::new(
        ManagementApplet::new(storage, CryptoEngine::new()?)?,
    ));
    let oath: &'static mut OathApplet<'static> =
        Box::leak(Box::new(OathApplet::new(storage, CryptoEngine::new()?)?));
    let piv: &'static mut PivApplet<'static> =
        Box::leak(Box::new(PivApplet::new(storage, CryptoEngine::new()?)?));
    let openpgp: &'static mut OpenPgpApplet<'static> =
        Box::leak(Box::new(OpenPgpApplet::new(storage, CryptoEngine::new()?)?));
    let mut router = CardRouter::new();
    register_multiprotocol_applets(&mut router, management, oath, piv, openpgp);
    Ok(router)
}

/// Monta um roteador multi-protocolo sobre um storage e chave existentes.
///
/// Usado com `--storage-path` (construção e `reset`): os 4 applets partilham
/// a mesma chave derivada do caminho, como o firmware partilha um único
/// `CryptoEngine` entre applets — o estado cifrado (`sys:*`) permanece
/// legível entre reinícios do processo.
fn new_card_router_over(
    storage: &'static RefCell<StorageEngine>,
    key: [u8; 32],
) -> Result<CardRouter<'static>, Box<dyn std::error::Error>> {
    let management: &'static mut ManagementApplet<'static> = Box::leak(Box::new(
        ManagementApplet::new(storage, CryptoEngine::from_key(key))?,
    ));
    let oath: &'static mut OathApplet<'static> = Box::leak(Box::new(OathApplet::new(
        storage,
        CryptoEngine::from_key(key),
    )?));
    let piv: &'static mut PivApplet<'static> = Box::leak(Box::new(PivApplet::new(
        storage,
        CryptoEngine::from_key(key),
    )?));
    let openpgp: &'static mut OpenPgpApplet<'static> = Box::leak(Box::new(OpenPgpApplet::new(
        storage,
        CryptoEngine::from_key(key),
    )?));
    let mut router = CardRouter::new();
    register_multiprotocol_applets(&mut router, management, oath, piv, openpgp);
    Ok(router)
}

/// Decodifica hex (`"00a4..."`) em bytes; rejeita ímpar, vazio ou não-hex.
fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        return Err("campo apdu deve ser hex com nº par de dígitos".to_string());
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i]).ok_or("campo apdu contém dígito não-hex")?;
        let lo = hex_val(bytes[i + 1]).ok_or("campo apdu contém dígito não-hex")?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

fn b64_encode(data: &[u8]) -> String {
    BASE64.encode(data)
}

fn b64_decode(value: &Value) -> Result<Vec<u8>, String> {
    match value {
        Value::String(s) => BASE64
            .decode(s)
            .map_err(|e| format!("base64 invalido: {e}")),
        Value::Null => Ok(Vec::new()),
        _ => Err("campo base64 deve ser string".to_string()),
    }
}

fn bool_field(obj: &Value, name: &str, default: bool) -> bool {
    obj.get(name).and_then(Value::as_bool).unwrap_or(default)
}

fn sign_count_from_auth_data(auth_data: &[u8]) -> u32 {
    u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]])
}

fn error_value(error: Box<dyn std::error::Error>) -> Value {
    if let Some(code) = error.downcast_ref::<Ctap2Error>() {
        json!({"ok": false, "code": code.as_u8(), "message": error.to_string()})
    } else {
        // 0x7F (unspecified failure): 0x05 seria lido como TIMEOUT por hosts.
        json!({"ok": false, "code": Ctap2Error::Unknown.as_u8(), "message": error.to_string()})
    }
}

/// Convert an attStmt CBOR map (`{1: x5c, 2: sig, 3: alg}`) to JSON with
/// readable keys so Python tests can inspect it without a CBOR decoder.
fn att_stmt_to_json(att_stmt: &std::collections::BTreeMap<i64, CborValue>) -> Value {
    let mut obj = serde_json::Map::new();
    if let Some(CborValue::Integer(alg)) = att_stmt.get(&3) {
        let alg: i128 = (*alg).into();
        obj.insert("alg".to_string(), json!(alg as i64));
    }
    if let Some(CborValue::Bytes(sig)) = att_stmt.get(&2) {
        obj.insert("sig".to_string(), json!(b64_encode(sig)));
    }
    if let Some(CborValue::Array(x5c)) = att_stmt.get(&1) {
        let certs: Vec<Value> = x5c
            .iter()
            .filter_map(|item| match item {
                CborValue::Bytes(cert) => Some(json!(b64_encode(cert))),
                _ => None,
            })
            .collect();
        obj.insert("x5c".to_string(), Value::Array(certs));
    }
    Value::Object(obj)
}

fn build_extensions(ext_val: Option<&Value>) -> Result<Option<Extensions>, Value> {
    let ext_val = match ext_val {
        Some(v) if !v.is_null() => v,
        _ => return Ok(None),
    };
    let cred_protect = ext_val
        .get("credProtect")
        .and_then(Value::as_u64)
        .map(|v| u8::try_from(v).unwrap_or(1));
    let cred_blob = match ext_val.get("credBlob") {
        Some(v) => {
            let decoded = b64_decode(v)
                .map_err(|msg| json!({"ok": false, "code": ERR_JSON_INVALID, "message": msg}))?;
            if decoded.is_empty() {
                None
            } else {
                Some(decoded)
            }
        }
        None => None,
    };
    let min_pin_length = ext_val
        .get("minPinLength")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // `hmac-secret` (CTAP 2.1 §12.5): booleano no MakeCredential ou mapa
    // `{1: keyAgreement, 2: saltEnc, 3: saltAuth, 4: pinUvAuthProtocol}` no
    // GetAssertion. O mapa JSON é convertido para as chaves inteiras da spec.
    let hmac_secret = match ext_val.get("hmacSecret") {
        Some(v) => {
            let mapped = if v.is_boolean() {
                CborValue::Bool(v.as_bool().unwrap())
            } else {
                let key_agreement = match v.get("keyAgreement") {
                    Some(key) => {
                        let x = b64_decode(key.get("x").unwrap_or(&Value::Null)).map_err(
                            |msg| json!({"ok": false, "code": ERR_JSON_INVALID, "message": msg}),
                        )?;
                        let y = b64_decode(key.get("y").unwrap_or(&Value::Null)).map_err(
                            |msg| json!({"ok": false, "code": ERR_JSON_INVALID, "message": msg}),
                        )?;
                        Some(CborValue::Map(vec![
                            (CborValue::Integer(1.into()), CborValue::Integer(2.into())),
                            (
                                CborValue::Integer(3.into()),
                                CborValue::Integer((-25).into()),
                            ),
                            (
                                CborValue::Integer((-1).into()),
                                CborValue::Integer(1.into()),
                            ),
                            (CborValue::Integer((-2).into()), CborValue::Bytes(x)),
                            (CborValue::Integer((-3).into()), CborValue::Bytes(y)),
                        ]))
                    }
                    None => None,
                };
                let mut entries = Vec::with_capacity(4);
                if let Some(key) = key_agreement {
                    entries.push((CborValue::Integer(1.into()), key));
                }
                if let Some(salt) = v.get("saltEnc") {
                    let decoded = b64_decode(salt).map_err(
                        |msg| json!({"ok": false, "code": ERR_JSON_INVALID, "message": msg}),
                    )?;
                    entries.push((CborValue::Integer(2.into()), CborValue::Bytes(decoded)));
                }
                if let Some(auth) = v.get("saltAuth") {
                    let decoded = b64_decode(auth).map_err(
                        |msg| json!({"ok": false, "code": ERR_JSON_INVALID, "message": msg}),
                    )?;
                    entries.push((CborValue::Integer(3.into()), CborValue::Bytes(decoded)));
                }
                if let Some(protocol) = v.get("pinUvAuthProtocol").and_then(Value::as_u64) {
                    entries.push((
                        CborValue::Integer(4.into()),
                        CborValue::Integer((protocol as i64).into()),
                    ));
                }
                CborValue::Map(entries)
            };
            Some(mapped)
        }
        None => None,
    };

    Ok(Some(Extensions {
        cred_protect,
        cred_blob,
        min_pin_length,
        hmac_secret,
        large_blob_key: false,
    }))
}

impl Simulator {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            auth: EmbeddedAuthenticator::new_with_profile(simulator_profile())?,
            storage_path: None,
            card_router: new_card_router()?,
            applet_storage: None,
            applet_key: None,
        })
    }

    fn with_storage_path(path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        // Applets partilham o MESMO arquivo do CTAP2: `FileStorageBackend`
        // recarrega do disco a cada acesso, então os dois engines coexistem
        // sem apagar as chaves um do outro (`sys:*` + `cred:*`).
        let applet_key = derive_applet_key_from_path(&path)?;
        let applet_storage: &'static RefCell<StorageEngine> = Box::leak(Box::new(RefCell::new(
            StorageEngine::with_backend(Box::new(FileStorageBackend::new(path.clone())?)),
        )));
        Ok(Self {
            auth: EmbeddedAuthenticator::new_with_insecure_host_storage(
                InsecureHostStorage::new(path.clone()),
                simulator_profile(),
            )?,
            storage_path: Some(path),
            card_router: new_card_router_over(applet_storage, applet_key)?,
            applet_storage: Some(applet_storage),
            applet_key: Some(applet_key),
        })
    }

    fn reset(&mut self) -> Value {
        let result = if let Some(path) = &self.storage_path {
            EmbeddedAuthenticator::new_with_insecure_host_storage(
                InsecureHostStorage::new(path.clone()),
                simulator_profile(),
            )
        } else {
            EmbeddedAuthenticator::new_with_profile(simulator_profile())
        };
        match result {
            Ok(auth) => {
                self.auth = auth;
                // Persistente: roteador novo sobre o MESMO engine — sessões
                // VERIFY/PW1 e estado sys:* voltam à fábrica só na memória
                // volátil dos applets; o arquivo é preservado. Memória: engine
                // novo, estado some (comportamento legado).
                let router = match (self.applet_storage, self.applet_key) {
                    (Some(storage), Some(key)) => new_card_router_over(storage, key),
                    _ => new_card_router(),
                };
                match router {
                    Ok(router) => {
                        self.card_router = router;
                        json!({"ok": true})
                    }
                    Err(error) => error_value(error),
                }
            }
            Err(error) => error_value(error),
        }
    }

    /// Configure the attestation format used by subsequent MakeCredential
    /// calls. For `packed`, a deterministic test certificate is installed so
    /// the resulting attStmt carries an `x5c` entry.
    fn set_attestation_format(&mut self, req: &Value) -> Value {
        let format = req.get("format").and_then(Value::as_str).unwrap_or("none");
        let format = match format {
            "none" => AttestationFormat::None,
            "self" => AttestationFormat::Self_,
            "packed" => AttestationFormat::Packed,
            "u2f" => AttestationFormat::U2F,
            "android-key" => AttestationFormat::AndroidKey,
            "apple" => AttestationFormat::Apple,
            other => {
                return json!({
                    "ok": false,
                    "code": ERR_JSON_INVALID,
                    "message": format!("formato de attestation desconhecido: {other}")
                });
            }
        };

        let ctap = self.auth.get_webauthn_authenticator_mut().get_ctap_mut();
        if format == AttestationFormat::Packed {
            let cert_private_key = match ctap.get_crypto().generate_key_pair() {
                Ok((private_key, _)) => private_key,
                Err(error) => return error_value(error),
            };
            ctap.set_attestation_certificate(AttestationCertificate {
                cert: TEST_ATTESTATION_CERT.to_vec(),
                private_key: cert_private_key,
            });
        }
        ctap.set_attestation_format(format);
        json!({"ok": true, "format": format.as_str()})
    }

    fn make_credential(&mut self, req: &Value) -> Value {
        let rp_id = req
            .get("rp_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let client_data = match b64_decode(req.get("client_data").unwrap_or(&Value::Null)) {
            Ok(v) => v,
            Err(msg) => return json!({"ok": false, "code": ERR_JSON_INVALID, "message": msg}),
        };
        let user_id = match b64_decode(req.get("user_id").unwrap_or(&Value::Null)) {
            Ok(v) => v,
            Err(msg) => return json!({"ok": false, "code": ERR_JSON_INVALID, "message": msg}),
        };

        let pub_key_cred_params: Vec<PublicKeyCredParams> = req
            .get("algorithms")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_i64)
                    .map(|algorithms| PublicKeyCredParams {
                        r#type: "public-key".to_string(),
                        algorithms: algorithms as i32,
                    })
                    .collect()
            })
            .unwrap_or_default();

        let exclude_list: Vec<CredentialDescriptor> = match req
            .get("exclude")
            .and_then(Value::as_array)
        {
            Some(items) => {
                let mut list = Vec::with_capacity(items.len());
                for item in items {
                    match b64_decode(item) {
                        Ok(id) => list.push(CredentialDescriptor {
                            r#type: "public-key".to_string(),
                            id,
                            transports: None,
                        }),
                        Err(msg) => {
                            return json!({"ok": false, "code": ERR_JSON_INVALID, "message": msg})
                        }
                    }
                }
                list
            }
            None => Vec::new(),
        };

        let options = req.get("options").cloned().unwrap_or_else(|| json!({}));
        let mc_options = MakeCredentialOptions {
            rk: bool_field(&options, "rk", false),
            uv: bool_field(&options, "uv", true),
            up: bool_field(&options, "up", true),
            extended: false,
        };

        let extensions = match build_extensions(req.get("extensions")) {
            Ok(v) => v,
            Err(err_val) => return err_val,
        };

        let request = MakeCredentialRequest {
            client_data_hash: client_data,
            rp: RelyingParty {
                id: rp_id,
                name: None,
                icon: None,
            },
            user: User {
                id: user_id,
                name: None,
                display_name: None,
                icon_url: None,
            },
            pub_key_cred_params,
            exclude_list,
            extensions,
            options: mc_options,
            pin_uv_auth_param: None,
            pin_protocol: None,
            enterprise_protections: None,
        };

        match self.auth.make_credential(request) {
            Ok(response) => {
                let auth_data = &response.auth_data;
                let flags = auth_data[32];
                let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
                let credential_id = auth_data[55..55 + cred_id_len].to_vec();
                let stored = self
                    .auth
                    .get_webauthn_authenticator()
                    .get_ctap()
                    .get_storage()
                    .list_credentials();
                let credential = stored
                    .iter()
                    .find(|c| c.credential_id == credential_id)
                    .expect("credential recém-criada deve estar armazenada");
                let mut result = json!({
                    "ok": true,
                    "fmt": response.fmt,
                    "att_stmt": att_stmt_to_json(&response.attestation_info),
                    "auth_data": b64_encode(auth_data),
                    "flags": flags,
                    "sign_count": sign_count_from_auth_data(auth_data),
                    "credential_id": b64_encode(&credential_id),
                    "public_key": b64_encode(&credential.public_key),
                    "rp_id_hash": b64_encode(&credential.rp_id_hash),
                });
                if let Some(ext) = response.extensions {
                    let mut ext_obj = serde_json::Map::new();
                    if let Some(blob) = ext.cred_blob {
                        ext_obj.insert("credBlob".to_string(), json!(b64_encode(&blob)));
                    }
                    if let Some(min_pin) = ext.min_pin_length {
                        ext_obj.insert("minPinLength".to_string(), json!(min_pin));
                    }
                    if let Some(policy) = ext.cred_protect {
                        ext_obj.insert("credProtect".to_string(), json!(policy));
                    }
                    // §12.5: `true` no MakeCredential; bytes cifrados no GetAssertion.
                    match ext.hmac_secret {
                        Some(CborValue::Bool(enabled)) => {
                            ext_obj.insert("hmac-secret".to_string(), json!(enabled));
                        }
                        Some(CborValue::Bytes(secret)) => {
                            ext_obj.insert("hmac-secret".to_string(), json!(b64_encode(&secret)));
                        }
                        _ => {}
                    }
                    if let Some(obj) = result.as_object_mut() {
                        for (k, v) in ext_obj {
                            obj.insert(k, v);
                        }
                    }
                }
                result
            }
            Err(error) => error_value(error),
        }
    }

    fn get_assertion(&mut self, req: &Value) -> Value {
        let rp_id = req
            .get("rp_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let credential_id = match b64_decode(req.get("credential_id").unwrap_or(&Value::Null)) {
            Ok(v) => v,
            Err(msg) => return json!({"ok": false, "code": ERR_JSON_INVALID, "message": msg}),
        };
        let client_data_hash = match b64_decode(req.get("client_data_hash").unwrap_or(&Value::Null))
        {
            Ok(v) => v,
            Err(msg) => return json!({"ok": false, "code": ERR_JSON_INVALID, "message": msg}),
        };

        let allow_list: Vec<CredentialDescriptor> = match req
            .get("allow_list")
            .and_then(Value::as_array)
        {
            Some(items) => {
                let mut list = Vec::with_capacity(items.len());
                for item in items {
                    match b64_decode(item) {
                        Ok(id) => list.push(CredentialDescriptor {
                            r#type: "public-key".to_string(),
                            id,
                            transports: None,
                        }),
                        Err(msg) => {
                            return json!({"ok": false, "code": ERR_JSON_INVALID, "message": msg})
                        }
                    }
                }
                list
            }
            None => Vec::new(),
        };

        let options = req.get("options").cloned().unwrap_or_else(|| json!({}));
        let up = bool_field(&options, "up", true);
        let uv = bool_field(&options, "uv", true);

        let extensions = match build_extensions(req.get("extensions")) {
            Ok(v) => v,
            Err(err_val) => return err_val,
        };

        let request = GetAssertionRequest {
            rp_id,
            // Campo wire `allowList`: só nomeia uma credencial quando o
            // chamador fornece um ID; com ID vazio a descoberta é por RP
            // (um descritor vazio aqui esconderia todas as credenciais na
            // contagem de multi-assertion).
            credentials: if credential_id.is_empty() {
                Vec::new()
            } else {
                vec![CredentialDescriptor {
                    r#type: "public-key".to_string(),
                    id: credential_id,
                    transports: None,
                }]
            },
            allow_list: if allow_list.is_empty() {
                None
            } else {
                Some(allow_list)
            },
            client_data_hash,
            extensions,
            options: GetAssertionOptions { up, uv },
            pin_uv_auth_param: None,
            pin_protocol: None,
            uv: Some(uv),
        };

        match self.auth.get_assertion(request) {
            Ok(response) => {
                let auth_data = &response.auth_data;
                let credential_id = response
                    .credential
                    .as_ref()
                    .map(|descriptor| descriptor.id.clone())
                    .unwrap_or_default();
                let mut result = json!({
                    "ok": true,
                    "credential_id": b64_encode(&credential_id),
                    "auth_data": b64_encode(auth_data),
                    "signature": b64_encode(&response.signature),
                    "flags": auth_data[32],
                    "sign_count": sign_count_from_auth_data(auth_data),
                    "user_handle": b64_encode(
                        &response.user.map(|u| u.id).unwrap_or_default()
                    ),
                });
                if let Some(ext) = response.extensions {
                    let mut ext_obj = serde_json::Map::new();
                    if let Some(blob) = ext.cred_blob {
                        ext_obj.insert("credBlob".to_string(), json!(b64_encode(&blob)));
                    }
                    if let Some(min_pin) = ext.min_pin_length {
                        ext_obj.insert("minPinLength".to_string(), json!(min_pin));
                    }
                    if let Some(policy) = ext.cred_protect {
                        ext_obj.insert("credProtect".to_string(), json!(policy));
                    }
                    // §12.5: bytes cifrados sob o segredo compartilhado.
                    if let Some(CborValue::Bytes(secret)) = ext.hmac_secret {
                        ext_obj.insert("hmac-secret".to_string(), json!(b64_encode(&secret)));
                    }
                    if let Some(obj) = result.as_object_mut() {
                        for (k, v) in ext_obj {
                            obj.insert(k, v);
                        }
                    }
                }
                result
            }
            Err(error) => error_value(error),
        }
    }

    fn verify_assertion(&self, req: &Value) -> Value {
        let credential_id = match b64_decode(req.get("credential_id").unwrap_or(&Value::Null)) {
            Ok(v) => v,
            Err(msg) => return json!({"ok": false, "code": ERR_JSON_INVALID, "message": msg}),
        };
        let auth_data = match b64_decode(req.get("auth_data").unwrap_or(&Value::Null)) {
            Ok(v) => v,
            Err(msg) => return json!({"ok": false, "code": ERR_JSON_INVALID, "message": msg}),
        };
        let signature = match b64_decode(req.get("signature").unwrap_or(&Value::Null)) {
            Ok(v) => v,
            Err(msg) => return json!({"ok": false, "code": ERR_JSON_INVALID, "message": msg}),
        };
        let client_data_hash = match b64_decode(req.get("client_data_hash").unwrap_or(&Value::Null))
        {
            Ok(v) => v,
            Err(msg) => return json!({"ok": false, "code": ERR_JSON_INVALID, "message": msg}),
        };

        let ctap = self.auth.get_webauthn_authenticator().get_ctap();
        let stored = ctap.get_storage().list_credentials();
        let credential = stored.iter().find(|c| c.credential_id == credential_id);

        match credential {
            Some(credential) => {
                let mut data_to_sign = Vec::new();
                data_to_sign.extend_from_slice(&auth_data[..32]);
                data_to_sign.extend_from_slice(&auth_data[32..37]);
                data_to_sign.extend_from_slice(&client_data_hash);
                let valid = match credential.algorithm {
                    -7 => ctap
                        .get_crypto()
                        .verify_p256(&credential.public_key, &data_to_sign, &signature)
                        .is_ok(),
                    -35 => ctap
                        .get_crypto()
                        .verify_p384(&credential.public_key, &data_to_sign, &signature)
                        .is_ok(),
                    -257 => ctap
                        .get_crypto()
                        .verify_rsa(&credential.public_key, &data_to_sign, &signature)
                        .is_ok(),
                    -37 => ctap
                        .get_crypto()
                        .verify_rsa_pss(&credential.public_key, &data_to_sign, &signature)
                        .is_ok(),
                    -8 => ctap
                        .get_crypto()
                        .verify(&data_to_sign, &signature, &credential.public_key)
                        .unwrap_or(false),
                    _ => ctap
                        .get_crypto()
                        .verify(&data_to_sign, &signature, &credential.public_key)
                        .unwrap_or(false),
                };
                json!({"ok": true, "valid": valid})
            }
            None => json!({"ok": true, "valid": false, "reason": "credential not found"}),
        }
    }

    fn get_info(&self) -> Value {
        match self.auth.get_info() {
            Ok(info) => {
                let aaguid_hex: String = info.aaguid.iter().map(|b| format!("{:02x}", b)).collect();
                json!({
                    "ok": true,
                    "aaguid": aaguid_hex,
                    "versions": info.versions,
                    "extensions": info.extensions,
                    "options": info.options,
                    "rp_count": info.rp_count,
                    "firmware_version": info.firmware_version,
                    "max_credentials": info.max_credential_count,
                    "max_credential_id_length": info.max_credential_id_length,
                    "algorithms": info.algorithms,
                })
            }
            Err(error) => error_value(error),
        }
    }

    fn process_command(&mut self, req: &Value) -> Value {
        let cmd = req.get("cmd").and_then(Value::as_u64).unwrap_or(0) as u8;
        let data = match b64_decode(req.get("data").unwrap_or(&Value::Null)) {
            Ok(v) => v,
            Err(msg) => return json!({"ok": false, "code": ERR_JSON_INVALID, "message": msg}),
        };
        match self.auth.process_command(cmd, data) {
            Ok(response) => json!({"ok": true, "cbor": b64_encode(&response)}),
            Err(error) => json!({"ok": false, "code": error.as_u8(), "message": error.to_string()}),
        }
    }

    /// Roteia uma APDU ISO 7816 bruta (hex) ao `CardRouter` multi-protocolo.
    ///
    /// Request: `{"op":"apdu","apdu":"<hex CLA INS P1 P2 [Lc data] [Le]>"}`.
    /// Formas curta e estendida (casos 1/2S/3S/4S/2E/3E/4E) são aceitas; `Le`
    /// ausente na resposta gera encadeamento `61 XX` a consumir com
    /// GET RESPONSE (`00c0000000`) na chamada seguinte.
    /// Response: `{"ok":true,"response":"<hex data+SW>","data":"<hex>",
    /// "sw":36864}` (`sw` decimal, `0x9000` no sucesso).
    fn apdu(&mut self, req: &Value) -> Value {
        let hex = match req.get("apdu").and_then(Value::as_str) {
            Some(hex) => hex,
            None => {
                return json!({"ok": false, "code": ERR_JSON_INVALID, "message": "campo apdu ausente"});
            }
        };
        let raw = match hex_decode(hex) {
            Ok(raw) => raw,
            Err(msg) => return json!({"ok": false, "code": ERR_JSON_INVALID, "message": msg}),
        };
        let resp = self.card_router.process(&raw);
        let sw = resp.sw.unwrap_or(0x9000);
        json!({
            "ok": true,
            "response": hex_encode(&resp.to_bytes()),
            "data": hex_encode(&resp.data),
            "sw": sw,
        })
    }

    fn client_pin(&mut self, req: &Value) -> Value {
        use ctap2::client_pin::{self, ClientPin, ClientPinSubCommand};

        let sub = req.get("sub_command").and_then(Value::as_u64).unwrap_or(0) as u8;
        let pin = match b64_decode(req.get("pin").unwrap_or(&Value::Null)) {
            Ok(v) => v,
            Err(msg) => return json!({"ok": false, "code": ERR_JSON_INVALID, "message": msg}),
        };
        let new_pin = match b64_decode(req.get("new_pin").unwrap_or(&Value::Null)) {
            Ok(v) => v,
            Err(msg) => return json!({"ok": false, "code": ERR_JSON_INVALID, "message": msg}),
        };

        let ctap = self.auth.get_webauthn_authenticator_mut().get_ctap_mut();

        let sub_command = match ClientPinSubCommand::from_u8(sub) {
            Some(s) => s,
            None => {
                return json!({"ok": false, "code": 0x02, "message": "sub_command invalido"});
            }
        };

        match sub_command {
            ClientPinSubCommand::GetPINRetries => {
                let retries = ctap.get_pin_retries();
                let blocked = client_pin::is_pin_blocked(ctap);
                json!({"ok": true, "retries": retries, "power_cycle_state": blocked})
            }
            ClientPinSubCommand::SetPIN => match ctap.set_pin(&pin) {
                Ok(()) => json!({"ok": true}),
                Err(error) => {
                    json!({"ok": false, "code": error.as_u8(), "message": error.to_string()})
                }
            },
            ClientPinSubCommand::ChangePIN => match ctap.change_pin(&pin, &new_pin) {
                Ok(()) => json!({"ok": true}),
                Err(error) => {
                    json!({"ok": false, "code": error.as_u8(), "message": error.to_string()})
                }
            },
            ClientPinSubCommand::GetPINToken => match ctap.verify_pin(&pin) {
                Ok(()) => {
                    // Rota JSON de conveniência para testes: o token do wire
                    // CTAP2 exige acordo de chaves; aqui devolve-se um valor
                    // opaco de 32 bytes.
                    let token = ctap.get_crypto().random_bytes(32);
                    json!({"ok": true, "pin_uv_auth_token": b64_encode(&token)})
                }
                Err(error) => {
                    json!({"ok": false, "code": error.as_u8(), "message": error.to_string()})
                }
            },
            _ => {
                json!({"ok": false, "code": 0x2E, "message": "sub_command nao suportado no modo JSON"})
            }
        }
    }

    fn get_next_assertion(&mut self) -> Value {
        match self
            .auth
            .get_webauthn_authenticator_mut()
            .get_ctap_mut()
            .process_command(0x08, vec![])
        {
            Ok(response) => {
                if response.len() == 1 && response[0] == 0x00 {
                    json!({"ok": true})
                } else {
                    match ctap2::decode_cbor::<ctap2::GetAssertionResponse>(&response) {
                        Ok(assertion) => json!({
                            "ok": true,
                            "credential_id": b64_encode(&assertion.credential.as_ref().map(|c| c.id.clone()).unwrap_or_default()),
                            "number_of_credentials": assertion.number_of_credentials,
                            "user_handle": b64_encode(
                                &assertion.user.map(|u| u.id).unwrap_or_default()
                            ),
                        }),
                        Err(_) => json!({"ok": true, "cbor": b64_encode(&response)}),
                    }
                }
            }
            Err(error) => json!({"ok": false, "code": error.as_u8(), "message": error.to_string()}),
        }
    }

    fn enumerate_rps_initial(&mut self) -> Value {
        match self
            .auth
            .get_webauthn_authenticator_mut()
            .get_ctap_mut()
            .process_command(0x3B, vec![])
        {
            Ok(response) => match ctap2::decode_cbor::<ctap2::EnumerateRPsResponse>(&response) {
                Ok(rps) => json!({
                    "ok": true,
                    "rp": {"id": rps.rp.id, "name": rps.rp.name, "icon": rps.rp.icon},
                    "rp_hash": b64_encode(&rps.rp_hash),
                    "total_rps": rps.total_rps,
                }),
                Err(error) => {
                    json!({"ok": false, "code": Ctap2Error::InvalidCbor.as_u8(), "message": error.to_string()})
                }
            },
            Err(error) => json!({"ok": false, "code": error.as_u8(), "message": error.to_string()}),
        }
    }

    fn enumerate_rps_next(&mut self) -> Value {
        match self
            .auth
            .get_webauthn_authenticator_mut()
            .get_ctap_mut()
            .process_command(0x3C, vec![])
        {
            Ok(response) => match ctap2::decode_cbor::<ctap2::EnumerateRPsResponse>(&response) {
                Ok(rps) => json!({
                    "ok": true,
                    "rp": {"id": rps.rp.id, "name": rps.rp.name, "icon": rps.rp.icon},
                    "rp_hash": b64_encode(&rps.rp_hash),
                    "total_rps": rps.total_rps,
                }),
                Err(error) => {
                    json!({"ok": false, "code": Ctap2Error::InvalidCbor.as_u8(), "message": error.to_string()})
                }
            },
            Err(error) => json!({"ok": false, "code": error.as_u8(), "message": error.to_string()}),
        }
    }

    fn bio_enroll(&mut self, req: &Value) -> Value {
        let sub = req.get("sub_command").and_then(Value::as_u64).unwrap_or(0) as u8;

        let request = ctap2::BioEnrollRequest {
            sub_command: sub,
            sub_command_params: None,
        };

        let data = match ctap2::encode_cbor(&request) {
            Ok(d) => d,
            Err(error) => {
                return json!({"ok": false, "code": error.as_u8(), "message": error.to_string()})
            }
        };

        match self
            .auth
            .get_webauthn_authenticator_mut()
            .get_ctap_mut()
            .process_command(0x09, data)
        {
            Ok(response) => match ctap2::decode_cbor::<ctap2::BioEnrollResponse>(&response) {
                Ok(bio) => json!({
                    "ok": true,
                    "fingerprint_kind": bio.fingerprint_kind,
                    "max_enrollments": bio.max_enrollments,
                }),
                Err(_) => json!({"ok": true, "cbor": b64_encode(&response)}),
            },
            Err(error) => json!({"ok": false, "code": error.as_u8(), "message": error.to_string()}),
        }
    }
}

fn run_raw_cbor(mut simulator: Simulator) {
    use std::io::Read;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut in_reader = stdin.lock();
    let mut out = stdout.lock();

    loop {
        let mut len_buf = [0u8; 2];
        if in_reader.read_exact(&mut len_buf).is_err() {
            break;
        }
        let total_len = u16::from_be_bytes(len_buf) as usize;
        if total_len == 0 {
            continue;
        }

        let mut payload = vec![0u8; total_len];
        if in_reader.read_exact(&mut payload).is_err() {
            break;
        }

        let cmd = payload[0];
        let data = payload[1..].to_vec();

        let (status, resp_data) = match simulator.auth.process_command(cmd, data) {
            Ok(resp) => (0x00u8, resp),
            Err(err) => (err.as_u8(), Vec::new()),
        };

        let resp_len = (1 + resp_data.len()) as u16;
        if out.write_all(&resp_len.to_be_bytes()).is_err() {
            break;
        }
        if out.write_all(&[status]).is_err() {
            break;
        }
        if !resp_data.is_empty() && out.write_all(&resp_data).is_err() {
            break;
        }
        let _ = out.flush();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let raw_cbor = args.iter().any(|arg| arg == "--raw-cbor");
    let storage_path = args
        .iter()
        .position(|arg| arg == "--storage-path")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from);

    let mut simulator = match if let Some(path) = storage_path {
        Simulator::with_storage_path(path)
    } else {
        Simulator::new()
    } {
        Ok(simulator) => simulator,
        Err(error) => {
            eprintln!("falha ao iniciar o simulador: {error}");
            process::exit(1);
        }
    };

    if raw_cbor {
        run_raw_cbor(simulator);
        return;
    }

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(_) => {
                let _ = writeln!(
                    out,
                    "{{\"ok\":false,\"code\":{ERR_JSON_INVALID},\"message\":\"json invalido\"}}"
                );
                let _ = out.flush();
                continue;
            }
        };

        let op = request.get("op").and_then(Value::as_str).unwrap_or("");
        let response = match op {
            "set_attestation_format" => simulator.set_attestation_format(&request),
            "make_credential" => simulator.make_credential(&request),
            "get_assertion" => simulator.get_assertion(&request),
            "verify_assertion" => simulator.verify_assertion(&request),
            "get_next_assertion" => simulator.get_next_assertion(),
            "enumerate_rps_initial" => simulator.enumerate_rps_initial(),
            "enumerate_rps_next" => simulator.enumerate_rps_next(),
            "bio_enroll" => simulator.bio_enroll(&request),
            "process_command" => simulator.process_command(&request),
            "apdu" => simulator.apdu(&request),
            "client_pin" => simulator.client_pin(&request),
            "get_info" => simulator.get_info(),
            "reset" => simulator.reset(),
            _ => json!({"ok": false, "code": 0x01, "message": format!("op desconhecida: {op}")}),
        };

        let _ = writeln!(out, "{response}");
        let _ = out.flush();
    }
}
