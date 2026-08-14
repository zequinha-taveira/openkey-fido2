use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process;

use authenticator::EmbeddedAuthenticator;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ciborium::Value as CborValue;
use ctap2::{
    AttestationCertificate, AttestationFormat, CredentialDescriptor, Ctap2Error, Extensions,
    GetAssertionOptions, GetAssertionRequest, HmacSecretInput, MakeCredentialOptions,
    MakeCredentialRequest, PublicKeyCredParams, RelyingParty, User,
};
use device_profile::DeviceProfileBuilder;
use serde_json::{json, Value};

const ERR_JSON_INVALID: u8 = 0x02;

/// Placeholder DER blob used as the packed attestation certificate in tests.
const TEST_ATTESTATION_CERT: &[u8] = &[0x30, 0x82, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];

struct Simulator {
    auth: EmbeddedAuthenticator,
    storage_path: Option<PathBuf>,
}

fn b64_encode(data: &[u8]) -> String {
    BASE64.encode(data)
}

fn b64_decode(value: &Value) -> Vec<u8> {
    value
        .as_str()
        .map(|s| BASE64.decode(s).unwrap_or_default())
        .unwrap_or_default()
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
        json!({"ok": false, "code": 0x05, "message": error.to_string()})
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

fn build_extensions(ext_val: Option<&Value>) -> Option<Extensions> {
    let ext_val = ext_val?;
    if ext_val.is_null() {
        return None;
    }
    let cred_protect = ext_val
        .get("credProtect")
        .and_then(Value::as_u64)
        .map(|v| ctap2::CredProtectPolicy::from(v as u8));
    let cred_blob = ext_val
        .get("credBlob")
        .map(b64_decode)
        .filter(|b| !b.is_empty());
    let min_pin_length = ext_val
        .get("minPinLength")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let hmac_secret = ext_val.get("hmacSecret").map(|v| HmacSecretInput {
        salt_enc: b64_decode(v.get("saltEnc").unwrap_or(&Value::Null)),
        pin_uv_auth_protocol: v
            .get("pinUvAuthProtocol")
            .and_then(Value::as_u64)
            .map(|p| p as u8),
    });

    Some(Extensions {
        cred_protect,
        cred_blob,
        min_pin_length,
        hmac_secret,
        large_blob_key: false,
    })
}

impl Simulator {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            auth: EmbeddedAuthenticator::new()?,
            storage_path: None,
        })
    }

    fn with_storage_path(path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let profile = DeviceProfileBuilder::new().build();
        Ok(Self {
            auth: EmbeddedAuthenticator::new_with_storage_path(path.clone(), profile)?,
            storage_path: Some(path),
        })
    }

    fn reset(&mut self) -> Value {
        let result = if let Some(path) = &self.storage_path {
            let profile = DeviceProfileBuilder::new().build();
            EmbeddedAuthenticator::new_with_storage_path(path.clone(), profile)
        } else {
            EmbeddedAuthenticator::new()
        };
        match result {
            Ok(auth) => {
                self.auth = auth;
                json!({"ok": true})
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
        let client_data = b64_decode(req.get("client_data").unwrap_or(&Value::Null));
        let user_id = b64_decode(req.get("user_id").unwrap_or(&Value::Null));

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

        let exclude_list: Vec<CredentialDescriptor> = req
            .get("exclude")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| CredentialDescriptor {
                        r#type: "public-key".to_string(),
                        id: b64_decode(item),
                        transports: None,
                    })
                    .collect()
            })
            .unwrap_or_default();

        let options = req.get("options").cloned().unwrap_or_else(|| json!({}));
        let mc_options = MakeCredentialOptions {
            rk: bool_field(&options, "rk", false),
            uv: bool_field(&options, "uv", true),
            up: bool_field(&options, "up", true),
            extended: false,
        };

        let extensions = build_extensions(req.get("extensions"));

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
                    if let Some(secret) = ext.hmac_secret {
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

    fn get_assertion(&mut self, req: &Value) -> Value {
        let rp_id = req
            .get("rp_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let credential_id = b64_decode(req.get("credential_id").unwrap_or(&Value::Null));
        let client_data_hash = b64_decode(req.get("client_data_hash").unwrap_or(&Value::Null));

        let allow_list: Vec<CredentialDescriptor> = req
            .get("allow_list")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| CredentialDescriptor {
                        r#type: "public-key".to_string(),
                        id: b64_decode(item),
                        transports: None,
                    })
                    .collect()
            })
            .unwrap_or_default();

        let options = req.get("options").cloned().unwrap_or_else(|| json!({}));
        let up = bool_field(&options, "up", true);
        let uv = bool_field(&options, "uv", true);

        let extensions = build_extensions(req.get("extensions"));

        let request = GetAssertionRequest {
            rp_id,
            credentials: vec![CredentialDescriptor {
                r#type: "public-key".to_string(),
                id: credential_id,
                transports: None,
            }],
            allow_list: if allow_list.is_empty() {
                None
            } else {
                Some(allow_list)
            },
            client_data_hash,
            extensions,
            options: GetAssertionOptions { up, uv },
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
                    if let Some(secret) = ext.hmac_secret {
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
        let credential_id = b64_decode(req.get("credential_id").unwrap_or(&Value::Null));
        let auth_data = b64_decode(req.get("auth_data").unwrap_or(&Value::Null));
        let signature = b64_decode(req.get("signature").unwrap_or(&Value::Null));
        let client_data_hash = b64_decode(req.get("client_data_hash").unwrap_or(&Value::Null));

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
                    -257 => ctap
                        .get_crypto()
                        .verify_rsa(&credential.public_key, &data_to_sign, &signature)
                        .is_ok(),
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
        let data = b64_decode(req.get("data").unwrap_or(&Value::Null));
        match self.auth.process_command(cmd, data) {
            Ok(response) => json!({"ok": true, "cbor": b64_encode(&response)}),
            Err(error) => json!({"ok": false, "code": error.as_u8(), "message": error.to_string()}),
        }
    }

    fn client_pin(&mut self, req: &Value) -> Value {
        use ctap2::client_pin::{self, ClientPin, ClientPinSubCommand};

        let sub = req.get("sub_command").and_then(Value::as_u64).unwrap_or(0) as u8;
        let pin = b64_decode(req.get("pin").unwrap_or(&Value::Null));
        let new_pin = b64_decode(req.get("new_pin").unwrap_or(&Value::Null));

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
                let blocked = client_pin::is_pin_blocked(ctap.get_storage());
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
                Ok(()) => match ctap.get_pin_token() {
                    Ok(token) => json!({"ok": true, "pin_uv_auth_token": b64_encode(&token)}),
                    Err(error) => {
                        json!({"ok": false, "code": error.as_u8(), "message": error.to_string()})
                    }
                },
                Err(error) => {
                    json!({"ok": false, "code": error.as_u8(), "message": error.to_string()})
                }
            },
            ClientPinSubCommand::GetPINHashEnc => match ctap.get_pin_hash_enc() {
                Ok(hash_enc) => json!({"ok": true, "key_agreement": b64_encode(&hash_enc)}),
                Err(error) => {
                    json!({"ok": false, "code": error.as_u8(), "message": error.to_string()})
                }
            },
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
                            "next": assertion.next,
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
                Err(error) => json!({"ok": false, "code": 0x04, "message": error.to_string()}),
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
                Err(error) => json!({"ok": false, "code": 0x04, "message": error.to_string()}),
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
            "client_pin" => simulator.client_pin(&request),
            "get_info" => simulator.get_info(),
            "reset" => simulator.reset(),
            _ => json!({"ok": false, "code": 0x01, "message": format!("op desconhecida: {op}")}),
        };

        let _ = writeln!(out, "{response}");
        let _ = out.flush();
    }
}
