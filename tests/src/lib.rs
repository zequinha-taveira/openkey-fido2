#![allow(unused_imports)]
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use ciborium::value::Integer;
use ciborium::Value;
use crypto::CryptoEngine;
use ctap2::{
    CredentialDescriptor, Ctap2Authenticator, Ctap2Error, GetAssertionOptions, GetAssertionRequest,
    MakeCredentialOptions, MakeCredentialRequest, PublicKeyCredParams, RelyingParty, User,
};
use rand::RngCore;
use storage::StorageEngine;

fn make_request(user_id: &[u8]) -> MakeCredentialRequest {
    MakeCredentialRequest {
        client_data_hash: b"{\"challenge\":\"test\"}".to_vec(),
        rp: RelyingParty {
            id: "example.com".to_string(),
            name: Some("Example".to_string()),
            icon: None,
        },
        user: User {
            id: user_id.to_vec(),
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
    }
}

fn make_request_es256(user_id: &[u8]) -> MakeCredentialRequest {
    MakeCredentialRequest {
        client_data_hash: b"{\"challenge\":\"test\"}".to_vec(),
        rp: RelyingParty {
            id: "example.com".to_string(),
            name: Some("Example".to_string()),
            icon: None,
        },
        user: User {
            id: user_id.to_vec(),
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
            uv: true,
            up: true,
            extended: false,
        },
        pin_uv_auth_param: None,
        pin_protocol: None,
        enterprise_protections: None,
    }
}

fn make_assert_request(
    authenticator: &Ctap2Authenticator,
    rp_id: &str,
    cred_id: Vec<u8>,
    allow_list: Option<Vec<CredentialDescriptor>>,
) -> GetAssertionRequest {
    GetAssertionRequest {
        rp_id: rp_id.to_string(),
        credentials: vec![CredentialDescriptor {
            r#type: "public-key".to_string(),
            id: cred_id,
            transports: None,
        }],
        allow_list,
        client_data_hash: authenticator.get_crypto().sha256(b"client data hash"),
        extensions: None,
        options: GetAssertionOptions { up: true, uv: true },
        pin_uv_auth_param: None,
        pin_protocol: None,
        uv: Some(true),
    }
}

fn sign_count_from_auth_data(auth_data: &[u8]) -> u32 {
    u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]])
}

#[test]
fn test_crypto_key_pair_generation() {
    let crypto = CryptoEngine::new().unwrap();
    let (private_key, public_key) = crypto.generate_key_pair().unwrap();
    assert_eq!(private_key.len(), 32);
    assert_eq!(public_key.len(), 32);
}

#[test]
fn test_crypto_sign_verify_roundtrip() {
    let crypto = CryptoEngine::new().unwrap();
    let (private_key, public_key) = crypto.generate_key_pair().unwrap();
    let data = b"hello world";
    let signature = crypto.sign(data, &private_key).unwrap();
    assert_eq!(signature.len(), 64);
    assert!(crypto.verify(data, &signature, &public_key).unwrap());
}

#[test]
fn test_crypto_sign_verify_tampered_data() {
    let crypto = CryptoEngine::new().unwrap();
    let (private_key, public_key) = crypto.generate_key_pair().unwrap();
    let data = b"hello world";
    let tampered_data = b"hello worlD";
    let signature = crypto.sign(data, &private_key).unwrap();
    assert!(crypto
        .verify(tampered_data, &signature, &public_key)
        .is_err());
}

#[test]
fn test_crypto_encrypt_decrypt_roundtrip() {
    let crypto = CryptoEngine::new().unwrap();
    let plaintext = b"secret message";
    let nonce = [0u8; 12];
    let ciphertext = crypto.encrypt(plaintext, &nonce).unwrap();
    assert_ne!(ciphertext, plaintext);
    let decrypted = crypto.decrypt(&ciphertext, &nonce).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_crypto_encrypt_tampered_ciphertext() {
    let crypto = CryptoEngine::new().unwrap();
    let plaintext = b"secret message";
    let nonce = [0u8; 12];
    let mut ciphertext = crypto.encrypt(plaintext, &nonce).unwrap();
    ciphertext[0] ^= 0xFF;
    let result = crypto.decrypt(&ciphertext, &nonce);
    assert!(result.is_err());
}

#[test]
fn test_ctap2_make_credential_stores_credential() {
    let crypto = CryptoEngine::new().unwrap();
    let storage = StorageEngine::new().unwrap();
    let mut authenticator = Ctap2Authenticator::new(ctap2::AAGUID, crypto, storage).unwrap();

    let request = MakeCredentialRequest {
        client_data_hash: b"{\"challenge\":\"test\",\"origin\":\"https://example.com\"}".to_vec(),
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
    assert_eq!(response.fmt, "none");
    assert!(response.auth_data.len() > 37);

    let stored = authenticator.get_storage().list_credentials();
    assert_eq!(stored.len(), 1);
}

#[test]
fn test_ctap2_get_assertion_signs_data() {
    let crypto = CryptoEngine::new().unwrap();
    let storage = StorageEngine::new().unwrap();
    let mut authenticator = Ctap2Authenticator::new(ctap2::AAGUID, crypto, storage).unwrap();

    let make_request = MakeCredentialRequest {
        client_data_hash: b"{}".to_vec(),
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
        pub_key_cred_params: vec![],
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

    let _make_response = authenticator.make_credential(make_request).unwrap();

    let credential = authenticator.get_storage().list_credentials();
    let cred_id = credential[0].credential_id.clone();
    let public_key = credential[0].public_key.clone();
    let client_data_hash = authenticator.get_crypto().sha256(b"client data hash");
    let client_data_hash_clone = client_data_hash.clone();

    let assert_request = GetAssertionRequest {
        rp_id: "example.com".to_string(),
        credentials: vec![CredentialDescriptor {
            r#type: "public-key".to_string(),
            id: cred_id,
            transports: None,
        }],
        allow_list: None,
        client_data_hash: client_data_hash_clone,
        extensions: None,
        options: GetAssertionOptions { up: true, uv: true },
        pin_uv_auth_param: None,
        pin_protocol: None,
        uv: Some(true),
    };

    let assert_response = authenticator.get_assertion(assert_request).unwrap();
    assert!(!assert_response.signature.is_empty());

    let data_to_verify = {
        let auth = &assert_response.auth_data;
        let mut d = vec![];
        d.extend_from_slice(&auth[..32]);
        d.extend_from_slice(&auth[32..37]);
        d.extend_from_slice(&client_data_hash);
        d
    };
    let verified = authenticator
        .get_crypto()
        .verify(&data_to_verify, &assert_response.signature, &public_key)
        .unwrap();
    assert!(verified);
}

#[test]
fn test_ctap2_get_info() {
    let crypto = CryptoEngine::new().unwrap();
    let storage = StorageEngine::new().unwrap();
    let authenticator = Ctap2Authenticator::new(ctap2::AAGUID, crypto, storage).unwrap();

    let info = authenticator.get_info().unwrap();
    assert!(info.versions.contains(&"2.0".to_string()));
    assert!(info.versions.contains(&"2.1".to_string()));
    assert_eq!(info.aaguid, vec![0u8; 16]);
    assert!(info.options.contains(&"rk".to_string()));
    assert!(info.options.contains(&"up".to_string()));
    assert_eq!(info.firmware_version, 1_000);
}

#[test]
fn test_ctap2_get_info_custom_aaguid() {
    let aaguid: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10,
    ];
    let crypto = CryptoEngine::new().unwrap();
    let storage = StorageEngine::new().unwrap();
    let authenticator = Ctap2Authenticator::new(aaguid, crypto, storage).unwrap();

    let info = authenticator.get_info().unwrap();
    assert_eq!(
        info.aaguid,
        vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10
        ]
    );

    let other_crypto = CryptoEngine::new().unwrap();
    let other_storage = StorageEngine::new().unwrap();
    let other = Ctap2Authenticator::new(ctap2::AAGUID, other_crypto, other_storage).unwrap();
    assert_ne!(info.aaguid, other.get_info().unwrap().aaguid);
}

#[test]
fn test_ctap2_get_version() {
    let crypto = CryptoEngine::new().unwrap();
    let storage = StorageEngine::new().unwrap();
    let authenticator = Ctap2Authenticator::new(ctap2::AAGUID, crypto, storage).unwrap();

    let version = authenticator.get_version().unwrap();
    assert_eq!(version.firmware_version, "0.1.0");
}

#[test]
fn test_ctap2_process_command_make_credential() {
    let crypto = CryptoEngine::new().unwrap();
    let storage = StorageEngine::new().unwrap();
    let mut authenticator = Ctap2Authenticator::new(ctap2::AAGUID, crypto, storage).unwrap();

    let request = MakeCredentialRequest {
        client_data_hash: b"{}".to_vec(),
        rp: RelyingParty {
            id: "example.com".to_string(),
            name: None,
            icon: None,
        },
        user: User {
            id: b"user456".to_vec(),
            name: None,
            display_name: None,
            icon_url: None,
        },
        pub_key_cred_params: vec![],
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

    let mut cbor_buf = Vec::<u8>::new();
    ciborium::ser::into_writer(&request, &mut cbor_buf).unwrap();
    let result = authenticator.process_command(0x01, cbor_buf);
    assert!(result.is_ok());
    let response_data = result.unwrap();
    let response: ctap2::MakeCredentialResponse = ctap2::decode_cbor(&response_data).unwrap();
    assert_eq!(response.fmt, "none");
}

#[test]
fn test_ctap2_process_command_get_info() {
    let crypto = CryptoEngine::new().unwrap();
    let storage = StorageEngine::new().unwrap();
    let mut authenticator = Ctap2Authenticator::new(ctap2::AAGUID, crypto, storage).unwrap();

    let result = authenticator.process_command(0x04, vec![]);
    assert!(result.is_ok());
    let response_data = result.unwrap();
    let wire: ciborium::Value = ciborium::de::from_reader(response_data.as_slice()).unwrap();
    let firmware_version = match wire {
        ciborium::Value::Map(entries) => entries.into_iter().find_map(|(key, value)| match key {
            ciborium::Value::Integer(number) if number == 0x0E.into() => Some(value),
            _ => None,
        }),
        _ => None,
    };
    assert_eq!(
        firmware_version,
        Some(ciborium::Value::Integer(1_000.into()))
    );
    let response: ctap2::GetInfoResponse = ctap2::decode_cbor(&response_data).unwrap();
    assert!(response.versions.contains(&"2.0".to_string()));
}

#[test]
fn test_ctap2_process_command_unknown_command() {
    let crypto = CryptoEngine::new().unwrap();
    let storage = StorageEngine::new().unwrap();
    let mut authenticator = Ctap2Authenticator::new(ctap2::AAGUID, crypto, storage).unwrap();

    let result = authenticator.process_command(0xFF, vec![]);
    assert_eq!(result.unwrap_err(), Ctap2Error::InvalidCommand);
}

#[test]
fn test_storage_credential_persistence() {
    let crypto = CryptoEngine::new().unwrap();
    let mut storage = StorageEngine::new().unwrap();

    let credential = storage::Credential {
        credential_id: vec![1, 2, 3, 4, 5],
        public_key: vec![6; 32],
        private_key: vec![7; 32],
        sign_count: 42,
        rp_id_hash: vec![8; 32],
        user_handle: Some(vec![9; 16]),
        cred_blob: Vec::new(),
        created_at: 1000,
        algorithm: -8,
        rp_id: "example.com".to_string(),
        large_blob_key: None,
        user_name: None,
        user_display_name: None,
        cred_protect: None,
        cred_random_with_uv: None,
        cred_random_without_uv: None,
    };

    storage
        .store_credential(credential.clone(), &crypto)
        .unwrap();
    let retrieved = storage
        .get_credential(&credential.credential_id, &crypto)
        .unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.credential_id, credential.credential_id);
    assert_eq!(retrieved.public_key, credential.public_key);
    assert_eq!(retrieved.sign_count, credential.sign_count);
    assert_eq!(retrieved.user_handle, credential.user_handle);
}

#[test]
fn test_ctap2_cose_key_is_valid_cbor_map() {
    let crypto = CryptoEngine::new().unwrap();
    let storage = StorageEngine::new().unwrap();
    let mut authenticator = Ctap2Authenticator::new(ctap2::AAGUID, crypto, storage).unwrap();

    let response = authenticator
        .make_credential(make_request(b"user123"))
        .unwrap();
    let (cred_id, public_key) = {
        let stored = authenticator.get_storage().list_credentials();
        assert_eq!(stored.len(), 1);
        (
            stored[0].credential_id.clone(),
            stored[0].public_key.clone(),
        )
    };

    // authData: rpIdHash(32) || flags(1) || signCount(4) ||
    //           aaguid(16) || credIdLen(2) || credId || COSE_Key
    let auth = &response.auth_data;
    assert!(auth.len() > 37);
    let cred_id_len = u16::from_be_bytes([auth[53], auth[54]]) as usize;
    let cred_id_start = 55;
    let cose_key_start = cred_id_start + cred_id_len;
    assert_eq!(&auth[cred_id_start..cose_key_start], &cred_id[..]);

    let map: BTreeMap<i64, Value> = ciborium::de::from_reader(&auth[cose_key_start..]).unwrap();
    assert_eq!(map.len(), 4);
    assert_eq!(map[&1], Value::Integer(Integer::from(1))); // kty = OKP
    assert_eq!(map[&3], Value::Integer(Integer::from(-8))); // alg = EdDSA
    assert_eq!(map[&-1], Value::Integer(Integer::from(6))); // crv = Ed25519
    match &map[&-2] {
        Value::Bytes(x) => {
            assert_eq!(x.len(), 32);
            assert_eq!(x, &public_key);
        }
        other => panic!("expected byte string for x coordinate, got {:?}", other),
    }
}

#[test]
fn test_ctap2_sign_count_increments_between_assertions() {
    let crypto = CryptoEngine::new().unwrap();
    let storage = StorageEngine::new().unwrap();
    let mut authenticator = Ctap2Authenticator::new(ctap2::AAGUID, crypto, storage).unwrap();

    authenticator
        .make_credential(make_request(b"user123"))
        .unwrap();

    let cred_id = {
        let stored = authenticator.get_storage().list_credentials();
        stored[0].credential_id.clone()
    };

    let first = authenticator
        .get_assertion(make_assert_request(
            &authenticator,
            "example.com",
            cred_id.clone(),
            None,
        ))
        .unwrap();
    let second = authenticator
        .get_assertion(make_assert_request(
            &authenticator,
            "example.com",
            cred_id.clone(),
            None,
        ))
        .unwrap();

    assert_eq!(sign_count_from_auth_data(&first.auth_data), 1);
    assert_eq!(sign_count_from_auth_data(&second.auth_data), 2);

    let stored = authenticator.get_storage().list_credentials();
    assert_eq!(stored[0].sign_count, 2);
}

#[test]
fn test_embedded_authenticator_aaguid_from_board_config() {
    use authenticator::EmbeddedAuthenticator;
    use board_generic::BoardDefinition;

    let aaguid: [u8; 16] = [
        0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33,
        0x44,
    ];
    let config = BoardDefinition::new("test-board", aaguid)
        .i2c_sda(0)
        .i2c_scl(1)
        .spi_mosi(2)
        .spi_miso(3)
        .spi_clk(4)
        .cs(5)
        .reset(6)
        .irq(7)
        .led(8)
        .button(9);

    let authenticator = EmbeddedAuthenticator::new_with_board(&config).unwrap();
    let info = authenticator.get_info().unwrap();
    assert_eq!(
        info.aaguid,
        vec![
            0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22,
            0x33, 0x44
        ]
    );

    let default = EmbeddedAuthenticator::new().unwrap();
    let default_info = default.get_info().unwrap();
    assert_eq!(default_info.aaguid, vec![0u8; 16]);
    assert_ne!(info.aaguid, default_info.aaguid);
}

#[test]
fn test_ctap2_allow_list_is_respected() {
    let crypto = CryptoEngine::new().unwrap();
    let storage = StorageEngine::new().unwrap();
    let mut authenticator = Ctap2Authenticator::new(ctap2::AAGUID, crypto, storage).unwrap();

    authenticator
        .make_credential(make_request(b"userA"))
        .unwrap();
    authenticator
        .make_credential(make_request(b"userB"))
        .unwrap();

    let (id_a, id_b) = {
        let stored = authenticator.get_storage().list_credentials();
        assert_eq!(stored.len(), 2);
        (
            stored[0].credential_id.clone(),
            stored[1].credential_id.clone(),
        )
    };

    let allow_list = Some(vec![CredentialDescriptor {
        r#type: "public-key".to_string(),
        id: id_b.clone(),
        transports: None,
    }]);
    let response = authenticator
        .get_assertion(make_assert_request(
            &authenticator,
            "example.com",
            id_a,
            allow_list,
        ))
        .unwrap();

    // allow_list must take priority over the `credentials` field.
    assert_eq!(response.credential.as_ref().unwrap().id, id_b);
}

#[test]
fn test_device_profile_builder_from_board() {
    use board_generic::BoardDefinition;
    use device_profile::{DeviceProfileBuilder, Transport};

    let aaguid: [u8; 16] = [
        0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33,
        0x44,
    ];
    let board = BoardDefinition::new("test-board", aaguid)
        .usb_ccid()
        .nfc()
        .secure_storage(true)
        .crypto_accelerator(true);

    let profile = DeviceProfileBuilder::from_board(&board).build();

    assert_eq!(profile.product_name, "test-board");
    assert_eq!(profile.aaguid, aaguid);
    assert!(profile.storage_encrypted);
    assert!(profile.crypto_accelerator);
    assert!(profile.transports.contains(&Transport::UsbCcid));
    assert!(profile.transports.contains(&Transport::Nfc));
    assert!(!profile.transports.contains(&Transport::Ble));
}

#[test]
fn test_device_profile_builder_overrides() {
    use device_profile::{AttestationType, DeviceProfileBuilder, Extension, PinPolicy};

    let profile = DeviceProfileBuilder::new()
        .product_name("OpenKey One")
        .vendor_name("OpenKey")
        .firmware_version("2.0.0")
        .attestation(AttestationType::Packed)
        .pin_policy(PinPolicy::Required)
        .rk_support(false)
        .max_credentials(100)
        .build();

    assert_eq!(profile.product_name, "OpenKey One");
    assert_eq!(profile.firmware_version, "2.0.0");
    assert_eq!(profile.attestation, AttestationType::Packed);
    assert_eq!(profile.pin_policy, PinPolicy::Required);
    assert!(!profile.rk_support);
    assert!(profile.extensions.contains(&Extension::CredProtect));
    assert!(profile.extensions.contains(&Extension::CredBlob));
    assert!(profile.extensions.contains(&Extension::MinPinLength));
    assert!(profile.extensions.contains(&Extension::HmacSecret));
    assert_eq!(profile.max_credentials, 100);
}

#[test]
fn test_capability_discovery_reports_runtime() {
    use device_profile::{CapabilityDiscovery, DeviceProfileBuilder, PinPolicy};

    let profile = DeviceProfileBuilder::new()
        .pin_policy(PinPolicy::Optional)
        .rk_support(true)
        .uv_support(false)
        .up_support(true)
        .build();

    let discovery = CapabilityDiscovery::new(profile);
    let caps = discovery.capabilities();

    assert!(caps.client_pin_available);
    assert!(caps.rk);
    assert!(!caps.uv);
    assert!(caps.up);
    assert_eq!(caps.aaguid, [0u8; 16]);
}

#[test]
fn test_embedded_authenticator_capabilities_drive_get_info() {
    use authenticator::EmbeddedAuthenticator;
    use device_profile::{DeviceProfileBuilder, Extension, PinPolicy};

    let profile = DeviceProfileBuilder::new()
        .product_name("OpenKey Pro")
        .firmware_version("3.1.0")
        .pin_policy(PinPolicy::Required)
        .rk_support(true)
        .up_support(true)
        .uv_support(true)
        .extension(Extension::CredProtect)
        .max_credential_id_length(128)
        .build();

    let authenticator = EmbeddedAuthenticator::new_with_profile(profile).unwrap();
    let caps = authenticator.capabilities();
    assert_eq!(caps.product_name, "OpenKey Pro");
    assert!(caps.client_pin_available);

    let info = authenticator.get_info().unwrap();
    assert_eq!(info.firmware_version, 3_001_000);
    assert!(info.options.contains(&"rk".to_string()));
    assert!(info.options.contains(&"clientPin".to_string()));
    assert_eq!(info.max_credential_id_length, 128);
}

#[test]
fn test_embedded_authenticator_capabilities_from_board() {
    use authenticator::EmbeddedAuthenticator;
    use board_generic::BoardDefinition;
    use device_profile::Transport;

    let aaguid: [u8; 16] = [
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0,
        0x00,
    ];
    let board = BoardDefinition::new("ccid-card", aaguid).usb_ccid();
    let authenticator = EmbeddedAuthenticator::new_with_board(&board).unwrap();

    let caps = authenticator.capabilities();
    assert_eq!(caps.aaguid, aaguid);
    assert!(caps.transports.contains(&Transport::UsbCcid));

    let info = authenticator.get_info().unwrap();
    assert_eq!(
        info.aaguid,
        vec![
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
            0xf0, 0x00
        ]
    );
}

#[test]
fn test_board_profiles_derive_correct_product_name_and_transports() {
    use board_generic::profiles::*;
    use device_profile::{DeviceProfileBuilder, Transport};

    let nrf = DeviceProfileBuilder::from_board(&NRF52840).build();
    assert_eq!(nrf.product_name, "nrf52840-fido");
    assert!(nrf.storage_encrypted);
    assert!(nrf.crypto_accelerator);
    assert!(nrf.transports.contains(&Transport::UsbHid));
    assert!(nrf.transports.contains(&Transport::Nfc));
    assert!(nrf.transports.contains(&Transport::Ble));
    assert!(!nrf.transports.contains(&Transport::UsbCcid));

    let stm32 = DeviceProfileBuilder::from_board(&STM32L4).build();
    assert_eq!(stm32.product_name, "stm32l4-fido");
    assert!(stm32.storage_encrypted);
    assert!(stm32.crypto_accelerator);
    assert!(stm32.transports.contains(&Transport::UsbHid));
    assert!(stm32.transports.contains(&Transport::UsbCcid));
    assert!(!stm32.transports.contains(&Transport::Nfc));

    let esp32 = DeviceProfileBuilder::from_board(&ESP32C3).build();
    assert_eq!(esp32.product_name, "esp32c3-fido");
    assert!(!esp32.storage_encrypted);
    assert!(esp32.crypto_accelerator);
    assert!(esp32.transports.contains(&Transport::UsbHid));
    assert!(esp32.transports.contains(&Transport::Ble));
    assert!(!esp32.transports.contains(&Transport::UsbCcid));

    let rp2350 = DeviceProfileBuilder::from_board(&RP2350).build();
    assert_eq!(rp2350.product_name, "rp2350-fido");
    assert!(rp2350.storage_encrypted);
    assert!(rp2350.crypto_accelerator);
    assert!(rp2350.transports.contains(&Transport::UsbHid));
    assert!(rp2350.transports.contains(&Transport::UsbCcid));
    assert!(!rp2350.transports.contains(&Transport::Nfc));
    assert!(rp2350.security.secure_boot);
    assert!(rp2350.security.trust_zone);
    assert!(rp2350.security.hardware_rng);
    assert!(rp2350.security.otp_memory);

    let rp2350_zero = DeviceProfileBuilder::from_board(&RP2350_ZERO).build();
    assert_eq!(rp2350_zero.product_name, "rp2350-zero");
    assert_eq!(rp2350_zero.aaguid, RP2350_ZERO.aaguid);
    assert!(rp2350_zero.storage_encrypted);
    assert!(rp2350_zero.crypto_accelerator);
    assert!(rp2350_zero.transports.contains(&Transport::UsbHid));
    assert!(rp2350_zero.transports.contains(&Transport::UsbCcid));
    assert!(!rp2350_zero.transports.contains(&Transport::Nfc));
    // Mesmos recursos de segurança do SoC RP2350A (TrustZone, TRNG, OTP).
    assert!(rp2350_zero.security.secure_boot);
    assert!(rp2350_zero.security.trust_zone);
    assert!(rp2350_zero.security.hardware_rng);
    assert!(rp2350_zero.security.otp_memory);

    let generic = DeviceProfileBuilder::from_board(&GENERIC).build();
    assert_eq!(generic.product_name, "generic-fido");
    assert!(!generic.storage_encrypted);
    assert!(!generic.crypto_accelerator);
    assert!(generic.transports.contains(&Transport::UsbCcid));
    assert!(!generic.transports.contains(&Transport::UsbHid));
}

#[test]
fn test_embedded_authenticator_with_nrf52840_profile() {
    use authenticator::EmbeddedAuthenticator;
    use board_generic::profiles::NRF52840;

    let authenticator = EmbeddedAuthenticator::new_with_board(&NRF52840).unwrap();
    let info = authenticator.get_info().unwrap();
    assert_eq!(
        info.aaguid,
        vec![
            0x4e, 0x52, 0x46, 0x35, 0x32, 0x38, 0x34, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01
        ]
    );
}

#[test]
fn test_embedded_authenticator_with_rp2350_zero_profile() {
    use authenticator::EmbeddedAuthenticator;
    use board_generic::profiles::RP2350_ZERO;

    let authenticator = EmbeddedAuthenticator::new_with_board(&RP2350_ZERO).unwrap();
    let info = authenticator.get_info().unwrap();
    assert_eq!(info.aaguid, RP2350_ZERO.aaguid.to_vec());
}

#[test]
fn test_board_profiles_have_unique_aaguids() {
    use board_generic::profiles::*;

    let aaguids = [
        NRF52840.aaguid,
        STM32L4.aaguid,
        ESP32C3.aaguid,
        RP2350.aaguid,
        RP2350_ZERO.aaguid,
        GENERIC.aaguid,
    ];
    for i in 0..aaguids.len() {
        for j in (i + 1)..aaguids.len() {
            assert_ne!(aaguids[i], aaguids[j]);
        }
    }
}

#[test]
fn test_storage_private_key_not_stored_in_plaintext() {
    use storage::Credential;

    let crypto = CryptoEngine::new().unwrap();
    let mut storage = StorageEngine::new().unwrap();

    let credential = Credential {
        credential_id: vec![1, 2, 3],
        public_key: vec![6; 32],
        private_key: vec![7; 32],
        sign_count: 0,
        rp_id_hash: vec![8; 32],
        user_handle: None,
        cred_blob: Vec::new(),
        created_at: 0,
        algorithm: -8,
        rp_id: "example.com".to_string(),
        large_blob_key: None,
        user_name: None,
        user_display_name: None,
        cred_protect: None,
        cred_random_with_uv: None,
        cred_random_without_uv: None,
    };

    storage
        .store_credential(credential.clone(), &crypto)
        .unwrap();

    let listed = storage.list_credentials();
    assert!(listed[0].private_key.is_empty());

    let retrieved = storage
        .get_credential(&credential.credential_id, &crypto)
        .unwrap()
        .unwrap();
    assert_eq!(retrieved.private_key, vec![7; 32]);
}

#[test]
fn test_ctap2_allow_list_wrong_rp_returns_error() {
    let crypto = CryptoEngine::new().unwrap();
    let storage = StorageEngine::new().unwrap();
    let mut authenticator = Ctap2Authenticator::new(ctap2::AAGUID, crypto, storage).unwrap();

    authenticator
        .make_credential(make_request(b"user123"))
        .unwrap();

    let cred_id = {
        let stored = authenticator.get_storage().list_credentials();
        stored[0].credential_id.clone()
    };

    let allow_list = Some(vec![CredentialDescriptor {
        r#type: "public-key".to_string(),
        id: cred_id.clone(),
        transports: None,
    }]);
    let result = authenticator.get_assertion(make_assert_request(
        &authenticator,
        "evil.com",
        cred_id,
        allow_list,
    ));
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(
        *err.downcast_ref::<Ctap2Error>().unwrap(),
        Ctap2Error::NoCredentials
    );
}

#[test]
fn test_ctap2_exclude_list_existing_credential_returns_error() {
    let crypto = CryptoEngine::new().unwrap();
    let storage = StorageEngine::new().unwrap();
    let mut authenticator = Ctap2Authenticator::new(ctap2::AAGUID, crypto, storage).unwrap();

    authenticator
        .make_credential(make_request(b"user123"))
        .unwrap();

    let cred_id = {
        let stored = authenticator.get_storage().list_credentials();
        stored[0].credential_id.clone()
    };

    let mut request = make_request(b"user123");
    request.exclude_list = vec![CredentialDescriptor {
        r#type: "public-key".to_string(),
        id: cred_id,
        transports: None,
    }];
    let result = authenticator.make_credential(request);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(
        *err.downcast_ref::<Ctap2Error>().unwrap(),
        Ctap2Error::CredentialExists
    );
}

#[test]
fn test_es256_make_credential_and_verify() {
    let crypto = CryptoEngine::new().unwrap();
    let storage = StorageEngine::new().unwrap();
    let mut authenticator = Ctap2Authenticator::new(ctap2::AAGUID, crypto, storage).unwrap();

    let response = authenticator
        .make_credential(make_request_es256(b"user123"))
        .unwrap();
    assert_eq!(response.fmt, "none");

    let (cred_id, public_key) = {
        let stored = authenticator.get_storage().list_credentials();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].algorithm, -7);
        (
            stored[0].credential_id.clone(),
            stored[0].public_key.clone(),
        )
    };

    // P-256 public key is 65 bytes: 0x04 || x(32) || y(32)
    assert_eq!(public_key.len(), 65);
    assert_eq!(public_key[0], 0x04);

    let assert_response = authenticator
        .get_assertion(make_assert_request(
            &authenticator,
            "example.com",
            cred_id.clone(),
            None,
        ))
        .unwrap();
    assert!(!assert_response.signature.is_empty());

    // Verify the signature
    let mut data_to_sign = Vec::new();
    data_to_sign.extend_from_slice(&assert_response.auth_data[..32]);
    data_to_sign.extend_from_slice(&assert_response.auth_data[32..37]);
    data_to_sign.extend_from_slice(&authenticator.get_crypto().sha256(b"client data hash"));
    authenticator
        .get_crypto()
        .verify_p256(&public_key, &data_to_sign, &assert_response.signature)
        .unwrap();
}

#[test]
fn test_file_storage_backend() {
    use std::path::PathBuf;
    use storage::{FileStorageBackend, StorageBackend};

    let test_path = PathBuf::from("test_storage_backend.json");
    let _ = std::fs::remove_file(&test_path);

    let mut backend = FileStorageBackend::new(test_path.clone()).unwrap();

    backend.write("key1", b"value1").unwrap();
    let result = backend.read("key1").unwrap();
    assert_eq!(result, Some(b"value1".to_vec()));

    backend.write("key2", b"value2").unwrap();
    let result2 = backend.read("key2").unwrap();
    assert_eq!(result2, Some(b"value2".to_vec()));

    backend.delete("key1").unwrap();
    let result3 = backend.read("key1").unwrap();
    assert_eq!(result3, None);

    let _ = std::fs::remove_file(&test_path);
}

#[test]
fn test_file_storage_backend_persistence() {
    use std::path::PathBuf;
    use storage::{FileStorageBackend, StorageBackend};

    let test_path = PathBuf::from("test_storage_persist.json");
    let _ = std::fs::remove_file(&test_path);

    let mut backend = FileStorageBackend::new(test_path.clone()).unwrap();
    backend
        .write("persistent_key", b"persistent_value")
        .unwrap();
    drop(backend);

    let backend2 = FileStorageBackend::new(test_path.clone()).unwrap();
    let result = backend2.read("persistent_key").unwrap();
    assert_eq!(result, Some(b"persistent_value".to_vec()));

    let _ = std::fs::remove_file(&test_path);
}

#[test]
fn test_flash_storage_backend_power_loss_recovery() {
    use storage::{FlashStorageBackend, SimulatedFlash, StorageBackend};

    let mut flash = SimulatedFlash::new(512, 2);
    let mut backend = FlashStorageBackend::new(flash).unwrap();
    backend.write("key", b"old").unwrap();
    flash = backend.into_device();
    flash.fail_after_program_bytes(3);
    let mut interrupted = FlashStorageBackend::new(flash).unwrap();
    assert!(interrupted.write("key", b"new").is_err());
    flash = interrupted.into_device();
    let recovered = FlashStorageBackend::new(flash).unwrap();
    assert_eq!(recovered.read("key").unwrap(), Some(b"old".to_vec()));
}

#[test]
fn test_storage_engine_with_backend() {
    use std::path::PathBuf;
    use storage::{FileStorageBackend, StorageBackend, StorageEngine};

    let test_path = PathBuf::from("test_engine_backend.json");
    let _ = std::fs::remove_file(&test_path);

    let backend = FileStorageBackend::new(test_path.clone()).unwrap();
    let mut engine = StorageEngine::with_backend(Box::new(backend));

    engine.store("test_key", b"test_value".to_vec()).unwrap();
    let result = engine.retrieve("test_key").unwrap();
    assert_eq!(result, b"test_value");

    let _ = std::fs::remove_file(&test_path);
}

#[test]
fn test_credential_pruning() {
    use storage::{Credential, StorageEngine};

    let crypto = CryptoEngine::new().unwrap();
    let mut storage = StorageEngine::new().unwrap();
    storage.set_max_credential_count(3);

    for i in 0u64..5 {
        let credential = Credential {
            credential_id: vec![i as u8; 4],
            public_key: vec![1; 32],
            private_key: vec![2; 32],
            sign_count: 0,
            rp_id_hash: vec![3; 32],
            user_handle: None,
            cred_blob: Vec::new(),
            created_at: i * 1000,
            algorithm: -8,
            rp_id: "example.com".to_string(),
            large_blob_key: None,
            user_name: None,
            user_display_name: None,
            cred_protect: None,
            cred_random_with_uv: None,
            cred_random_without_uv: None,
        };
        storage.store_credential(credential, &crypto).unwrap();
    }

    let credentials = storage.list_credentials();
    assert_eq!(credentials.len(), 3);
    assert_eq!(credentials[0].credential_id, vec![2; 4]);
    assert_eq!(credentials[1].credential_id, vec![3; 4]);
    assert_eq!(credentials[2].credential_id, vec![4; 4]);
}

#[test]
fn test_wear_leveling_counter() {
    use storage::{FileStorageBackend, StorageBackend};

    let test_path = PathBuf::from("test_wear_leveling.json");
    let _ = std::fs::remove_file(&test_path);

    let backend = FileStorageBackend::new(test_path.clone()).unwrap();
    let mut engine = StorageEngine::with_backend(Box::new(backend));

    for _ in 0..100 {
        engine.store("counter_test", b"value".to_vec()).unwrap();
    }

    let result = engine.retrieve("counter_test").unwrap();
    assert_eq!(result, b"value");

    let _ = std::fs::remove_file(&test_path);
}

#[test]
fn test_usb_hid_transport_stub() {
    use transport::{Transport, UsbHidTransport};

    let mut transport = UsbHidTransport::new();
    let result = transport.init();
    assert!(result.is_err());

    let result = transport.send(b"data");
    assert!(result.is_err());

    let result = transport.recv();
    assert!(result.is_err());

    let result = transport.close();
    assert!(result.is_ok());
}

#[test]
fn test_usb_ccid_transport_stub() {
    use transport::{Transport, UsbCcidTransport};

    let mut transport = UsbCcidTransport::new();
    let result = transport.init();
    assert!(result.is_err());

    let result = transport.send(b"data");
    assert!(result.is_err());

    let result = transport.recv();
    assert!(result.is_err());

    let result = transport.close();
    assert!(result.is_ok());
}

#[test]
fn test_transport_config_usb_hid() {
    use device_profile::{DeviceProfileBuilder, TransportConfig, TransportType};

    let profile = DeviceProfileBuilder::new()
        .transport_config(TransportConfig::usb_hid())
        .build();

    let config = profile.transport_config.unwrap();
    assert_eq!(config.transport_type, TransportType::UsbHid);
}

#[test]
fn test_transport_config_usb_ccid() {
    use device_profile::{DeviceProfileBuilder, TransportConfig, TransportType};

    let profile = DeviceProfileBuilder::new()
        .transport_config(TransportConfig::usb_ccid())
        .build();

    let config = profile.transport_config.unwrap();
    assert_eq!(config.transport_type, TransportType::UsbCcid);
}

#[test]
fn test_embedded_authenticator_with_transport() {
    use authenticator::EmbeddedAuthenticator;
    use device_profile::{DeviceProfileBuilder, TransportConfig};

    let profile = DeviceProfileBuilder::new()
        .transport_config(TransportConfig::usb_hid())
        .build();

    let authenticator = EmbeddedAuthenticator::new_with_profile(profile).unwrap();
    assert!(authenticator.transport().is_some());
}

#[test]
fn test_embedded_authenticator_without_transport() {
    use authenticator::EmbeddedAuthenticator;
    use device_profile::DeviceProfileBuilder;

    let profile = DeviceProfileBuilder::new().build();
    let authenticator = EmbeddedAuthenticator::new_with_profile(profile).unwrap();
    assert!(authenticator.transport().is_none());
}

#[cfg(test)]
mod embedded_authenticator_transport_tests {
    use authenticator::EmbeddedAuthenticator;
    use device_profile::{DeviceProfileBuilder, TransportConfig};
    use embedded_hal::digital::{ErrorType, OutputPin};
    use std::sync::{Arc, Mutex};
    use transport::embedded::rp2350::{Rp2350UsbHid, Rp2350UsbPeriph};
    use transport::embedded::{EmbeddedTransportError, UsbCcidDevice};
    use transport::{FramedCcidTransport, FramedUsbHidTransport, Transport, TransportError};

    struct TestPin;

    impl ErrorType for TestPin {
        type Error = core::convert::Infallible;
    }

    impl OutputPin for TestPin {
        fn set_low(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn set_high(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockCcidState {
        initialized: bool,
        init_calls: usize,
        sent_blocks: Vec<Vec<u8>>,
        recv_block: Vec<u8>,
    }

    struct MockCcid {
        state: Arc<Mutex<MockCcidState>>,
        recv_error: Option<EmbeddedTransportError>,
    }

    impl MockCcid {
        fn new(state: Arc<Mutex<MockCcidState>>, recv_block: Vec<u8>) -> Self {
            state.lock().unwrap().recv_block = recv_block;
            Self {
                state,
                recv_error: None,
            }
        }

        fn failing_recv(state: Arc<Mutex<MockCcidState>>) -> Self {
            Self {
                state,
                recv_error: Some(EmbeddedTransportError::Timeout),
            }
        }
    }

    impl UsbCcidDevice for MockCcid {
        fn init(&mut self) -> Result<(), EmbeddedTransportError> {
            let mut state = self.state.lock().unwrap();
            state.initialized = true;
            state.init_calls += 1;
            Ok(())
        }

        fn send_ccid_block(&mut self, buf: &[u8]) -> Result<(), EmbeddedTransportError> {
            let mut state = self.state.lock().unwrap();
            if !state.initialized {
                return Err(EmbeddedTransportError::NotInitialized);
            }
            state.sent_blocks.push(buf.to_vec());
            Ok(())
        }

        fn recv_ccid_block(&mut self, buf: &mut [u8]) -> Result<usize, EmbeddedTransportError> {
            if let Some(error) = &self.recv_error {
                return Err(error.clone());
            }

            let state = self.state.lock().unwrap();
            if !state.initialized {
                return Err(EmbeddedTransportError::NotInitialized);
            }
            let len = state.recv_block.len();
            buf[..len].copy_from_slice(&state.recv_block);
            Ok(len)
        }
    }

    #[derive(Default)]
    struct MockTransportState {
        initialized: bool,
        init_calls: usize,
        sent_frames: Vec<Vec<u8>>,
    }

    struct MockTransport {
        state: Arc<Mutex<MockTransportState>>,
        init_error: Option<&'static str>,
    }

    impl MockTransport {
        fn new(state: Arc<Mutex<MockTransportState>>) -> Self {
            Self {
                state,
                init_error: None,
            }
        }

        fn failing(state: Arc<Mutex<MockTransportState>>) -> Self {
            Self {
                state,
                init_error: Some("mock init failure"),
            }
        }
    }

    impl Transport for MockTransport {
        fn init(&mut self) -> Result<(), TransportError> {
            let mut state = self.state.lock().unwrap();
            state.init_calls += 1;
            if let Some(message) = self.init_error {
                return Err(TransportError::RecvError(message.to_string()));
            }
            state.initialized = true;
            Ok(())
        }

        fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
            let mut state = self.state.lock().unwrap();
            if !state.initialized {
                return Err(TransportError::NotInitialized);
            }
            state.sent_frames.push(data.to_vec());
            Ok(())
        }

        fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
            if !self.state.lock().unwrap().initialized {
                return Err(TransportError::NotInitialized);
            }
            Ok(Vec::new())
        }

        fn close(&mut self) -> Result<(), TransportError> {
            self.state.lock().unwrap().initialized = false;
            Ok(())
        }
    }

    fn usb_hid_profile() -> device_profile::DeviceProfile {
        DeviceProfileBuilder::new()
            .transport_config(TransportConfig::usb_hid())
            .build()
    }

    fn usb_ccid_profile() -> device_profile::DeviceProfile {
        DeviceProfileBuilder::new()
            .transport_config(TransportConfig::usb_ccid())
            .build()
    }

    #[test]
    fn injected_transport_is_composed_and_initialized_explicitly() {
        let state = Arc::new(Mutex::new(MockTransportState::default()));
        let mut authenticator = EmbeddedAuthenticator::new_with_profile_and_transport(
            usb_hid_profile(),
            Box::new(MockTransport::new(state.clone())),
        )
        .unwrap();

        assert!(authenticator.transport().is_some());
        assert_eq!(state.lock().unwrap().init_calls, 0);

        authenticator.transport_mut().unwrap().init().unwrap();
        authenticator
            .transport_mut()
            .unwrap()
            .send(b"injected frame")
            .unwrap();

        let state = state.lock().unwrap();
        assert!(state.initialized);
        assert_eq!(state.init_calls, 1);
        assert_eq!(state.sent_frames, vec![b"injected frame".to_vec()]);
    }

    #[test]
    fn injected_transport_init_error_is_propagated() {
        let state = Arc::new(Mutex::new(MockTransportState::default()));
        let mut authenticator = EmbeddedAuthenticator::new_with_profile_and_transport(
            usb_hid_profile(),
            Box::new(MockTransport::failing(state.clone())),
        )
        .unwrap();

        let error = authenticator.transport_mut().unwrap().init().unwrap_err();
        assert!(matches!(
            error,
            TransportError::RecvError(message) if message == "mock init failure"
        ));
        assert_eq!(state.lock().unwrap().init_calls, 1);
    }

    #[test]
    fn injected_framed_usb_hid_transport_composes_on_host() {
        let device = Rp2350UsbHid::new(Rp2350UsbPeriph::new(), TestPin);
        let transport = FramedUsbHidTransport::new(device);
        let mut authenticator = EmbeddedAuthenticator::new_with_profile_and_transport(
            usb_hid_profile(),
            Box::new(transport),
        )
        .unwrap();

        authenticator.transport_mut().unwrap().init().unwrap();
        authenticator
            .transport_mut()
            .unwrap()
            .send(&[0xA5; 120])
            .unwrap();
    }

    #[test]
    fn injected_framed_ccid_transport_round_trips_on_host() {
        let state = Arc::new(Mutex::new(MockCcidState::default()));
        let raw_apdu = vec![0x00, 0x10, 0x00, 0x00, 0x03, 1, 2, 3];
        let transport = FramedCcidTransport::new(MockCcid::new(state.clone(), raw_apdu));
        let mut authenticator = EmbeddedAuthenticator::new_with_profile_and_transport(
            usb_ccid_profile(),
            Box::new(transport),
        )
        .unwrap();

        let before_init = authenticator
            .transport_mut()
            .unwrap()
            .send(b"before init")
            .unwrap_err();
        assert!(matches!(before_init, TransportError::NotInitialized));
        assert_eq!(state.lock().unwrap().init_calls, 0);

        let transport = authenticator.transport_mut().unwrap();
        transport.init().unwrap();
        transport.send(&[4, 5, 6]).unwrap();
        assert_eq!(transport.recv().unwrap(), vec![1, 2, 3]);

        let state = state.lock().unwrap();
        assert!(state.initialized);
        assert_eq!(state.init_calls, 1);
        assert_eq!(state.sent_blocks, vec![vec![4, 5, 6, 0x90, 0x00]]);
    }

    #[test]
    fn injected_framed_ccid_transport_propagates_host_errors() {
        let state = Arc::new(Mutex::new(MockCcidState::default()));
        let transport = FramedCcidTransport::new(MockCcid::failing_recv(state.clone()));
        let mut authenticator = EmbeddedAuthenticator::new_with_profile_and_transport(
            usb_ccid_profile(),
            Box::new(transport),
        )
        .unwrap();

        authenticator.transport_mut().unwrap().init().unwrap();
        let error = authenticator.transport_mut().unwrap().recv().unwrap_err();
        assert!(matches!(
            error,
            TransportError::RecvError(message) if message == "timeout"
        ));
        assert_eq!(state.lock().unwrap().init_calls, 1);
    }
}

#[test]
fn test_rp2350_security_features_enabled() {
    use board_generic::profiles::RP2350;
    use board_generic::SecurityFeatures;

    let expected = SecurityFeatures::rp2350();
    assert!(expected.secure_boot);
    assert!(expected.trust_zone);
    assert!(expected.hardware_rng);
    assert!(expected.sha256_accelerator);
    assert!(expected.debug_disable);
    assert!(expected.otp_memory);
    assert!(expected.unique_id);
    assert!(!expected.tamper_detection);

    assert_eq!(RP2350.security, expected);
    assert!(RP2350.security.has_any());
}

#[test]
fn test_security_features_none_has_no_features() {
    use board_generic::SecurityFeatures;

    let none = SecurityFeatures::none();
    assert!(!none.secure_boot);
    assert!(!none.trust_zone);
    assert!(!none.hardware_rng);
    assert!(!none.sha256_accelerator);
    assert!(!none.debug_disable);
    assert!(!none.otp_memory);
    assert!(!none.unique_id);
    assert!(!none.tamper_detection);
    assert!(!none.has_any());
}

#[test]
fn test_board_definition_security_builder_methods() {
    use board_generic::BoardDefinition;

    let board = BoardDefinition::new("test", [0u8; 16])
        .secure_boot(true)
        .trust_zone(true)
        .hardware_rng(true)
        .sha256_accelerator(true)
        .debug_disable(true)
        .otp_memory(true)
        .unique_id(true)
        .tamper_detection(true);

    assert!(board.security.secure_boot);
    assert!(board.security.trust_zone);
    assert!(board.security.hardware_rng);
    assert!(board.security.sha256_accelerator);
    assert!(board.security.debug_disable);
    assert!(board.security.otp_memory);
    assert!(board.security.unique_id);
    assert!(board.security.tamper_detection);
    assert!(board.security.has_any());
}

#[test]
fn test_device_profile_inherits_security_from_board() {
    use board_generic::profiles::RP2350;
    use device_profile::DeviceProfileBuilder;

    let profile = DeviceProfileBuilder::from_board(&RP2350).build();

    assert!(profile.security.secure_boot);
    assert!(profile.security.trust_zone);
    assert!(profile.security.hardware_rng);
    assert!(profile.security.sha256_accelerator);
    assert!(profile.security.debug_disable);
    assert!(profile.security.otp_memory);
    assert!(profile.security.unique_id);
    assert!(profile.security.has_any());
}

#[test]
fn test_device_profile_default_has_no_security() {
    use device_profile::DeviceProfileBuilder;

    let profile = DeviceProfileBuilder::new().build();

    assert!(!profile.security.secure_boot);
    assert!(!profile.security.trust_zone);
    assert!(!profile.security.hardware_rng);
    assert!(!profile.security.sha256_accelerator);
    assert!(!profile.security.debug_disable);
    assert!(!profile.security.otp_memory);
    assert!(!profile.security.unique_id);
    assert!(!profile.security.tamper_detection);
    assert!(!profile.security.has_any());
}

#[test]
fn test_nrf52840_no_security_features_by_default() {
    use board_generic::profiles::NRF52840;

    assert!(!NRF52840.security.has_any());
}

#[test]
fn test_esp32c3_no_security_features_by_default() {
    use board_generic::profiles::ESP32C3;

    assert!(!ESP32C3.security.has_any());
}

#[test]
fn test_security_features_partial_enable() {
    use board_generic::BoardDefinition;

    let board = BoardDefinition::new("partial", [0u8; 16])
        .secure_boot(true)
        .hardware_rng(true);

    assert!(board.security.secure_boot);
    assert!(!board.security.trust_zone);
    assert!(board.security.hardware_rng);
    assert!(!board.security.sha256_accelerator);
    assert!(board.security.has_any());
}

#[test]
fn test_get_info_rp2350_includes_security_features() {
    use authenticator::EmbeddedAuthenticator;
    use board_generic::profiles::RP2350;

    let authenticator = EmbeddedAuthenticator::new_with_board(&RP2350).unwrap();
    let info = authenticator.get_info().unwrap();

    let security = info.security.expect("security should be Some for RP2350");
    assert!(security.secure_boot);
    assert!(security.trust_zone);
    assert!(security.hardware_rng);
    assert!(security.sha256_accelerator);
    assert!(security.debug_disable);
    assert!(security.otp_memory);
    assert!(security.unique_id);
    assert!(!security.tamper_detection);
}

#[test]
fn test_get_info_nrf52840_no_security_features() {
    use authenticator::EmbeddedAuthenticator;
    use board_generic::profiles::NRF52840;

    let authenticator = EmbeddedAuthenticator::new_with_board(&NRF52840).unwrap();
    let info = authenticator.get_info().unwrap();

    assert!(info.security.is_none());
}

#[test]
fn test_get_info_default_has_no_security_features() {
    use authenticator::EmbeddedAuthenticator;

    let authenticator = EmbeddedAuthenticator::new().unwrap();
    let info = authenticator.get_info().unwrap();

    assert!(info.security.is_none());
}

#[test]
fn test_ctaphid_framing_roundtrip_multi_packet() {
    use transport::ctaphid::{CtaphidAssembler, CtaphidCommand, CtaphidFragmenter};

    let payload = (0..500).map(|i| (i % 255) as u8).collect::<Vec<_>>();
    let cid = 0x12345678;
    let packets = CtaphidFragmenter::fragment(cid, CtaphidCommand::Cbor, &payload).unwrap();
    assert_eq!(packets.len(), 9); // 57 + 8 * 59 = 529 max capacity

    let mut assembler = CtaphidAssembler::new();
    let mut message = None;
    for (i, pkt) in packets.iter().enumerate() {
        let res = assembler.process_packet(pkt).unwrap();
        if i + 1 == packets.len() {
            message = res;
        } else {
            assert!(res.is_none());
        }
    }

    let msg = message.expect("complete message should be assembled");
    assert_eq!(msg.cid, cid);
    assert_eq!(msg.cmd, CtaphidCommand::Cbor);
    assert_eq!(msg.payload, payload);
}

#[test]
fn test_ctaphid_channel_allocation_and_management() {
    use transport::ctaphid::{ctaphid_capabilities, ChannelManager, CTAPHID_BROADCAST_CID};

    let mut mgr = ChannelManager::new();
    let nonce: [u8; 8] = rand::random();
    let resp = mgr.build_init_response(
        &nonce,
        2,
        1,
        0,
        ctaphid_capabilities::CAPABILITY_CBOR | ctaphid_capabilities::CAPABILITY_WINK,
    );

    assert_eq!(resp.len(), 17);
    assert_eq!(&resp[0..8], &nonce);
    let cid = u32::from_be_bytes([resp[8], resp[9], resp[10], resp[11]]);
    assert!(mgr.is_valid_cid(cid));
    assert!(mgr.is_valid_cid(CTAPHID_BROADCAST_CID));

    mgr.release_cid(cid);
    assert!(!mgr.is_valid_cid(cid));
}

#[test]
fn test_ctaphid_invalid_sequence_rejection() {
    use transport::ctaphid::{
        CtaphidAssembler, CtaphidCommand, CtaphidErrorCode, CtaphidFragmenter,
    };

    let payload = vec![0xEE; 150];
    let packets = CtaphidFragmenter::fragment(0x99887766, CtaphidCommand::Msg, &payload).unwrap();

    let mut assembler = CtaphidAssembler::new();
    assert!(assembler.process_packet(&packets[0]).unwrap().is_none());

    // Skip packet 1 and send packet 2 directly
    let err = assembler.process_packet(&packets[2]).unwrap_err();
    assert_eq!(err.0, 0x99887766);
    assert_eq!(err.1, CtaphidErrorCode::InvalidSeq);
}

#[test]
fn test_nrf52840_and_stm32l4_hardware_transports() {
    use transport::embedded::nrf52840::{Nrf52840Nfc, Nrf52840UsbHid};
    use transport::embedded::stm32l4::Stm32l4UsbHid;
    use transport::embedded::{NfcDevice, UsbHidDevice};

    struct TestPin;
    impl embedded_hal::digital::ErrorType for TestPin {
        type Error = core::convert::Infallible;
    }
    impl embedded_hal::digital::OutputPin for TestPin {
        fn set_low(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
        fn set_high(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    let mut nrf_usb = Nrf52840UsbHid::new(TestPin);
    assert!(nrf_usb.init().is_ok());
    assert!(nrf_usb.send_packet(b"hello").is_ok());

    let mut nrf_nfc = Nrf52840Nfc::new();
    assert!(nrf_nfc.init().is_ok());
    assert!(!nrf_nfc.is_field_detected());

    let mut stm_usb = Stm32l4UsbHid::new(TestPin);
    assert!(stm_usb.init().is_ok());
    assert!(stm_usb.send_packet(b"world").is_ok());
}

/// Monta o roteador multi-protocolo (Management + OATH + PIV + OpenPGP)
/// sobre storage em memória, como o simulador host faz.
fn multiprotocol_router() -> transport::iso7816::CardRouter<'static> {
    use authenticator::{
        register_multiprotocol_applets, ManagementApplet, OathApplet, OpenPgpApplet, PivApplet,
    };
    use std::cell::RefCell;

    const MASTER_KEY: [u8; 32] = [77u8; 32];
    let storage: &'static RefCell<StorageEngine> =
        Box::leak(Box::new(RefCell::new(StorageEngine::new().unwrap())));
    let engine = || CryptoEngine::from_key(MASTER_KEY);
    let mgmt = Box::leak(Box::new(ManagementApplet::new(storage, engine()).unwrap()));
    let oath = Box::leak(Box::new(OathApplet::new(storage, engine()).unwrap()));
    let piv = Box::leak(Box::new(PivApplet::new(storage, engine()).unwrap()));
    let openpgp = Box::leak(Box::new(OpenPgpApplet::new(storage, engine()).unwrap()));
    let mut router = transport::iso7816::CardRouter::new();
    register_multiprotocol_applets(&mut router, mgmt, oath, piv, openpgp);
    router
}

fn select_frame(aid: &[u8]) -> Vec<u8> {
    let mut v = vec![0x00, 0xA4, 0x04, 0x00, aid.len() as u8];
    v.extend_from_slice(aid);
    v
}

#[test]
fn test_multiprotocol_router_piv_verify_generate_auth() {
    use authenticator::AID_PIV;

    let mut router = multiprotocol_router();
    assert_eq!(
        router.process(&select_frame(AID_PIV)).sw,
        Some(transport::iso7816::SW_NO_ERROR)
    );

    // Slot 9A sem VERIFY: AUTH nega com 6982.
    let auth = vec![0x00, 0x87, 0x00, 0x9A, 0x01, 0xAA];
    assert_eq!(
        router.process(&auth).sw,
        Some(transport::iso7816::SW_SECURITY_STATUS)
    );

    // VERIFY com o PIN padrão, GENERATE Ed25519 e AUTH assinam.
    let mut verify = vec![0x00, 0x20, 0x00, 0x80, 0x08];
    verify.extend_from_slice(b"123456\xFF\xFF");
    assert_eq!(
        router.process(&verify).sw,
        Some(transport::iso7816::SW_NO_ERROR)
    );
    let generate = vec![
        0x00, 0x47, 0x00, 0x9A, 0x05, 0xAC, 0x03, 0x80, 0x01, 0xE0, 0x00,
    ];
    let resp = router.process(&generate);
    assert_eq!(resp.sw, Some(transport::iso7816::SW_NO_ERROR));
    assert_eq!(&resp.data[..2], &[0x7F, 0x49]);
    let mut auth = vec![0x00, 0x87, 0x00, 0x9A, 0x20];
    auth.extend_from_slice(&[0x11u8; 32]);
    auth.push(0x00);
    let resp = router.process(&auth);
    assert_eq!(resp.sw, Some(transport::iso7816::SW_NO_ERROR));
    assert_eq!(resp.data.len(), 64);
}

#[test]
fn test_multiprotocol_router_openpgp_verify_generate_sign() {
    use authenticator::AID_OPENPGP;

    let mut router = multiprotocol_router();
    let resp = router.process(&select_frame(AID_OPENPGP));
    assert_eq!(resp.sw, Some(transport::iso7816::SW_NO_ERROR));
    assert_eq!(resp.data.first(), Some(&0x6F));

    // PSO SIGN sem VERIFY: 6982.
    let sign = vec![0x00, 0x2A, 0x9E, 0x9A, 0x01, 0xAA];
    assert_eq!(
        router.process(&sign).sw,
        Some(transport::iso7816::SW_SECURITY_STATUS)
    );

    // VERIFY PW1, GENERATE SIG e PSO SIGN assinam.
    let mut verify = vec![0x00, 0x20, 0x00, 0x81, 0x06];
    verify.extend_from_slice(b"123456");
    assert_eq!(
        router.process(&verify).sw,
        Some(transport::iso7816::SW_NO_ERROR)
    );
    let resp = router.process(&[0x00, 0x47, 0x00, 0x00, 0x01, 0xE0, 0x00]);
    assert_eq!(resp.sw, Some(transport::iso7816::SW_NO_ERROR));
    assert_eq!(&resp.data[..2], &[0x7F, 0x49]);
    let mut sign = vec![0x00, 0x2A, 0x9E, 0x9A, 0x05];
    sign.extend_from_slice(b"hello");
    sign.push(0x00);
    let resp = router.process(&sign);
    assert_eq!(resp.sw, Some(transport::iso7816::SW_NO_ERROR));
    assert_eq!(resp.data.len(), 64);
}
