use authenticator::EmbeddedAuthenticator;
use board_generic::BoardDefinition;
use log::info;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    info!("FIDO2 CTAP2 Example");
    info!("This example demonstrates MakeCredential, GetAssertion, and Reset.");

    let config = BoardDefinition::new(
        "generic-embedded",
        [
            0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22,
            0x33, 0x44,
        ],
    )
    .usb_hid()
    .secure_storage(true);

    let mut authenticator = EmbeddedAuthenticator::new_with_board(&config)?;

    info!("Authenticator ready");

    // 1. Get capabilities via GetInfo
    let info = authenticator.get_info()?;
    info!("Firmware version: {}", info.firmware_version);

    // 2. Make a credential
    let req = ctap2::MakeCredentialRequest {
        client_data_hash: [0u8; 32].to_vec(),
        rp: ctap2::RelyingParty {
            id: "example.com".to_string(),
            name: None,
            icon: None,
        },
        user: ctap2::User {
            id: b"user123".to_vec(),
            name: None,
            display_name: None,
            icon_url: None,
        },
        pub_key_cred_params: vec![ctap2::PublicKeyCredParams {
            r#type: "public-key".to_string(),
            algorithms: -8,
        }],
        exclude_list: vec![],
        extensions: None,
        options: ctap2::MakeCredentialOptions {
            rk: false,
            uv: true,
            up: true,
            extended: false,
        },
        pin_protocol: None,
        enterprise_protections: None,
    };

    info!("Making credential...");
    match authenticator.make_credential(req) {
        Ok(_) => info!("Credential stored successfully"),
        Err(e) => info!("MakeCredential error: {}", e),
    }

    // 3. Get assertion
    info!("Getting assertion...");
    let req = ctap2::GetAssertionRequest {
        rp_id: "example.com".to_string(),
        credentials: vec![],
        allow_list: None,
        client_data_hash: [0u8; 32].to_vec(),
        extensions: None,
        options: ctap2::GetAssertionOptions { up: true, uv: true },
        pin_protocol: None,
        uv: None,
    };

    let req_bytes = ctap2::encode_cbor(&req)?;
    let resp = authenticator.process_command(0x02, req_bytes)?;
    info!("GetAssertion response: {:?}", resp);

    // 4. Reset
    info!("Resetting authenticator...");
    let resp = authenticator.process_command(0x07, vec![])?;
    info!("Reset response: {:?}", resp);

    info!("Example complete.");
    Ok(())
}