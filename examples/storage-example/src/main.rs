use authenticator::EmbeddedAuthenticator;
use board_generic::BoardDefinition;
use log::info;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    info!("FIDO2 Storage Example");
    info!("This example demonstrates credential storage and retrieval.");

    let config = BoardDefinition::new(
        "generic-embedded",
        [
            0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22,
            0x33, 0x44,
        ],
    )
    .usb_hid()
    .secure_storage(true);

    let authenticator = EmbeddedAuthenticator::new_with_board(&config)?;

    info!("Authenticator ready");

    let credentials = authenticator
        .get_webauthn_authenticator()
        .get_ctap()
        .get_storage()
        .list_credentials();
    info!("Current credentials count: {}", credentials.len());

    info!("Example complete.");
    Ok(())
}