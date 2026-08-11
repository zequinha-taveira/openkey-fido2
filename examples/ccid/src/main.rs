use authenticator::EmbeddedAuthenticator;
use board_generic::BoardDefinition;
use log::info;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    info!("FIDO2 Embedded Authenticator - CCID Example");

    let config = BoardDefinition::new(
        "ccid-embedded",
        [
            0x01, 0x00, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x00, 0x11, 0x22, 0x33,
            0x44, 0x55,
        ],
    )
    .usb_ccid()
    .secure_storage(true)
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

    let authenticator = EmbeddedAuthenticator::new_with_board(&config)?;
    let _board = board_generic::BoardHAL::new(config);

    info!("CCID Authenticator ready");
    info!("Capabilities: {:?}", authenticator.capabilities());
    info!("{:?}", authenticator);

    Ok(())
}
