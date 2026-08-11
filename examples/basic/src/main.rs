use authenticator::EmbeddedAuthenticator;
use board_generic::BoardDefinition;
use log::info;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    info!("FIDO2 Embedded Authenticator - Basic Example");

    let config = BoardDefinition::new(
        "generic-embedded",
        [
            0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22,
            0x33, 0x44,
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

    info!("Authenticator ready");
    info!("Capabilities: {:?}", authenticator.capabilities());
    info!("{:?}", authenticator);

    Ok(())
}
