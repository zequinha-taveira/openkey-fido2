//! Pre-defined board profiles built on [`BoardDefinition`].
//!
//! Each profile is a `const` value describing a target board's identity
//! (name and AAGUID), the physical transports it exposes, the hardware
//! features it provides (secure storage, crypto accelerator) and its logical
//! HAL pin assignments. Profiles can be passed directly to
//! `DeviceProfileBuilder::from_board` or `EmbeddedAuthenticator::new_with_board`.
//!
//! Available profiles: `NRF52840`, `STM32L4`, `ESP32C3`, `RP2350` and `GENERIC`.

use crate::board_generic::{BoardDefinition, SecurityFeatures};

/// nRF52840-based authenticator with USB-HID, NFC and BLE transports.
pub const NRF52840: BoardDefinition = BoardDefinition::new(
    "nrf52840-fido",
    [
        0x4e, 0x52, 0x46, 0x35, 0x32, 0x38, 0x34, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ],
)
.usb_hid()
.nfc()
.ble()
.secure_storage(true)
.crypto_accelerator(true)
.i2c_sda(4)
.i2c_scl(5)
.spi_mosi(6)
.spi_miso(7)
.spi_clk(8)
.cs(9)
.reset(10)
.irq(11)
.led(12)
.button(13);

/// STM32L4-based authenticator with USB-HID and USB-CCID transports.
pub const STM32L4: BoardDefinition = BoardDefinition::new(
    "stm32l4-fido",
    [
        0x53, 0x54, 0x4d, 0x33, 0x32, 0x4c, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ],
)
.usb_hid()
.usb_ccid()
.secure_storage(true)
.crypto_accelerator(true)
.led(0)
.button(1)
.i2c_sda(8)
.i2c_scl(9)
.spi_mosi(10)
.spi_miso(11)
.spi_clk(12)
.cs(13)
.reset(14)
.irq(15);

/// ESP32-C3-based authenticator with USB-HID and BLE transports.
pub const ESP32C3: BoardDefinition = BoardDefinition::new(
    "esp32c3-fido",
    [
        0x45, 0x53, 0x50, 0x33, 0x32, 0x43, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03,
    ],
)
.usb_hid()
.ble()
.crypto_accelerator(true)
.secure_storage(false)
.i2c_sda(4)
.i2c_scl(5)
.spi_mosi(6)
.spi_miso(7)
.spi_clk(8)
.cs(9)
.reset(10)
.irq(11)
.led(12)
.button(13);

/// Raspberry Pi RP2350-based authenticator with USB-HID and USB-CCID transports.
///
/// The RP2350 provides hardware security features including ARM TrustZone
/// (Cortex-M33), secure boot with RSA signature verification, hardware TRNG,
/// SHA-256 accelerator, OTP memory for key storage, unique chip ID, and
/// debug disable via OTP.
///
/// Pin assignments reflect a typical dev board. Use [`rp2350_with_pins`] to
/// override for boards with different wiring.
pub const RP2350: BoardDefinition = rp2350_with_pins(Rp2350Pins {
    i2c_sda: 4,
    i2c_scl: 5,
    spi_mosi: 6,
    spi_miso: 7,
    spi_clk: 8,
    cs: 9,
    reset: 10,
    irq: 11,
    led: 25,
    button: 13,
});

/// RP2350 board with custom pin assignments.
///
/// Use this when the target board uses different GPIOs than the defaults.
///
/// ```
/// use board_generic::profiles::{rp2350_with_pins, Rp2350Pins};
///
/// let board = rp2350_with_pins(Rp2350Pins {
///     i2c_sda: 2,
///     i2c_scl: 3,
///     spi_mosi: 16,
///     spi_miso: 19,
///     spi_clk: 18,
///     cs: 17,
///     reset: 20,
///     irq: 21,
///     led: 10,
///     button: 15,
/// });
/// ```
#[inline]
pub const fn rp2350_with_pins(pins: Rp2350Pins) -> BoardDefinition {
    BoardDefinition::new(
        "rp2350-fido",
        [
            0x52, 0x50, 0x32, 0x33, 0x35, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x05,
        ],
    )
    .usb_hid()
    .usb_ccid()
    .secure_storage(true)
    .crypto_accelerator(true)
    .security_features(SecurityFeatures::rp2350())
    .i2c_sda(pins.i2c_sda)
    .i2c_scl(pins.i2c_scl)
    .spi_mosi(pins.spi_mosi)
    .spi_miso(pins.spi_miso)
    .spi_clk(pins.spi_clk)
    .cs(pins.cs)
    .reset(pins.reset)
    .irq(pins.irq)
    .led(pins.led)
    .button(pins.button)
}

/// Pin assignments for [`rp2350_with_pins`].
pub struct Rp2350Pins {
    /// GPIO do sinal I2C SDA.
    pub i2c_sda: u8,
    /// GPIO do sinal I2C SCL.
    pub i2c_scl: u8,
    /// GPIO do sinal SPI MOSI.
    pub spi_mosi: u8,
    /// GPIO do sinal SPI MISO.
    pub spi_miso: u8,
    /// GPIO do clock SPI.
    pub spi_clk: u8,
    /// GPIO do chip select.
    pub cs: u8,
    /// GPIO de reset do periférico.
    pub reset: u8,
    /// GPIO de interrupção.
    pub irq: u8,
    /// GPIO do LED de status (user presence).
    pub led: u8,
    /// GPIO do botão de user presence.
    pub button: u8,
}

/// Generic board profile with USB-CCID transport only.
pub const GENERIC: BoardDefinition = BoardDefinition::new(
    "generic-fido",
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff,
    ],
)
.usb_ccid()
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
