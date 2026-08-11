"""Perfis de boards para o virtual board, espelhando `board-generic/src/profiles.rs`.

Valores (name, aaguid, transports, secure storage, crypto accelerator e pinos)
são mantidos em paralelo com os perfis Rust de `firmware/board-generic`:
NRF52840, STM32L4, ESP32C3, RP2350 e GENERIC.
"""

from dataclasses import dataclass, field

TRANSPORT_USB_CCID = 0x01
TRANSPORT_USB_HID = 0x02
TRANSPORT_NFC = 0x04
TRANSPORT_BLE = 0x08


@dataclass(frozen=True)
class SecurityFeatures:
    secure_boot: bool = False
    trust_zone: bool = False
    hardware_rng: bool = False
    sha256_accelerator: bool = False
    debug_disable: bool = False
    otp_memory: bool = False
    unique_id: bool = False
    tamper_detection: bool = False


@dataclass(frozen=True)
class BoardProfile:
    name: str
    aaguid: bytes
    transports: int
    has_secure_storage: bool
    has_crypto_accelerator: bool
    security: SecurityFeatures = None
    i2c_sda_pin: int = 0
    i2c_scl_pin: int = 0
    spi_mosi_pin: int = 0
    spi_miso_pin: int = 0
    spi_clk_pin: int = 0
    cs_pin: int = 0
    reset_pin: int = 0
    irq_pin: int = 0
    led_pin: int = 0
    button_pin: int = 0

    def has_transport(self, mask):
        return bool(self.transports & mask)


NRF52840 = BoardProfile(
    name="nrf52840-fido",
    aaguid=bytes([0x4E, 0x52, 0x46, 0x35, 0x32, 0x38, 0x34, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]),
    transports=TRANSPORT_USB_HID | TRANSPORT_NFC | TRANSPORT_BLE,
    has_secure_storage=True,
    has_crypto_accelerator=True,
    i2c_sda_pin=4, i2c_scl_pin=5,
    spi_mosi_pin=6, spi_miso_pin=7, spi_clk_pin=8, cs_pin=9,
    reset_pin=10, irq_pin=11, led_pin=12, button_pin=13,
)

STM32L4 = BoardProfile(
    name="stm32l4-fido",
    aaguid=bytes([0x53, 0x54, 0x4D, 0x33, 0x32, 0x4C, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]),
    transports=TRANSPORT_USB_HID | TRANSPORT_USB_CCID,
    has_secure_storage=True,
    has_crypto_accelerator=True,
    led_pin=0, button_pin=1,
    i2c_sda_pin=8, i2c_scl_pin=9,
    spi_mosi_pin=10, spi_miso_pin=11, spi_clk_pin=12, cs_pin=13,
    reset_pin=14, irq_pin=15,
)

ESP32C3 = BoardProfile(
    name="esp32c3-fido",
    aaguid=bytes([0x45, 0x53, 0x50, 0x33, 0x32, 0x43, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03]),
    transports=TRANSPORT_USB_HID | TRANSPORT_BLE,
    has_secure_storage=False,
    has_crypto_accelerator=True,
    i2c_sda_pin=4, i2c_scl_pin=5,
    spi_mosi_pin=6, spi_miso_pin=7, spi_clk_pin=8, cs_pin=9,
    reset_pin=10, irq_pin=11, led_pin=12, button_pin=13,
)

RP2350 = BoardProfile(
    name="rp2350-fido",
    aaguid=bytes([0x52, 0x50, 0x32, 0x33, 0x35, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05]),
    transports=TRANSPORT_USB_HID | TRANSPORT_USB_CCID,
    has_secure_storage=True,
    has_crypto_accelerator=True,
    security=SecurityFeatures(
        secure_boot=True,
        trust_zone=True,
        hardware_rng=True,
        sha256_accelerator=True,
        debug_disable=True,
        otp_memory=True,
        unique_id=True,
        tamper_detection=False,
    ),
    i2c_sda_pin=4, i2c_scl_pin=5,
    spi_mosi_pin=6, spi_miso_pin=7, spi_clk_pin=8, cs_pin=9,
    reset_pin=10, irq_pin=11, led_pin=25, button_pin=13,
)

GENERIC = BoardProfile(
    name="generic-fido",
    aaguid=bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]),
    transports=TRANSPORT_USB_CCID,
    has_secure_storage=False,
    has_crypto_accelerator=False,
    i2c_sda_pin=0, i2c_scl_pin=1,
    spi_mosi_pin=2, spi_miso_pin=3, spi_clk_pin=4, cs_pin=5,
    reset_pin=6, irq_pin=7, led_pin=8, button_pin=9,
)

ALL = [NRF52840, STM32L4, ESP32C3, RP2350, GENERIC]
