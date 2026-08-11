"""Virtual board para o simulador FIDO2 (emulação de board/HAL em Python)."""

from .board import CcidBoard, VirtualBoard
from .ccid import CcidTransport, build_response, fragment, unwrap_apdu, wrap_apdu
from .gpio import GpioController, GpioPin
from .i2c import I2CBus, I2CDevice
from .spi import SPIBus
from .profiles import ALL, GENERIC, BoardProfile, NRF52840, RP2350, STM32L4, ESP32C3, SecurityFeatures
from .cbor import CborError, decode, encode

__all__ = [
    "ALL",
    "BoardProfile",
    "CborError",
    "CcidBoard",
    "CcidTransport",
    "ESP32C3",
    "GENERIC",
    "GpioController",
    "GpioPin",
    "I2CBus",
    "I2CDevice",
    "NRF52840",
    "RP2350",
    "SPIBus",
    "STM32L4",
    "SecurityFeatures",
    "VirtualBoard",
    "build_response",
    "decode",
    "encode",
    "fragment",
    "unwrap_apdu",
    "wrap_apdu",
]
