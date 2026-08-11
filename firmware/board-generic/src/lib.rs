//! Camada de abstração de hardware (HAL) e perfis de board.
//!
//! [`BoardDefinition`] descreve pinagem, transportes e features de segurança
//! de forma `const`, permitindo que perfis sejam avaliados em tempo de
//! compilação e não ocupem RAM no target embarcado.

/// Definição de board, HAL e traits de periféricos.
pub mod board_generic;
/// Perfis de board pré-definidos (NRF52840, STM32L4, ESP32C3, RP2350, GENERIC).
pub mod profiles;

pub use board_generic::{
    BoardDefinition, BoardHAL, BoardTrait, GpioPin, I2cBus, SecurityFeatures, TRANSPORT_BLE,
    TRANSPORT_NFC, TRANSPORT_USB_CCID, TRANSPORT_USB_HID,
};
pub use profiles::{rp2350_with_pins, Rp2350Pins, ESP32C3, GENERIC, NRF52840, RP2350, STM32L4};
