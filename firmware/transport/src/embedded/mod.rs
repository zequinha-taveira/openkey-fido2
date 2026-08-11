//! Trait contracts for embedded transport implementations.
//!
//! This module defines the hardware abstraction traits that concrete boards
//! implement to provide real transport capabilities. The design separates:
//!
//! - [`UsbHidDevice`]: USB-HID endpoint operations (interrupt transfers)
//! - [`UsbCcidDevice`]: CCID bulk transfers (smartcard)
//! - [`NfcDevice`]: NFC ISO 14443 passive target
//! - [`BleGattDevice`]: BLE GATT server notifications
//!
//! Each trait is implemented by the board's HAL. The transport crate
//! provides adapters that implement [`super::Transport`] on top of these.

#[cfg(feature = "embedded")]
pub mod rp2350;

#[cfg(feature = "embedded")]
pub mod usb_hid;

#[cfg(feature = "embedded")]
pub use usb_hid::UsbHidDevice;

/// Errors produced by embedded transport operations.
///
/// This is a `no_std`-compatible error type that mirrors [`super::TransportError`]
/// but without requiring `std::error::Error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbeddedTransportError {
    /// Operation called before `init()`.
    NotInitialized,
    /// Send failed — contains a descriptive code.
    SendFailed,
    /// Receive failed — contains a descriptive code.
    RecvFailed,
    /// Transport closed.
    Closed,
    /// Hardware buffer too small for frame.
    BufferTooSmall,
    /// CRC or framing error.
    FramingError,
    /// User presence timeout.
    Timeout,
}

impl core::fmt::Display for EmbeddedTransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotInitialized => write!(f, "not initialized"),
            Self::SendFailed => write!(f, "send failed"),
            Self::RecvFailed => write!(f, "receive failed"),
            Self::Closed => write!(f, "transport closed"),
            Self::BufferTooSmall => write!(f, "buffer too small"),
            Self::FramingError => write!(f, "framing error"),
            Self::Timeout => write!(f, "timeout"),
        }
    }
}

impl From<EmbeddedTransportError> for super::TransportError {
    fn from(e: EmbeddedTransportError) -> Self {
        match e {
            EmbeddedTransportError::NotInitialized => super::TransportError::NotInitialized,
            EmbeddedTransportError::SendFailed => {
                super::TransportError::SendError("embedded".to_string())
            }
            EmbeddedTransportError::RecvFailed => {
                super::TransportError::RecvError("embedded".to_string())
            }
            EmbeddedTransportError::Closed => super::TransportError::Closed,
            EmbeddedTransportError::BufferTooSmall => {
                super::TransportError::SendError("buffer too small".to_string())
            }
            EmbeddedTransportError::FramingError => {
                super::TransportError::RecvError("framing".to_string())
            }
            EmbeddedTransportError::Timeout => {
                super::TransportError::RecvError("timeout".to_string())
            }
        }
    }
}
