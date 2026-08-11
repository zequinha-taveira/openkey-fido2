//! Camada de transporte do autenticador FIDO2.
//!
//! Define a trait [`Transport`] e stubs para os transportes físicos
//! previstos: USB-HID (CTAPHID), USB-CCID, NFC (ISO 14443) e BLE GATT.
//!
//! When the `embedded` feature is enabled, the [`embedded`] module provides
//! `no_std` trait contracts and reference implementations for targets that
//! implement [`embedded-hal`].

#[cfg(feature = "embedded")]
pub mod embedded;

pub mod ble_gatt;
pub mod nfc;
pub mod transport;
pub mod usb_ccid;
pub mod usb_hid;

pub use ble_gatt::BleGattTransport;
pub use nfc::NfcTransport;
pub use transport::{DummyTransport, Transport, TransportError};
pub use usb_ccid::UsbCcidTransport;
pub use usb_hid::UsbHidTransport;
