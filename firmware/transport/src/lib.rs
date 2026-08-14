//! Camada de transporte do autenticador FIDO2.
//!
//! Define a trait [`Transport`], a camada de empacotamento [`ctaphid`],
//! adaptadores para framing de hardware (`FramedUsbHidTransport`, `FramedCcidTransport`),
//! e stubs para os transportes físicos previstos: USB-HID (CTAPHID), USB-CCID,
//! NFC (ISO 14443) e BLE GATT.
//!
//! When the `embedded` feature is enabled, the [`embedded`] module provides
//! `no_std` trait contracts and reference implementations for targets that
//! implement [`embedded-hal`].

#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

#[cfg(feature = "embedded")]
pub mod embedded;

pub mod ble_gatt;
pub mod ctaphid;
pub mod nfc;
pub mod transport;
pub mod usb_ccid;
pub mod usb_hid;

#[cfg(feature = "embedded")]
pub mod framed_ccid;
#[cfg(feature = "embedded")]
pub mod framed_hid;

pub use ble_gatt::BleGattTransport;
pub use ctaphid::{
    ctaphid_capabilities, ChannelManager, CtaphidAssembler, CtaphidCommand, CtaphidErrorCode,
    CtaphidFragmenter, CtaphidKeepaliveStatus, CtaphidMessage, CtaphidPacket,
};
#[cfg(feature = "usb-device")]
pub use embedded::usb_hid_backend::{CtapHidClass, UsbHidBackend};
#[cfg(feature = "embedded")]
pub use framed_ccid::FramedCcidTransport;
#[cfg(feature = "embedded")]
pub use framed_hid::FramedUsbHidTransport;
pub use nfc::NfcTransport;
pub use transport::{DummyTransport, Transport, TransportError};
pub use usb_ccid::UsbCcidTransport;
pub use usb_hid::UsbHidTransport;
