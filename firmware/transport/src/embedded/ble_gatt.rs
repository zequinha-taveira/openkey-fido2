//! Bluetooth Low Energy (BLE) GATT contract for FIDO2 / CTAP2.

use super::EmbeddedTransportError;

/// BLE GATT Server contract for FIDO Alliance Bluetooth profile.
pub trait BleGattDevice {
    /// Initialize the BLE stack, advertising parameters and FIDO GATT service.
    fn init(&mut self) -> Result<(), EmbeddedTransportError>;

    /// Indicates whether a BLE Central host is connected.
    fn is_connected(&self) -> bool;

    /// Send a notification packet on the FIDO Control Point length / Status characteristic.
    fn send_notification(&mut self, data: &[u8]) -> Result<(), EmbeddedTransportError>;

    /// Receive a written command from the FIDO Control Point characteristic.
    fn recv_command(&mut self, buf: &mut [u8]) -> Result<usize, EmbeddedTransportError>;

    /// Stop advertising and disconnect active links.
    fn disconnect(&mut self) -> Result<(), EmbeddedTransportError>;
}
