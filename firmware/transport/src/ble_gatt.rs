use crate::transport::{Transport, TransportError};
use alloc::string::ToString;
use alloc::vec::Vec;
use log::warn;

/// Stub de transporte BLE GATT (FIDO Bluetooth Service).
///
/// Placeholder para o servidor GATT com o serviço `fido2`
/// (characteristics `fidoControlPoint`, `fidoStatus`, `fidoServiceRevision`).
/// Todas as operações de I/O retornam [`TransportError::Unimplemented`].
pub struct BleGattTransport {
    initialized: bool,
}

impl BleGattTransport {
    /// Cria o stub BLE GATT sem inicializar o stack Bluetooth.
    pub fn new() -> Self {
        Self { initialized: false }
    }

    /// Indica se `init()` já foi chamado.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for BleGattTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for BleGattTransport {
    fn init(&mut self) -> Result<(), TransportError> {
        warn!("BleGattTransport is a stub — not yet implemented");
        self.initialized = true;
        Err(TransportError::Unimplemented(
            "BleGattTransport requires BLE GATT server integration".to_string(),
        ))
    }

    fn send(&mut self, _data: &[u8]) -> Result<(), TransportError> {
        if !self.initialized {
            return Err(TransportError::NotInitialized);
        }
        Err(TransportError::Unimplemented(
            "BleGattTransport::send requires BLE GATT server integration".to_string(),
        ))
    }

    fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        if !self.initialized {
            return Err(TransportError::NotInitialized);
        }
        Err(TransportError::Unimplemented(
            "BleGattTransport::recv requires BLE GATT server integration".to_string(),
        ))
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.initialized = false;
        Ok(())
    }
}

// Host-only BLE PDU constants for the FIDO GATT profile.
//
// These are pure `const`s with no radio dependency: no SoftDevice/NimBLE
// integration is claimed. Real BLE stack integration remains pending
// (`TODO.md` item for `BleGattTransport` stays 🚧).
//
// Fragmentation model (host-only, mirrors the FIDO Bluetooth profile shape):
// the first notification carries a 3-byte header `[CMD, LEN_HI, LEN_LO]`
// followed by the first payload chunk; continuation notifications carry
// raw payload chunks. `LEN` is the big-endian total message length.
//
// 16-bit UUID aliases below are host-side identifiers; on-air 128-bit
// UUIDs derive from the Bluetooth base UUID. Only the service UUID
// (`0xFFFD`, assigned by the Bluetooth SIG for FIDO2) is normative.

/// FIDO2 GATT service UUID (Bluetooth SIG assigned number).
pub const FIDO_SERVICE_UUID16: u16 = 0xFFFD;

/// Host-only alias for the FIDO Control Point characteristic.
pub const FIDO_CONTROL_POINT_UUID16: u16 = 0xFF11;

/// Host-only alias for the FIDO Status characteristic (notifications).
pub const FIDO_STATUS_UUID16: u16 = 0xFF12;

/// Host-only alias for the FIDO Service Revision characteristic.
pub const FIDO_SERVICE_REVISION_UUID16: u16 = 0xFF13;

/// Default ATT MTU before negotiation.
pub const BLE_DEFAULT_MTU: usize = 23;

/// ATT header overhead; max notification payload at default MTU.
pub const BLE_MAX_NOTIFICATION_LEN: usize = BLE_DEFAULT_MTU - 3;

/// Length of the first-fragment header `[CMD, LEN_HI, LEN_LO]`.
pub const BLE_HEADER_LEN: usize = 3;

/// Message command carried in the first-fragment header.
pub const BLE_CMD_MSG: u8 = 0x83;

/// Ping command (echo, host-only).
pub const BLE_CMD_PING: u8 = 0x81;

/// Keepalive status command (host-only).
pub const BLE_CMD_KEEPALIVE: u8 = 0x82;

/// Cancel command (host-only).
pub const BLE_CMD_CANCEL: u8 = 0xBE;

/// Error command (host-only).
pub const BLE_CMD_ERROR: u8 = 0xBF;

/// Upper bound for a reassembled BLE message (host-only guard).
pub const BLE_MAX_MESSAGE_LEN: usize = 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_returns_unimplemented() {
        let mut t = BleGattTransport::new();
        assert!(!t.is_initialized());
        assert!(matches!(t.init(), Err(TransportError::Unimplemented(_))));
        assert!(t.is_initialized());
    }

    #[test]
    fn test_io_before_init_returns_not_initialized() {
        let mut t = BleGattTransport::default();
        assert!(matches!(
            t.send(b"data"),
            Err(TransportError::NotInitialized)
        ));
        assert!(matches!(t.recv(), Err(TransportError::NotInitialized)));
    }

    #[test]
    fn test_io_after_init_returns_unimplemented() {
        let mut t = BleGattTransport::new();
        let _ = t.init();
        assert!(matches!(
            t.send(b"data"),
            Err(TransportError::Unimplemented(_))
        ));
        assert!(matches!(t.recv(), Err(TransportError::Unimplemented(_))));
    }

    #[test]
    fn test_close_resets_state() {
        let mut t = BleGattTransport::new();
        let _ = t.init();
        assert!(t.close().is_ok());
        assert!(!t.is_initialized());
    }
}
