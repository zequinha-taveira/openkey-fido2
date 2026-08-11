use crate::transport::{Transport, TransportError};
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
