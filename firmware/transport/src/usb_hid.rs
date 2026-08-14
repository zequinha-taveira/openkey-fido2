use crate::transport::{Transport, TransportError};
use alloc::string::ToString;
use alloc::vec::Vec;
use log::warn;

/// Stub de transporte USB-HID (CTAPHID).
///
/// Placeholder para a integração futura com a crate `usb-device`.
/// Todas as operações de I/O retornam [`TransportError::Unimplemented`].
pub struct UsbHidTransport {
    initialized: bool,
}

impl UsbHidTransport {
    /// Cria o stub USB-HID sem inicializar o periférico.
    pub fn new() -> Self {
        Self { initialized: false }
    }

    /// Indica se `init()` já foi chamado.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for UsbHidTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for UsbHidTransport {
    fn init(&mut self) -> Result<(), TransportError> {
        warn!("UsbHidTransport is a stub — not yet implemented");
        self.initialized = true;
        Err(TransportError::Unimplemented(
            "UsbHidTransport requires usb-device crate integration".to_string(),
        ))
    }

    fn send(&mut self, _data: &[u8]) -> Result<(), TransportError> {
        if !self.initialized {
            return Err(TransportError::NotInitialized);
        }
        Err(TransportError::Unimplemented(
            "UsbHidTransport::send requires usb-device crate integration".to_string(),
        ))
    }

    fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        if !self.initialized {
            return Err(TransportError::NotInitialized);
        }
        Err(TransportError::Unimplemented(
            "UsbHidTransport::recv requires usb-device crate integration".to_string(),
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
        let mut t = UsbHidTransport::new();
        assert!(!t.is_initialized());
        assert!(matches!(t.init(), Err(TransportError::Unimplemented(_))));
        assert!(t.is_initialized());
    }

    #[test]
    fn test_io_before_init_returns_not_initialized() {
        let mut t = UsbHidTransport::default();
        assert!(matches!(
            t.send(b"data"),
            Err(TransportError::NotInitialized)
        ));
        assert!(matches!(t.recv(), Err(TransportError::NotInitialized)));
    }

    #[test]
    fn test_io_after_init_returns_unimplemented() {
        let mut t = UsbHidTransport::new();
        let _ = t.init();
        assert!(matches!(
            t.send(b"data"),
            Err(TransportError::Unimplemented(_))
        ));
        assert!(matches!(t.recv(), Err(TransportError::Unimplemented(_))));
    }

    #[test]
    fn test_close_resets_state() {
        let mut t = UsbHidTransport::new();
        let _ = t.init();
        assert!(t.close().is_ok());
        assert!(!t.is_initialized());
    }
}
