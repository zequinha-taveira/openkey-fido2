use crate::transport::{Transport, TransportError};
use log::warn;

/// Stub de transporte USB-CCID (smartcard).
///
/// Placeholder para a implementação do protocolo CCID.
/// Todas as operações de I/O retornam [`TransportError::Unimplemented`].
pub struct UsbCcidTransport {
    initialized: bool,
}

impl UsbCcidTransport {
    /// Cria o stub CCID sem inicializar o periférico.
    pub fn new() -> Self {
        Self { initialized: false }
    }

    /// Indica se `init()` já foi chamado.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for UsbCcidTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for UsbCcidTransport {
    fn init(&mut self) -> Result<(), TransportError> {
        warn!("UsbCcidTransport is a stub — not yet implemented");
        self.initialized = true;
        Err(TransportError::Unimplemented(
            "UsbCcidTransport requires CCID protocol integration".to_string(),
        ))
    }

    fn send(&mut self, _data: &[u8]) -> Result<(), TransportError> {
        if !self.initialized {
            return Err(TransportError::NotInitialized);
        }
        Err(TransportError::Unimplemented(
            "UsbCcidTransport::send requires CCID protocol integration".to_string(),
        ))
    }

    fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        if !self.initialized {
            return Err(TransportError::NotInitialized);
        }
        Err(TransportError::Unimplemented(
            "UsbCcidTransport::recv requires CCID protocol integration".to_string(),
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
        let mut t = UsbCcidTransport::new();
        assert!(!t.is_initialized());
        assert!(matches!(t.init(), Err(TransportError::Unimplemented(_))));
        assert!(t.is_initialized());
    }

    #[test]
    fn test_io_before_init_returns_not_initialized() {
        let mut t = UsbCcidTransport::default();
        assert!(matches!(
            t.send(b"data"),
            Err(TransportError::NotInitialized)
        ));
        assert!(matches!(t.recv(), Err(TransportError::NotInitialized)));
    }

    #[test]
    fn test_io_after_init_returns_unimplemented() {
        let mut t = UsbCcidTransport::new();
        let _ = t.init();
        assert!(matches!(
            t.send(b"data"),
            Err(TransportError::Unimplemented(_))
        ));
        assert!(matches!(t.recv(), Err(TransportError::Unimplemented(_))));
    }

    #[test]
    fn test_close_resets_state() {
        let mut t = UsbCcidTransport::new();
        let _ = t.init();
        assert!(t.close().is_ok());
        assert!(!t.is_initialized());
    }
}
