use crate::transport::{Transport, TransportError};
use alloc::string::ToString;
use alloc::vec::Vec;
use log::warn;

/// Stub de transporte NFC (ISO/IEC 14443 Type A/B).
///
/// Placeholder para a implementação do frontend NFC e do mapeamento
/// APDU ↔ CTAP2. Todas as operações de I/O retornam
/// [`TransportError::Unimplemented`].
pub struct NfcTransport {
    initialized: bool,
}

impl NfcTransport {
    /// Cria o stub NFC sem inicializar o frontend.
    pub fn new() -> Self {
        Self { initialized: false }
    }

    /// Indica se `init()` já foi chamado.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for NfcTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for NfcTransport {
    fn init(&mut self) -> Result<(), TransportError> {
        warn!("NfcTransport is a stub — not yet implemented");
        self.initialized = true;
        Err(TransportError::Unimplemented(
            "NfcTransport requires ISO 14443 frontend integration".to_string(),
        ))
    }

    fn send(&mut self, _data: &[u8]) -> Result<(), TransportError> {
        if !self.initialized {
            return Err(TransportError::NotInitialized);
        }
        Err(TransportError::Unimplemented(
            "NfcTransport::send requires ISO 14443 frontend integration".to_string(),
        ))
    }

    fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        if !self.initialized {
            return Err(TransportError::NotInitialized);
        }
        Err(TransportError::Unimplemented(
            "NfcTransport::recv requires ISO 14443 frontend integration".to_string(),
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
        let mut t = NfcTransport::new();
        assert!(!t.is_initialized());
        assert!(matches!(t.init(), Err(TransportError::Unimplemented(_))));
        assert!(t.is_initialized());
    }

    #[test]
    fn test_io_before_init_returns_not_initialized() {
        let mut t = NfcTransport::default();
        assert!(matches!(
            t.send(b"data"),
            Err(TransportError::NotInitialized)
        ));
        assert!(matches!(t.recv(), Err(TransportError::NotInitialized)));
    }

    #[test]
    fn test_io_after_init_returns_unimplemented() {
        let mut t = NfcTransport::new();
        let _ = t.init();
        assert!(matches!(
            t.send(b"data"),
            Err(TransportError::Unimplemented(_))
        ));
        assert!(matches!(t.recv(), Err(TransportError::Unimplemented(_))));
    }

    #[test]
    fn test_close_resets_state() {
        let mut t = NfcTransport::new();
        let _ = t.init();
        assert!(t.close().is_ok());
        assert!(!t.is_initialized());
    }
}
