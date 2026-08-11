use log::debug;

/// Erros produzidos pela camada de transporte.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Operação chamada antes de `init()`.
    #[error("transport not initialized")]
    NotInitialized,
    /// Falha ao enviar dados para o host.
    #[error("send failed: {0}")]
    SendError(String),
    /// Falha ao receber dados do host.
    #[error("receive failed: {0}")]
    RecvError(String),
    /// Transporte já encerrado.
    #[error("transport closed")]
    Closed,
    /// Funcionalidade ainda não implementada (stubs).
    #[error("unimplemented: {0}")]
    Unimplemented(String),
}

/// Abstração de transporte físico usado para trocar comandos CTAP2 com o host.
///
/// A trait é object-safe, permitindo `Box<dyn Transport>` no
/// `EmbeddedAuthenticator`.
pub trait Transport: Send + Sync {
    /// Inicializa o transporte (enumeração USB, ativação de rádio, etc.).
    fn init(&mut self) -> Result<(), TransportError>;
    /// Envia um frame de resposta para o host.
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError>;
    /// Recebe um frame de requisição do host.
    fn recv(&mut self) -> Result<Vec<u8>, TransportError>;
    /// Encerra o transporte e libera recursos.
    fn close(&mut self) -> Result<(), TransportError>;
}

/// Transporte no-op usado em testes e no simulador host.
pub struct DummyTransport;

impl DummyTransport {
    /// Cria um transporte dummy.
    pub fn new() -> Self {
        Self
    }
}

impl Default for DummyTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for DummyTransport {
    fn init(&mut self) -> Result<(), TransportError> {
        debug!("DummyTransport initialized");
        Ok(())
    }

    fn send(&mut self, _data: &[u8]) -> Result<(), TransportError> {
        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        Ok(Vec::new())
    }

    fn close(&mut self) -> Result<(), TransportError> {
        debug!("DummyTransport closed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dummy_transport_lifecycle() {
        let mut t = DummyTransport::new();
        assert!(t.init().is_ok());
        assert!(t.send(b"ping").is_ok());
        assert_eq!(t.recv().unwrap(), Vec::<u8>::new());
        assert!(t.close().is_ok());
    }

    #[test]
    fn test_transport_is_object_safe() {
        let mut boxed: Box<dyn Transport> = Box::new(DummyTransport::new());
        assert!(boxed.init().is_ok());
    }

    #[test]
    fn test_transport_error_messages() {
        assert_eq!(
            TransportError::NotInitialized.to_string(),
            "transport not initialized"
        );
        assert_eq!(TransportError::Closed.to_string(), "transport closed");
        assert_eq!(
            TransportError::Unimplemented("nfc".to_string()).to_string(),
            "unimplemented: nfc"
        );
        assert_eq!(
            TransportError::SendError("io".to_string()).to_string(),
            "send failed: io"
        );
        assert_eq!(
            TransportError::RecvError("io".to_string()).to_string(),
            "receive failed: io"
        );
    }
}
