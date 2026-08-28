//! Agregador multi-protocolo de transportes (`MultiTransport`).
//!
//! Permite que um `EmbeddedAuthenticator` opere simultaneamente sobre vários
//! meios físicos (HID, CCID, NFC, BLE) mantendo a trait object-safe
//! `Transport`. Cada operação é disseminada aos transportes internos:
//!
//! - `init`/`close` fazem broadcast sequencial; o primeiro erro interrompe.
//! - `send`/`recv` usam first-success: tenta cada transporte até um não
//!   retornar `NotInitialized/Closed/Unimplemented`.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::transport::{Transport, TransportError};

/// Agregador que muxa `N` transportes sob uma única trait `Transport`.
///
/// O vetor pode estar vazio — nesse caso todas as operações retornam o
/// erro correspondente (`NotInitialized`/`Unimplemented`).
pub struct MultiTransport {
    transports: Vec<Box<dyn Transport>>,
}

impl MultiTransport {
    /// Cria o agregador a partir de um vetor já alocado.
    pub fn new(transports: Vec<Box<dyn Transport>>) -> Self {
        Self { transports }
    }

    /// Número de transportes internos.
    pub fn len(&self) -> usize {
        self.transports.len()
    }

    /// Indica se não há transportes internos.
    pub fn is_empty(&self) -> bool {
        self.transports.is_empty()
    }

    /// Acesso à fatia interna (somente leitura).
    pub fn transports(&self) -> &[Box<dyn Transport>] {
        &self.transports
    }

    /// Acesso mutável à fatia interna.
    pub fn transports_mut(&mut self) -> &mut [Box<dyn Transport>] {
        &mut self.transports
    }

    /// Adiciona um transporte ao agregador.
    pub fn push(&mut self, transport: Box<dyn Transport>) {
        self.transports.push(transport);
    }
}

impl Transport for MultiTransport {
    fn init(&mut self) -> Result<(), TransportError> {
        if self.transports.is_empty() {
            return Err(TransportError::NotInitialized);
        }
        for t in &mut self.transports {
            t.init()?;
        }
        Ok(())
    }

    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        let mut last_err = TransportError::NotInitialized;
        for t in &mut self.transports {
            match t.send(data) {
                Ok(()) => return Ok(()),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut last_err = TransportError::NotInitialized;
        for t in &mut self.transports {
            match t.recv() {
                Ok(v) => return Ok(v),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    fn close(&mut self) -> Result<(), TransportError> {
        if self.transports.is_empty() {
            return Err(TransportError::NotInitialized);
        }
        for t in &mut self.transports {
            t.close()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{DummyTransport, TransportError};

    struct FailingTransport;

    impl Transport for FailingTransport {
        fn init(&mut self) -> Result<(), TransportError> {
            Err(TransportError::SendError("fail".to_string()))
        }
        fn send(&mut self, _data: &[u8]) -> Result<(), TransportError> {
            Err(TransportError::NotInitialized)
        }
        fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
            Err(TransportError::NotInitialized)
        }
        fn close(&mut self) -> Result<(), TransportError> {
            Err(TransportError::NotInitialized)
        }
    }

    struct EchoTransport(Vec<u8>);

    impl Transport for EchoTransport {
        fn init(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
        fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
            self.0 = data.to_vec();
            Ok(())
        }
        fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
            Ok(self.0.clone())
        }
        fn close(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    #[test]
    fn test_empty_multitransport_returns_not_initialized() {
        let mut m = MultiTransport::new(Vec::new());
        assert!(m.init().is_err());
        assert!(m.send(b"hi").is_err());
        assert!(m.recv().is_err());
        assert!(m.close().is_err());
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn test_multitransport_broadcast_init_close() {
        let mut m = MultiTransport::new(vec![
            Box::new(DummyTransport::new()),
            Box::new(DummyTransport::new()),
        ]);
        assert!(m.init().is_ok());
        assert!(m.close().is_ok());
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn test_multitransport_first_success_send_recv() {
        // Primeiro falha, segundo sucede.
        let mut m = MultiTransport::new(vec![
            Box::new(FailingTransport),
            Box::new(EchoTransport(Vec::new())),
        ]);
        // init broadcast falha no primeiro -> erro.
        assert!(m.init().is_err());
        // Mas send tenta ambos: primeiro NotInitialized, segundo Ok.
        assert!(m.send(b"payload").is_ok());
        // recv first-success: FailingTransport falha, Echo retorna payload.
        let data = m.recv().unwrap();
        assert_eq!(data, b"payload".to_vec());
    }

    #[test]
    fn test_multitransport_push_and_transports_access() {
        let mut m = MultiTransport::new(Vec::new());
        m.push(Box::new(DummyTransport::new()));
        assert_eq!(m.len(), 1);
        assert_eq!(m.transports().len(), 1);
        assert_eq!(m.transports_mut().len(), 1);
    }
}
