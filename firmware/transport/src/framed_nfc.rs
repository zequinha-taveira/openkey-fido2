//! Adaptador de transporte NFC com framing ISO 7816-4 sobre qualquer [`NfcDevice`].
//!
//! Host-only: sem rádio; o framing cru (`recv_apdu_command` /
//! `send_apdu_response`) vive no [`Transport`] e o roteamento ISO 7816
//! ([`CardRouter::process`], incluindo dreno `61 XX`/GET RESPONSE) vive em
//! [`FramedNfcTransport::recv_routed`], que recebe o roteador por empréstimo
//! — espelhando o loop da RP2350 (`take_pending_request → router.process →
//! send_response`). O roteador não é guardado no transporte porque
//! [`Transport`] exige `Send + Sync` e [`Applet`](crate::iso7816::Applet) não
//! é thread-safe.

#[cfg(feature = "embedded")]
use crate::embedded::{EmbeddedTransportError, NfcDevice};
use crate::iso7816::{CardRouter, ResponseData};
use crate::transport::{Transport, TransportError};
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

/// Tamanho do buffer de leitura de APDU (cobre forma curta + estendida curta).
#[cfg(feature = "embedded")]
const NFC_APDU_BUF: usize = 2048;

/// Adaptador que encapsula um [`NfcDevice`] e gerencia frames APDU.
#[cfg(feature = "embedded")]
pub struct FramedNfcTransport<D: NfcDevice> {
    device: D,
    initialized: bool,
}

#[cfg(feature = "embedded")]
impl<D: NfcDevice> FramedNfcTransport<D> {
    /// Cria uma nova instância a partir de um dispositivo NFC concreto.
    pub fn new(device: D) -> Self {
        Self {
            device,
            initialized: false,
        }
    }

    /// Retorna uma referência ao dispositivo NFC subjacente.
    pub fn device(&self) -> &D {
        &self.device
    }

    /// Retorna uma referência mutável ao dispositivo NFC subjacente.
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    /// Lê um comando APDU, roteia via [`CardRouter::process`], devolve a
    /// resposta ao leitor e retorna a porção de dados (sem SW).
    ///
    /// Respostas encadeadas (`61 XX`) são drenadas internamente: o transporte
    /// lê os GET RESPONSEs seguintes do dispositivo, alimenta o roteador e
    /// concatena os trechos até o SW final.
    pub fn recv_routed(&mut self, router: &mut CardRouter) -> Result<Vec<u8>, TransportError> {
        if !self.initialized {
            return Err(TransportError::NotInitialized);
        }
        let raw = self.read_command()?;
        let mut out = self.process_and_respond(router, &raw)?;
        while router.is_chain_pending() {
            let next = self.read_command()?;
            let chunk = self.process_and_respond(router, &next)?;
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    /// Lê um comando APDU bruto do leitor (com checagem de campo).
    fn read_command(&mut self) -> Result<Vec<u8>, TransportError> {
        if !self.device.is_field_detected() {
            return Err(TransportError::from(EmbeddedTransportError::Timeout));
        }
        let mut buf = vec![0u8; NFC_APDU_BUF];
        let len = self
            .device
            .recv_apdu_command(&mut buf)
            .map_err(TransportError::from)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Roteia um comando, envia a resposta (`data + SW`) e retorna os dados.
    fn process_and_respond(
        &mut self,
        router: &mut CardRouter,
        raw: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let resp = router.process(raw);
        let data = resp.data.clone();
        self.device
            .send_apdu_response(&resp.to_bytes())
            .map_err(TransportError::from)?;
        Ok(data)
    }
}

#[cfg(feature = "embedded")]
impl<D: NfcDevice + Send + Sync> Transport for FramedNfcTransport<D> {
    fn init(&mut self) -> Result<(), TransportError> {
        self.device.init().map_err(TransportError::from)?;
        self.initialized = true;
        Ok(())
    }

    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        if !self.initialized {
            return Err(TransportError::NotInitialized);
        }
        if !self.device.is_field_detected() {
            return Err(TransportError::SendError("timeout".to_string()));
        }
        let bytes = ResponseData::ok(data.to_vec()).to_bytes();
        self.device
            .send_apdu_response(&bytes)
            .map_err(TransportError::from)?;
        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        if !self.initialized {
            return Err(TransportError::NotInitialized);
        }
        self.read_command()
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.initialized = false;
        Ok(())
    }
}

#[cfg(all(test, feature = "embedded"))]
mod tests {
    use super::*;
    use crate::embedded::EmbeddedTransportError;
    use crate::iso7816::{Apdu, Applet, ResponseData, INS_SELECT};
    use alloc::collections::VecDeque;
    use alloc::vec;

    struct MockNfcDevice {
        queued: VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
        field: bool,
        initialized: bool,
    }

    impl MockNfcDevice {
        fn new() -> Self {
            Self {
                queued: VecDeque::new(),
                sent: Vec::new(),
                field: true,
                initialized: false,
            }
        }

        fn queue(&mut self, apdu: Vec<u8>) {
            self.queued.push_back(apdu);
        }

        fn set_field(&mut self, present: bool) {
            self.field = present;
        }
    }

    impl NfcDevice for MockNfcDevice {
        fn init(&mut self) -> Result<(), EmbeddedTransportError> {
            self.initialized = true;
            Ok(())
        }

        fn is_field_detected(&self) -> bool {
            self.field
        }

        fn send_apdu_response(&mut self, response: &[u8]) -> Result<(), EmbeddedTransportError> {
            if !self.initialized {
                return Err(EmbeddedTransportError::NotInitialized);
            }
            self.sent.push(response.to_vec());
            Ok(())
        }

        fn recv_apdu_command(&mut self, buf: &mut [u8]) -> Result<usize, EmbeddedTransportError> {
            if !self.initialized {
                return Err(EmbeddedTransportError::NotInitialized);
            }
            match self.queued.pop_front() {
                Some(cmd) => {
                    if cmd.len() > buf.len() {
                        return Err(EmbeddedTransportError::BufferTooSmall);
                    }
                    buf[..cmd.len()].copy_from_slice(&cmd);
                    Ok(cmd.len())
                }
                None => Err(EmbeddedTransportError::Timeout),
            }
        }
    }

    const ECHO_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];

    struct EchoApplet;

    impl Applet for EchoApplet {
        fn aid(&self) -> &[u8] {
            ECHO_AID
        }

        fn select(&mut self) -> Result<(), u16> {
            Ok(())
        }

        fn process(&mut self, apdu: &Apdu) -> Result<ResponseData, u16> {
            Ok(ResponseData::ok(apdu.data.to_vec()))
        }
    }

    struct BigApplet {
        payload: Vec<u8>,
    }

    impl Applet for BigApplet {
        fn aid(&self) -> &[u8] {
            ECHO_AID
        }

        fn select(&mut self) -> Result<(), u16> {
            Ok(())
        }

        fn process(&mut self, _apdu: &Apdu) -> Result<ResponseData, u16> {
            Ok(ResponseData::ok(self.payload.clone()))
        }
    }

    fn select_apdu(aid: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, INS_SELECT, 0x04, 0x00, aid.len() as u8];
        v.extend_from_slice(aid);
        v
    }

    fn case4_apdu(ins: u8, data: &[u8], le: u8) -> Vec<u8> {
        let mut v = vec![0x00, ins, 0x00, 0x00, data.len() as u8];
        v.extend_from_slice(data);
        v.push(le);
        v
    }

    fn get_response(le: Option<u8>) -> Vec<u8> {
        let mut v = vec![0x00, 0xC0, 0x00, 0x00];
        if let Some(b) = le {
            v.push(b);
        }
        v
    }

    #[test]
    fn test_send_recv_roundtrip_via_mock() {
        let raw = case4_apdu(0x10, &[1, 2, 3], 16);
        let mut t = FramedNfcTransport::new(MockNfcDevice::new());
        t.init().unwrap();
        t.device_mut().queue(raw.clone());

        let received = t.recv().unwrap();
        assert_eq!(received, raw);

        t.send(&[4, 5, 6]).unwrap();
        let sent = t.device().sent.last().unwrap();
        assert_eq!(sent, &vec![4, 5, 6, 0x90, 0x00]);
    }

    #[test]
    fn test_routed_echo_via_card_router() {
        let mut t = FramedNfcTransport::new(MockNfcDevice::new());
        t.init().unwrap();
        t.device_mut().queue(select_apdu(ECHO_AID));
        t.device_mut().queue(case4_apdu(0x10, &[1, 2, 3], 16));

        let mut applet = EchoApplet;
        let mut router = CardRouter::new();
        router.register(&mut applet);

        assert!(t.recv_routed(&mut router).unwrap().is_empty());
        assert_eq!(t.recv_routed(&mut router).unwrap(), vec![1, 2, 3]);
        assert_eq!(t.device().sent.len(), 2);
        assert_eq!(t.device().sent[1], vec![1, 2, 3, 0x90, 0x00]);
    }

    #[test]
    fn test_field_absent_returns_timeout() {
        let mut t = FramedNfcTransport::new(MockNfcDevice::new());
        t.init().unwrap();
        t.device_mut().set_field(false);
        assert!(matches!(t.recv(), Err(TransportError::RecvError(_))));
        assert!(matches!(t.send(b"data"), Err(TransportError::SendError(_))));

        let mut applet = EchoApplet;
        let mut router = CardRouter::new();
        router.register(&mut applet);
        assert!(matches!(
            t.recv_routed(&mut router),
            Err(TransportError::RecvError(_))
        ));
    }

    #[test]
    fn test_chaining_drain() {
        let payload: Vec<u8> = (0..300u32).map(|i| (i % 256) as u8).collect();
        let expected = payload.clone();
        let mut t = FramedNfcTransport::new(MockNfcDevice::new());
        t.init().unwrap();
        // Sem Le o roteador retém tudo e sinaliza 61XX; dreno via GET RESPONSE.
        t.device_mut().queue(select_apdu(ECHO_AID));
        t.device_mut().queue(vec![0x80, 0x10, 0x00, 0x00]);
        t.device_mut().queue(get_response(Some(0x00)));
        t.device_mut().queue(get_response(None));

        let mut applet = BigApplet { payload };
        let mut router = CardRouter::new();
        router.register(&mut applet);

        assert!(t.recv_routed(&mut router).unwrap().is_empty());
        let drained = t.recv_routed(&mut router).unwrap();
        assert_eq!(drained, expected);
        assert!(!router.is_chain_pending());
        assert_eq!(t.device().sent.len(), 4);
        let last = t.device().sent.last().unwrap();
        assert_eq!(last[last.len() - 2..], [0x90, 0x00]);
    }

    #[test]
    fn test_io_before_init_returns_not_initialized() {
        let mut t = FramedNfcTransport::new(MockNfcDevice::new());
        assert!(matches!(t.send(b"x"), Err(TransportError::NotInitialized)));
        assert!(matches!(t.recv(), Err(TransportError::NotInitialized)));

        let mut applet = EchoApplet;
        let mut router = CardRouter::new();
        router.register(&mut applet);
        assert!(matches!(
            t.recv_routed(&mut router),
            Err(TransportError::NotInitialized)
        ));
    }
}
