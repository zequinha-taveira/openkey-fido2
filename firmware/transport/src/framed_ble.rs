//! Adaptador de transporte BLE GATT com framing host-only sobre qualquer [`BleGattDevice`].
//!
//! Modelo de fragmentação (apenas host, sem SoftDevice/NimBLE): o primeiro
//! fragmento carrega o cabeçalho de 3 bytes `[CMD, LEN_HI, LEN_LO]` seguido
//! do primeiro chunk; continuações carregam chunks brutos. `LEN` é o
//! comprimento total big-endian da mensagem.

#[cfg(feature = "embedded")]
use crate::ble_gatt::{BLE_CMD_MSG, BLE_HEADER_LEN, BLE_MAX_MESSAGE_LEN, BLE_MAX_NOTIFICATION_LEN};
#[cfg(feature = "embedded")]
use crate::embedded::BleGattDevice;
use crate::transport::{Transport, TransportError};
use alloc::string::ToString;
use alloc::vec::Vec;

/// Fragmenta `(cmd, payload)` em notificações de até `max_chunk` bytes.
///
/// O primeiro fragmento leva o cabeçalho de 3 bytes; continuações são
/// payload bruto.
pub fn ble_fragment(cmd: u8, payload: &[u8], max_chunk: usize) -> Vec<Vec<u8>> {
    let chunk = max_chunk.max(BLE_HEADER_LEN + 1);
    let total = payload.len();
    let mut out: Vec<Vec<u8>> = Vec::new();
    if total == 0 {
        return vec![vec![cmd, 0, 0]];
    }
    let first_capacity = chunk - BLE_HEADER_LEN;
    let first_len = total.min(first_capacity);
    let mut frag = Vec::with_capacity(BLE_HEADER_LEN + first_len);
    frag.push(cmd);
    frag.push((total >> 8) as u8);
    frag.push((total & 0xFF) as u8);
    frag.extend_from_slice(&payload[..first_len]);
    out.push(frag);
    let mut offset = first_len;
    while offset < total {
        let end = (offset + chunk).min(total);
        out.push(payload[offset..end].to_vec());
        offset = end;
    }
    out
}

/// Adaptador que encapsula um [`BleGattDevice`] e gerencia framing BLE.
#[cfg(feature = "embedded")]
pub struct FramedBleGattTransport<D: BleGattDevice> {
    device: D,
    rx_buf: Vec<u8>,
    rx_expected: Option<usize>,
    initialized: bool,
}

#[cfg(feature = "embedded")]
impl<D: BleGattDevice> FramedBleGattTransport<D> {
    /// Cria uma nova instância a partir de um dispositivo BLE GATT concreto.
    pub fn new(device: D) -> Self {
        Self {
            device,
            rx_buf: Vec::new(),
            rx_expected: None,
            initialized: false,
        }
    }

    /// Retorna uma referência ao dispositivo de hardware subjacente.
    pub fn device(&self) -> &D {
        &self.device
    }

    /// Retorna uma referência mutável ao dispositivo de hardware subjacente.
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    /// Indica se `init()` já foi chamado.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    fn reset_assembler(&mut self) {
        self.rx_buf.clear();
        self.rx_expected = None;
    }

    fn push_fragment(&mut self, frag: &[u8]) -> Result<Option<Vec<u8>>, TransportError> {
        if self.rx_expected.is_none() {
            if frag.len() < BLE_HEADER_LEN {
                return Err(TransportError::RecvError(
                    "ble fragment too short for header".to_string(),
                ));
            }
            let total = ((frag[1] as usize) << 8) | (frag[2] as usize);
            if total > BLE_MAX_MESSAGE_LEN {
                return Err(TransportError::RecvError(
                    "ble message exceeds max length".to_string(),
                ));
            }
            self.rx_buf.clear();
            self.rx_buf.extend_from_slice(&frag[BLE_HEADER_LEN..]);
            self.rx_expected = Some(total);
        } else {
            self.rx_buf.extend_from_slice(frag);
        }
        let expected = self.rx_expected.unwrap_or(0);
        if self.rx_buf.len() > expected {
            self.reset_assembler();
            return Err(TransportError::RecvError(
                "ble framing overflow".to_string(),
            ));
        }
        if self.rx_buf.len() == expected {
            let msg = core::mem::take(&mut self.rx_buf);
            self.rx_expected = None;
            return Ok(Some(msg));
        }
        Ok(None)
    }
}

#[cfg(feature = "embedded")]
impl<D: BleGattDevice + Send + Sync> Transport for FramedBleGattTransport<D> {
    fn init(&mut self) -> Result<(), TransportError> {
        self.device.init().map_err(TransportError::from)?;
        self.reset_assembler();
        self.initialized = true;
        Ok(())
    }

    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        if !self.initialized {
            return Err(TransportError::NotInitialized);
        }
        if !self.device.is_connected() {
            return Err(TransportError::Closed);
        }
        for frag in ble_fragment(BLE_CMD_MSG, data, BLE_MAX_NOTIFICATION_LEN) {
            self.device
                .send_notification(&frag)
                .map_err(TransportError::from)?;
        }
        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        if !self.initialized {
            return Err(TransportError::NotInitialized);
        }
        if !self.device.is_connected() {
            return Err(TransportError::RecvError(
                "timeout: ble central not connected".to_string(),
            ));
        }
        let mut raw = [0u8; BLE_MAX_NOTIFICATION_LEN * 2];
        loop {
            if !self.device.is_connected() {
                return Err(TransportError::Closed);
            }
            let n = self
                .device
                .recv_command(&mut raw)
                .map_err(TransportError::from)?;
            if n == 0 {
                continue;
            }
            match self.push_fragment(&raw[..n])? {
                Some(msg) => return Ok(msg),
                None => continue,
            }
        }
    }

    fn close(&mut self) -> Result<(), TransportError> {
        let _ = self.device.disconnect();
        self.reset_assembler();
        self.initialized = false;
        Ok(())
    }
}

#[cfg(all(test, feature = "embedded"))]
mod tests {
    use super::*;
    use crate::embedded::EmbeddedTransportError;
    use alloc::collections::VecDeque;

    pub(crate) struct MockBleGatt {
        commands: VecDeque<Vec<u8>>,
        pub(crate) notifications: Vec<Vec<u8>>,
        initialized: bool,
        connected: bool,
    }

    impl MockBleGatt {
        fn new() -> Self {
            Self {
                commands: VecDeque::new(),
                notifications: Vec::new(),
                initialized: false,
                connected: false,
            }
        }

        fn queue_command(&mut self, data: Vec<u8>) {
            self.commands.push_back(data);
        }

        fn set_connected(&mut self, connected: bool) {
            self.connected = connected;
        }
    }

    impl BleGattDevice for MockBleGatt {
        fn init(&mut self) -> Result<(), EmbeddedTransportError> {
            self.initialized = true;
            self.connected = true;
            Ok(())
        }

        fn is_connected(&self) -> bool {
            self.connected
        }

        fn send_notification(&mut self, data: &[u8]) -> Result<(), EmbeddedTransportError> {
            if !self.initialized {
                return Err(EmbeddedTransportError::NotInitialized);
            }
            if !self.connected {
                return Err(EmbeddedTransportError::Closed);
            }
            self.notifications.push(data.to_vec());
            Ok(())
        }

        fn recv_command(&mut self, buf: &mut [u8]) -> Result<usize, EmbeddedTransportError> {
            if !self.initialized {
                return Err(EmbeddedTransportError::NotInitialized);
            }
            if !self.connected {
                return Err(EmbeddedTransportError::Closed);
            }
            match self.commands.pop_front() {
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

        fn disconnect(&mut self) -> Result<(), EmbeddedTransportError> {
            self.connected = false;
            Ok(())
        }
    }

    #[test]
    fn test_ble_not_initialized_gating() {
        let mut t = FramedBleGattTransport::new(MockBleGatt::new());
        assert!(!t.is_initialized());
        assert!(matches!(
            t.send(b"data"),
            Err(TransportError::NotInitialized)
        ));
        assert!(matches!(t.recv(), Err(TransportError::NotInitialized)));
    }

    #[test]
    fn test_ble_fragment_reassemble_roundtrip() {
        let mut t = FramedBleGattTransport::new(MockBleGatt::new());
        t.init().unwrap();

        let payload: Vec<u8> = (0..64u8).collect();
        t.send(&payload).unwrap();

        // 64B em notificações de 20B: 1º leva 17B + 3 continuations
        // (20+20+7) = 4 notificações.
        assert_eq!(t.device().notifications.len(), 4);

        let frags = core::mem::take(&mut t.device_mut().notifications);
        for f in frags {
            t.device_mut().queue_command(f);
        }

        let received = t.recv().unwrap();
        assert_eq!(received, payload);
    }

    #[test]
    fn test_ble_disconnected_send_closed_recv_timeout() {
        let mut t = FramedBleGattTransport::new(MockBleGatt::new());
        t.init().unwrap();
        t.device_mut().set_connected(false);

        assert!(matches!(t.send(b"data"), Err(TransportError::Closed)));
        match t.recv() {
            Err(TransportError::RecvError(msg)) => assert!(msg.contains("timeout")),
            Err(TransportError::Closed) => {}
            other => panic!("expected timeout/closed, got {:?}", other),
        }
    }

    #[test]
    fn test_ble_disconnect_clears_state() {
        let mut t = FramedBleGattTransport::new(MockBleGatt::new());
        t.init().unwrap();

        // Mensagem de 32B gera 2 fragmentos; entrega só o primeiro e força
        // timeout no segundo, deixando estado parcial no assembler.
        let payload: Vec<u8> = (0..32u8).collect();
        let frags = ble_fragment(BLE_CMD_MSG, &payload, BLE_MAX_NOTIFICATION_LEN);
        assert!(frags.len() > 1);
        t.device_mut().queue_command(frags[0].clone());
        assert!(matches!(t.recv(), Err(TransportError::RecvError(_))));

        // disconnect limpa estado parcial e derruba init.
        assert!(t.close().is_ok());
        assert!(!t.is_initialized());
        assert!(matches!(t.send(b"x"), Err(TransportError::NotInitialized)));

        // Após re-init, roundtrip completo funciona (sem resíduo).
        t.device_mut().set_connected(true);
        t.init().unwrap();
        t.send(&payload).unwrap();
        let sent = core::mem::take(&mut t.device_mut().notifications);
        for f in sent {
            t.device_mut().queue_command(f);
        }
        assert_eq!(t.recv().unwrap(), payload);
    }

    #[test]
    fn test_ble_fragment_header_shape() {
        let frags = ble_fragment(BLE_CMD_MSG, &[1, 2, 3], BLE_MAX_NOTIFICATION_LEN);
        assert_eq!(frags.len(), 1);
        assert_eq!(&frags[0][..BLE_HEADER_LEN], &[BLE_CMD_MSG, 0, 3]);
        assert_eq!(&frags[0][BLE_HEADER_LEN..], &[1, 2, 3]);
    }
}
