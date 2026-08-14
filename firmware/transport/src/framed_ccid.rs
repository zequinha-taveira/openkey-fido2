#[cfg(feature = "embedded")]
use crate::embedded::{ApduCommand, ApduResponse, UsbCcidDevice};
use crate::transport::{Transport, TransportError};
use alloc::vec::Vec;

/// Adaptador que encapsula um [`UsbCcidDevice`] e gerencia APDU frames.
#[cfg(feature = "embedded")]
pub struct FramedCcidTransport<D: UsbCcidDevice> {
    device: D,
    initialized: bool,
}

#[cfg(feature = "embedded")]
impl<D: UsbCcidDevice> FramedCcidTransport<D> {
    /// Cria uma nova instância a partir de um dispositivo CCID concreto.
    pub fn new(device: D) -> Self {
        Self {
            device,
            initialized: false,
        }
    }

    /// Retorna uma referência ao dispositivo CCID subjacente.
    pub fn device(&self) -> &D {
        &self.device
    }

    /// Retorna uma referência mutável ao dispositivo CCID subjacente.
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }
}

#[cfg(feature = "embedded")]
impl<D: UsbCcidDevice + Send + Sync> Transport for FramedCcidTransport<D> {
    fn init(&mut self) -> Result<(), TransportError> {
        self.device.init().map_err(TransportError::from)?;
        self.initialized = true;
        Ok(())
    }

    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        if !self.initialized {
            return Err(TransportError::NotInitialized);
        }

        let resp = ApduResponse::success(data.to_vec());
        let apdu_bytes = resp.to_bytes();

        self.device
            .send_ccid_block(&apdu_bytes)
            .map_err(TransportError::from)?;

        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        if !self.initialized {
            return Err(TransportError::NotInitialized);
        }

        let mut buf = vec![0u8; self.device.max_transfer_size()];
        let len = self
            .device
            .recv_ccid_block(&mut buf)
            .map_err(TransportError::from)?;

        let apdu = ApduCommand::parse(&buf[..len]).map_err(TransportError::from)?;

        Ok(apdu.data)
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

    struct MockCcid {
        sent_blocks: Vec<Vec<u8>>,
        recv_data: Vec<u8>,
        initialized: bool,
    }

    impl MockCcid {
        fn new(recv_data: Vec<u8>) -> Self {
            Self {
                sent_blocks: Vec::new(),
                recv_data,
                initialized: false,
            }
        }
    }

    impl UsbCcidDevice for MockCcid {
        fn init(&mut self) -> Result<(), EmbeddedTransportError> {
            self.initialized = true;
            Ok(())
        }

        fn send_ccid_block(&mut self, buf: &[u8]) -> Result<(), EmbeddedTransportError> {
            if !self.initialized {
                return Err(EmbeddedTransportError::NotInitialized);
            }
            self.sent_blocks.push(buf.to_vec());
            Ok(())
        }

        fn recv_ccid_block(&mut self, buf: &mut [u8]) -> Result<usize, EmbeddedTransportError> {
            if !self.initialized {
                return Err(EmbeddedTransportError::NotInitialized);
            }
            if self.recv_data.is_empty() {
                return Err(EmbeddedTransportError::Timeout);
            }
            let len = self.recv_data.len();
            buf[..len].copy_from_slice(&self.recv_data);
            Ok(len)
        }
    }

    #[test]
    fn test_framed_ccid_send_recv() {
        // Raw APDU: CLA=0x00 INS=0x10 P1=0x00 P2=0x00 Lc=0x03 Data=[1,2,3]
        let raw_apdu = vec![0x00, 0x10, 0x00, 0x00, 0x03, 1, 2, 3];
        let mock = MockCcid::new(raw_apdu);
        let mut transport = FramedCcidTransport::new(mock);
        transport.init().unwrap();

        let received = transport.recv().unwrap();
        assert_eq!(received, vec![1, 2, 3]);

        transport.send(&[4, 5, 6]).unwrap();
        let sent = &transport.device().sent_blocks[0];
        // Expect data + SW1(0x90) + SW2(0x00)
        assert_eq!(sent, &vec![4, 5, 6, 0x90, 0x00]);
    }
}
