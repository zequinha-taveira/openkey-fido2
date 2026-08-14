//! Adaptador de transporte USB-HID com suporte a framing CTAPHID sobre qualquer [`UsbHidDevice`].

use crate::ctaphid::assembler::CtaphidAssembler;
use crate::ctaphid::fragmenter::CtaphidFragmenter;
use crate::ctaphid::types::{CtaphidCommand, CTAPHID_PACKET_SIZE};
#[cfg(feature = "embedded")]
use crate::embedded::UsbHidDevice;
use crate::transport::{Transport, TransportError};
use alloc::string::ToString;
use alloc::vec::Vec;

/// Adaptador que encapsula um [`UsbHidDevice`] e gerencia o framing CTAPHID.
#[cfg(feature = "embedded")]
pub struct FramedUsbHidTransport<D: UsbHidDevice> {
    device: D,
    assembler: CtaphidAssembler,
    active_cid: u32,
    initialized: bool,
}

#[cfg(feature = "embedded")]
impl<D: UsbHidDevice> FramedUsbHidTransport<D> {
    /// Cria uma nova instância a partir de um dispositivo USB-HID concreto.
    pub fn new(device: D) -> Self {
        Self {
            device,
            assembler: CtaphidAssembler::new(),
            active_cid: 0x00010001,
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

    /// Define o Channel ID ativo para as próximas transmissões.
    pub fn set_cid(&mut self, cid: u32) {
        self.active_cid = cid;
    }

    /// Retorna o Channel ID atualmente ativo.
    pub fn cid(&self) -> u32 {
        self.active_cid
    }
}

#[cfg(feature = "embedded")]
impl<D: UsbHidDevice + Send + Sync> Transport for FramedUsbHidTransport<D> {
    fn init(&mut self) -> Result<(), TransportError> {
        self.device.init().map_err(TransportError::from)?;
        self.assembler.reset();
        self.initialized = true;
        Ok(())
    }

    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        if !self.initialized {
            return Err(TransportError::NotInitialized);
        }

        let packets = CtaphidFragmenter::fragment(self.active_cid, CtaphidCommand::Cbor, data)
            .map_err(|e| TransportError::SendError(e.to_string()))?;

        for pkt in packets {
            self.device
                .send_packet(&pkt)
                .map_err(TransportError::from)?;
        }

        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        if !self.initialized {
            return Err(TransportError::NotInitialized);
        }

        let mut raw_buf = [0u8; CTAPHID_PACKET_SIZE];

        loop {
            let bytes_read = self
                .device
                .recv_packet(&mut raw_buf)
                .map_err(TransportError::from)?;

            if bytes_read != CTAPHID_PACKET_SIZE {
                return Err(TransportError::RecvError(
                    "incomplete USB-HID packet received".to_string(),
                ));
            }

            match self.assembler.process_packet(&raw_buf) {
                Ok(Some(msg)) => {
                    self.active_cid = msg.cid;
                    return Ok(msg.payload);
                }
                Ok(None) => {
                    // Mais pacotes CONT são necessários, continua lendo do endpoint
                    continue;
                }
                Err((_cid, err)) => {
                    return Err(TransportError::RecvError(format!(
                        "CTAPHID assembly error: {:?}",
                        err
                    )));
                }
            }
        }
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.assembler.reset();
        self.initialized = false;
        Ok(())
    }
}

#[cfg(all(test, feature = "embedded"))]
mod tests {
    use super::*;
    use crate::ctaphid::fragmenter::CtaphidFragmenter;
    use crate::ctaphid::types::CtaphidCommand;
    use crate::embedded::EmbeddedTransportError;
    use alloc::collections::VecDeque;

    struct MockUsbHid {
        in_packets: Vec<[u8; 64]>,
        out_packets: VecDeque<[u8; 64]>,
        initialized: bool,
    }

    impl MockUsbHid {
        fn new() -> Self {
            Self {
                in_packets: Vec::new(),
                out_packets: VecDeque::new(),
                initialized: false,
            }
        }

        fn queue_packet(&mut self, pkt: [u8; 64]) {
            self.out_packets.push_back(pkt);
        }
    }

    impl UsbHidDevice for MockUsbHid {
        fn init(&mut self) -> Result<(), EmbeddedTransportError> {
            self.initialized = true;
            Ok(())
        }

        fn send_packet(&mut self, buf: &[u8]) -> Result<(), EmbeddedTransportError> {
            if !self.initialized {
                return Err(EmbeddedTransportError::NotInitialized);
            }
            let mut pkt = [0u8; 64];
            pkt[..buf.len()].copy_from_slice(buf);
            self.in_packets.push(pkt);
            Ok(())
        }

        fn recv_packet(&mut self, buf: &mut [u8]) -> Result<usize, EmbeddedTransportError> {
            if !self.initialized {
                return Err(EmbeddedTransportError::NotInitialized);
            }
            if let Some(pkt) = self.out_packets.pop_front() {
                buf[..64].copy_from_slice(&pkt);
                Ok(64)
            } else {
                Err(EmbeddedTransportError::Timeout)
            }
        }

        fn packet_size(&self) -> usize {
            64
        }
    }

    #[test]
    fn test_framed_usb_hid_send_multi_packet() {
        let mock = MockUsbHid::new();
        let mut transport = FramedUsbHidTransport::new(mock);
        transport.init().unwrap();

        let data = vec![0xAB; 120];
        transport.send(&data).unwrap();

        // 120 bytes: 1 INIT packet (57B) + 1 CONT packet (59B) + 1 CONT packet (4B) = 3 packets
        assert_eq!(transport.device().in_packets.len(), 3);
    }

    #[test]
    fn test_framed_usb_hid_recv_roundtrip() {
        let mut mock = MockUsbHid::new();
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let pkts = CtaphidFragmenter::fragment(0x44332211, CtaphidCommand::Cbor, &payload).unwrap();

        for pkt in pkts {
            mock.queue_packet(pkt);
        }

        let mut transport = FramedUsbHidTransport::new(mock);
        transport.init().unwrap();

        let received = transport.recv().unwrap();
        assert_eq!(received, payload);
        assert_eq!(transport.cid(), 0x44332211);
    }
}
