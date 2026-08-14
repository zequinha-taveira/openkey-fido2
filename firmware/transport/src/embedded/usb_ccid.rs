//! USB-CCID (Smart Card / Integrated Circuit Card Devices) contract for embedded targets.
//!
//! CCID encapsulates APDU (Application Protocol Data Unit) frames defined in ISO/IEC 7816-4.
//! FIDO2/CTAP2 over CCID uses short and extended length APDU commands.

use super::EmbeddedTransportError;
use alloc::vec::Vec;

/// ISO 7816-4 APDU Command structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApduCommand {
    /// Class byte (CLA).
    pub cla: u8,
    /// Instruction byte (INS).
    pub ins: u8,
    /// Parameter 1 (P1).
    pub p1: u8,
    /// Parameter 2 (P2).
    pub p2: u8,
    /// Command payload (Data).
    pub data: Vec<u8>,
    /// Expected maximum response length (Le), if specified.
    pub le: Option<usize>,
}

impl ApduCommand {
    /// Parses a raw APDU command byte buffer.
    pub fn parse(raw: &[u8]) -> Result<Self, EmbeddedTransportError> {
        if raw.len() < 4 {
            return Err(EmbeddedTransportError::FramingError);
        }

        let cla = raw[0];
        let ins = raw[1];
        let p1 = raw[2];
        let p2 = raw[3];

        if raw.len() == 4 {
            // Case 1: CLA INS P1 P2
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: None,
            });
        }

        let len = raw.len();
        if len == 5 {
            // Case 2S: CLA INS P1 P2 Le
            let le = if raw[4] == 0 { 256 } else { raw[4] as usize };
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: Some(le),
            });
        }

        let lc = raw[4] as usize;
        if lc > 0 && 5 + lc <= len {
            let data = raw[5..5 + lc].to_vec();
            let le = if len > 5 + lc {
                let le_byte = raw[5 + lc];
                Some(if le_byte == 0 { 256 } else { le_byte as usize })
            } else {
                None
            };

            Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data,
                le,
            })
        } else {
            // Extended APDU or direct data block
            let data = raw[4..].to_vec();
            Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data,
                le: None,
            })
        }
    }
}

/// ISO 7816-4 APDU Response structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApduResponse {
    /// Response payload data.
    pub data: Vec<u8>,
    /// Status Word 1 (e.g. 0x90).
    pub sw1: u8,
    /// Status Word 2 (e.g. 0x00 for Success).
    pub sw2: u8,
}

impl ApduResponse {
    /// Creates a success response (0x9000).
    pub fn success(data: Vec<u8>) -> Self {
        Self {
            data,
            sw1: 0x90,
            sw2: 0x00,
        }
    }

    /// Creates an error response with given status words.
    pub fn error(sw1: u8, sw2: u8) -> Self {
        Self {
            data: Vec::new(),
            sw1,
            sw2,
        }
    }

    /// Serializes response to raw bytes `[DATA | SW1 | SW2]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.data.len() + 2);
        out.extend_from_slice(&self.data);
        out.push(self.sw1);
        out.push(self.sw2);
        out
    }
}

/// USB-CCID smart card peripheral operations contract.
pub trait UsbCcidDevice {
    /// Initialize the CCID endpoint.
    fn init(&mut self) -> Result<(), EmbeddedTransportError>;

    /// Send a CCID bulk IN message to host.
    fn send_ccid_block(&mut self, buf: &[u8]) -> Result<(), EmbeddedTransportError>;

    /// Receive a CCID bulk OUT message from host.
    fn recv_ccid_block(&mut self, buf: &mut [u8]) -> Result<usize, EmbeddedTransportError>;

    /// Maximum CCID transfer size.
    fn max_transfer_size(&self) -> usize {
        1024
    }

    /// Returns whether the CCID interface is ready.
    fn is_ready(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apdu_parse_simple() {
        let raw = [
            0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,
        ];
        let apdu = ApduCommand::parse(&raw).unwrap();
        assert_eq!(apdu.cla, 0x00);
        assert_eq!(apdu.ins, 0xA4);
        assert_eq!(apdu.p1, 0x04);
        assert_eq!(apdu.p2, 0x00);
        assert_eq!(apdu.data, &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
    }

    #[test]
    fn test_apdu_response_success() {
        let resp = ApduResponse::success(vec![1, 2, 3]);
        let bytes = resp.to_bytes();
        assert_eq!(bytes, vec![1, 2, 3, 0x90, 0x00]);
    }
}
