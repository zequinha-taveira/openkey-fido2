//! NFC Contactless (ISO/IEC 14443-4 Type A/B T=CL) contract for embedded targets.

use super::EmbeddedTransportError;

/// Contactless NFC Type 4 Tag / ISO 14443-4 target peripheral contract.
pub trait NfcDevice {
    /// Initialize the NFC radio peripheral and configure tag type 4 emulation.
    fn init(&mut self) -> Result<(), EmbeddedTransportError>;

    /// Indicates whether an external RF field is detected.
    fn is_field_detected(&self) -> bool;

    /// Sends an ISO 14443-4 APDU response frame to the contactless reader.
    fn send_apdu_response(&mut self, response: &[u8]) -> Result<(), EmbeddedTransportError>;

    /// Receives an ISO 14443-4 APDU command frame from the contactless reader.
    fn recv_apdu_command(&mut self, buf: &mut [u8]) -> Result<usize, EmbeddedTransportError>;

    /// Puts the NFC peripheral into low power / sleep mode.
    fn sleep(&mut self) -> Result<(), EmbeddedTransportError> {
        Ok(())
    }
}
