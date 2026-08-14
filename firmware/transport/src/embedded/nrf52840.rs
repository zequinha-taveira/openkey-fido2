//! Reference transport implementation for the Nordic nRF52840.
//!
//! Provides [`Nrf52840UsbHid`] for the nRF52840 USB Device peripheral (USBD)
//! and [`Nrf52840Nfc`] for the nRF52840 Near Field Communication (NFCT) peripheral.

use super::nfc::NfcDevice;
use super::usb_hid::StatusLed;
use super::{EmbeddedTransportError, UsbHidDevice};
use embedded_hal::digital::OutputPin;

/// Nordic nRF52840 USBD USB-HID reference implementation.
pub struct Nrf52840UsbHid<'a, P: OutputPin> {
    led: StatusLed<P>,
    buf: [u8; 64],
    initialized: bool,
    _lifetime: core::marker::PhantomData<&'a ()>,
}

impl<'a, P: OutputPin> Nrf52840UsbHid<'a, P> {
    /// Creates a new nRF52840 USB-HID device instance.
    pub fn new(led: P) -> Self {
        Self {
            led: StatusLed::new(led, true),
            buf: [0u8; 64],
            initialized: false,
            _lifetime: core::marker::PhantomData,
        }
    }

    /// Indicates whether the USBD peripheral has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl<'a, P: OutputPin> UsbHidDevice for Nrf52840UsbHid<'a, P> {
    fn init(&mut self) -> Result<(), EmbeddedTransportError> {
        // In real firmware:
        // 1. Enable USBD power events and HFCLK clock
        // 2. Configure EasyDMA IN/OUT endpoint descriptors
        // 3. Enable interrupts and pull-up on D+
        self.led
            .on()
            .map_err(|_| EmbeddedTransportError::SendFailed)?;
        self.initialized = true;
        Ok(())
    }

    fn send_packet(&mut self, buf: &[u8]) -> Result<(), EmbeddedTransportError> {
        if !self.initialized {
            return Err(EmbeddedTransportError::NotInitialized);
        }
        if buf.len() > self.buf.len() {
            return Err(EmbeddedTransportError::BufferTooSmall);
        }
        self.buf[..buf.len()].copy_from_slice(buf);
        // Real implementation triggers USBD.EPIN[1].START
        Ok(())
    }

    fn recv_packet(&mut self, buf: &mut [u8]) -> Result<usize, EmbeddedTransportError> {
        if !self.initialized {
            return Err(EmbeddedTransportError::NotInitialized);
        }
        if buf.len() < 64 {
            return Err(EmbeddedTransportError::BufferTooSmall);
        }
        // Real implementation waits for USBD.EPOUT[1].ENDEPOUT event
        Err(EmbeddedTransportError::Timeout)
    }

    fn packet_size(&self) -> usize {
        64
    }

    fn set_led(&mut self, on: bool) -> Result<(), EmbeddedTransportError> {
        if on { self.led.on() } else { self.led.off() }
            .map_err(|_| EmbeddedTransportError::SendFailed)
    }
}

/// Nordic nRF52840 NFCT NFC Tag Type 4 reference implementation.
pub struct Nrf52840Nfc {
    initialized: bool,
    field_present: bool,
    _buf: [u8; 512],
}

impl Nrf52840Nfc {
    /// Creates a new nRF52840 NFCT device instance.
    pub fn new() -> Self {
        Self {
            initialized: false,
            field_present: false,
            _buf: [0u8; 512],
        }
    }
}

impl Default for Nrf52840Nfc {
    fn default() -> Self {
        Self::new()
    }
}

impl NfcDevice for Nrf52840Nfc {
    fn init(&mut self) -> Result<(), EmbeddedTransportError> {
        // Real implementation:
        // 1. Configure NFCT.PACKETPTR and NFCT.MAXLEN
        // 2. Enable FIELDDETECTED and SELECTED interrupts
        // 3. Start NFCT RX task
        self.initialized = true;
        self.field_present = false;
        Ok(())
    }

    fn is_field_detected(&self) -> bool {
        self.field_present
    }

    fn send_apdu_response(&mut self, _response: &[u8]) -> Result<(), EmbeddedTransportError> {
        if !self.initialized {
            return Err(EmbeddedTransportError::NotInitialized);
        }
        Ok(())
    }

    fn recv_apdu_command(&mut self, _buf: &mut [u8]) -> Result<usize, EmbeddedTransportError> {
        if !self.initialized {
            return Err(EmbeddedTransportError::NotInitialized);
        }
        Err(EmbeddedTransportError::Timeout)
    }

    fn sleep(&mut self) -> Result<(), EmbeddedTransportError> {
        self.field_present = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_hal::digital::{ErrorType, OutputPin};

    #[derive(Debug)]
    struct DummyPin {
        state: bool,
    }

    impl ErrorType for DummyPin {
        type Error = core::convert::Infallible;
    }

    impl OutputPin for DummyPin {
        fn set_low(&mut self) -> Result<(), Self::Error> {
            self.state = false;
            Ok(())
        }
        fn set_high(&mut self) -> Result<(), Self::Error> {
            self.state = true;
            Ok(())
        }
    }

    #[test]
    fn test_nrf52840_usb_lifecycle() {
        let pin = DummyPin { state: false };
        let mut usb = Nrf52840UsbHid::new(pin);
        assert!(!usb.is_initialized());
        assert_eq!(usb.packet_size(), 64);
        assert!(usb.init().is_ok());
        assert!(usb.is_initialized());
        assert!(usb.send_packet(b"hello").is_ok());
        assert!(usb.set_led(false).is_ok());
    }

    #[test]
    fn test_nrf52840_nfc_lifecycle() {
        let mut nfc = Nrf52840Nfc::new();
        assert!(!nfc.is_field_detected());
        assert!(nfc.init().is_ok());
        assert!(nfc.sleep().is_ok());
    }
}
