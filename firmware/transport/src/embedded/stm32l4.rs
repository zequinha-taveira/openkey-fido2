//! Reference transport implementation for the STMicroelectronics STM32L4.
//!
//! Provides [`Stm32l4UsbHid`] for the STM32 USB 2.0 Full-Speed device peripheral (PMA).

use super::usb_hid::StatusLed;
use super::{EmbeddedTransportError, UsbHidDevice};
use embedded_hal::digital::OutputPin;

/// STM32L4 USB FS device reference implementation.
pub struct Stm32l4UsbHid<'a, P: OutputPin> {
    led: StatusLed<P>,
    buf: [u8; 64],
    initialized: bool,
    _lifetime: core::marker::PhantomData<&'a ()>,
}

impl<'a, P: OutputPin> Stm32l4UsbHid<'a, P> {
    /// Creates a new STM32L4 USB-HID device instance.
    pub fn new(led: P) -> Self {
        Self {
            led: StatusLed::new(led, true),
            buf: [0u8; 64],
            initialized: false,
            _lifetime: core::marker::PhantomData,
        }
    }

    /// Indicates whether the USB peripheral has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl<'a, P: OutputPin> UsbHidDevice for Stm32l4UsbHid<'a, P> {
    fn init(&mut self) -> Result<(), EmbeddedTransportError> {
        // Real implementation:
        // 1. Enable RCC.APB1ENR1.USBFSEN clock and HSI48 / PLLSAI1
        // 2. Configure USB Packet Memory Area (PMA) buffers for EP1 IN/OUT
        // 3. Set USB_CNTR and clear power-down
        // 4. Configure pull-up on D+ via USB_BCDR
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
        // Real implementation: copy to PMA and toggle EP1 TX status to VALID
        Ok(())
    }

    fn recv_packet(&mut self, buf: &mut [u8]) -> Result<usize, EmbeddedTransportError> {
        if !self.initialized {
            return Err(EmbeddedTransportError::NotInitialized);
        }
        if buf.len() < 64 {
            return Err(EmbeddedTransportError::BufferTooSmall);
        }
        // Real implementation: read from PMA when CTR_RX flag is set
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
    fn test_stm32l4_usb_lifecycle() {
        let pin = DummyPin { state: false };
        let mut usb = Stm32l4UsbHid::new(pin);
        assert!(!usb.is_initialized());
        assert_eq!(usb.packet_size(), 64);
        assert!(usb.init().is_ok());
        assert!(usb.is_initialized());
        assert!(usb.send_packet(b"test").is_ok());
        assert!(usb.set_led(true).is_ok());
    }
}
