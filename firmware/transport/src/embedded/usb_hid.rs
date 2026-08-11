//! USB-HID transport contract for embedded targets.
//!
//! The CTAPHID protocol (CTAP2 §8.2.4) frames messages as interrupt transfers:
//!
//! - Fixed-size packets (typically 64 bytes on FS USB)
//! - 4-byte header: channel_id (u16) + command/seq (u8) + packet_len (u16)
//! - Continuation packets have sequence numbers 0..N
//!
//! This trait abstracts the USB peripheral so the transport layer can
//! implement framing without knowing the hardware.

use super::EmbeddedTransportError;
use embedded_hal::digital::OutputPin;

/// USB-HID device operations required by the transport layer.
///
/// Implement this trait for a board's USB peripheral. The transport layer
/// handles CTAPHID framing; this trait provides raw interrupt transfers.
///
/// # Example
///
/// ```ignore
/// struct Rp2350Usb {
///     usb: USB,
///     gpio: Pin,
/// }
///
/// impl UsbHidDevice for Rp2350Usb {
///     fn init(&mut self) -> Result<(), EmbeddedTransportError> { ... }
///     fn send_packet(&mut self, buf: &[u8]) -> Result<(), EmbeddedTransportError> { ... }
///     fn recv_packet(&mut self, buf: &mut [u8]) -> Result<usize, EmbeddedTransportError> { ... }
///     fn packet_size(&self) -> usize { 64 }
///     fn set_led(&mut self, on: bool) -> Result<(), EmbeddedTransportError> { ... }
/// }
/// ```
pub trait UsbHidDevice {
    /// Initialize the USB peripheral (clocks, pins, endpoints).
    ///
    /// Called once before any transfer. Must enable interrupts and
    /// prepare the IN/OUT endpoints for interrupt transfers.
    fn init(&mut self) -> Result<(), EmbeddedTransportError>;

    /// Send a single interrupt IN packet to the host.
    ///
    /// `buf` is at most [`Self::packet_size()`] bytes. Blocks until
    /// the packet is acknowledged or returns an error.
    fn send_packet(&mut self, buf: &[u8]) -> Result<(), EmbeddedTransportError>;

    /// Receive a single interrupt OUT packet from the host.
    ///
    /// Returns the number of bytes written to `buf`. `buf` must be at
    /// least [`Self::packet_size()`] bytes. Blocks until a packet arrives
    /// or returns `Timeout` if no packet within the deadline.
    fn recv_packet(&mut self, buf: &mut [u8]) -> Result<usize, EmbeddedTransportError>;

    /// Maximum packet size in bytes (typically 64 for FS USB).
    fn packet_size(&self) -> usize;

    /// Indicate whether the USB device is configured by the host.
    fn is_configured(&self) -> bool {
        true
    }

    /// Set the LED indicator (optional, for user presence feedback).
    fn set_led(&mut self, _on: bool) -> Result<(), EmbeddedTransportError> {
        Ok(())
    }

    /// Reset the USB peripheral (bus reset, re-enumerate).
    fn reset(&mut self) -> Result<(), EmbeddedTransportError> {
        self.init()
    }
}

/// Status LED indicator for user presence signaling.
///
/// Wraps an [`OutputPin`] and provides a simple on/off interface.
/// The transport layer blinks the LED during CTAPHID transactions.
pub struct StatusLed<P: OutputPin> {
    pub(crate) pin: P,
    active_high: bool,
}

impl<P: OutputPin> StatusLed<P> {
    /// Creates a new status LED on the given pin.
    ///
    /// `active_high` determines whether `set_high()` turns the LED on.
    pub fn new(pin: P, active_high: bool) -> Self {
        Self { pin, active_high }
    }

    /// Turns the LED on.
    pub fn on(&mut self) -> Result<(), P::Error> {
        if self.active_high {
            self.pin.set_high()
        } else {
            self.pin.set_low()
        }
    }

    /// Turns the LED off.
    pub fn off(&mut self) -> Result<(), P::Error> {
        if self.active_high {
            self.pin.set_low()
        } else {
            self.pin.set_high()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_hal::digital::{ErrorType, OutputPin};

    #[derive(Debug)]
    struct TestPin {
        state: bool,
    }

    impl ErrorType for TestPin {
        type Error = core::convert::Infallible;
    }

    impl OutputPin for TestPin {
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
    fn test_status_led_active_high() {
        let pin = TestPin { state: false };
        let mut led = StatusLed::new(pin, true);
        led.on().unwrap();
        assert!(led.pin.state);
        led.off().unwrap();
        assert!(!led.pin.state);
    }

    #[test]
    fn test_status_led_active_low() {
        let pin = TestPin { state: true };
        let mut led = StatusLed::new(pin, false);
        led.on().unwrap();
        assert!(!led.pin.state);
        led.off().unwrap();
        assert!(led.pin.state);
    }

    #[test]
    fn test_error_conversion() {
        use crate::TransportError;

        let err: TransportError = EmbeddedTransportError::BufferTooSmall.into();
        assert!(matches!(err, TransportError::SendError(_)));

        let err: TransportError = EmbeddedTransportError::Timeout.into();
        assert!(matches!(err, TransportError::RecvError(_)));
    }
}
