//! Reference USB-HID implementation for the RP2350 (Raspberry Pi).
//!
//! This module provides a concrete implementation of [`super::UsbHidDevice`]
//! for the RP2350's USB peripheral. It demonstrates how to bridge the
//! embedded-hal traits to the CTAPHID transport.
//!
//! # Architecture
//!
//! ```text
//! Host <--USB--> RP2350 USB peripheral
//!                     |
//!                     v
//!              Rp2350UsbHid (implements UsbHidDevice)
//!                     |
//!                     v
//!              UsbHidTransport (CTAPHID framing)
//!                     |
//!                     v
//!              Transport trait (object-safe)
//! ```

use super::usb_hid::StatusLed;
use super::{EmbeddedTransportError, UsbHidDevice};
use embedded_hal::digital::OutputPin;

/// RP2350 USB-HID device implementation.
///
/// Wraps the RP2350 USB peripheral and provides the [`UsbHidDevice`] trait
/// implementation. This is a reference — real implementations need to
/// configure clocks, GPIO, and USB interrupts.
///
/// # Example
///
/// ```ignore
/// let usb_periph = pac::USB::take().unwrap();
/// let led = pins.gpio25.into_push_pull_output();
/// let mut hid = Rp2350UsbHid::new(usb_periph, led);
/// hid.init().expect("USB init failed");
/// ```
pub struct Rp2350UsbHid<'a, P: OutputPin> {
    /// RP2350 USB peripheral (placeholder — real impl uses `rp2350-hal`).
    _usb: Rp2350UsbPeriph,
    /// Status LED for user presence signaling.
    led: StatusLed<P>,
    /// Packet buffer for interrupt transfers.
    buf: [u8; 64],
    /// Initialized flag.
    initialized: bool,
    /// Phantom lifetime for the LED pin.
    _lifetime: core::marker::PhantomData<&'a ()>,
}

/// Placeholder for the RP2350 USB peripheral.
///
/// In a real implementation, this would be `rp2350_hal::usb::UsbBus` or
/// a raw peripheral access via `rp2350-pac`.
pub struct Rp2350UsbPeriph;

impl Rp2350UsbPeriph {
    /// Creates a placeholder peripheral instance.
    ///
    /// In real code, this would be obtained from `pac::USB::take()`.
    pub fn new() -> Self {
        Self
    }

    /// Enables USB clocks and initializes the peripheral.
    fn init_peripheral(&mut self) {
        // Real implementation:
        // 1. Enable USB clock via CLOCKS
        // 2. Configure GPIO for USB D+/D-
        // 3. Set up USB DPRAM
        // 4. Enable USB interrupt
    }

    /// Writes a packet to the IN endpoint buffer.
    fn write_in_endpoint(&mut self, _buf: &[u8]) {
        // Real implementation: write to USB DPRAM EP buffer
    }

    /// Reads a packet from the OUT endpoint buffer.
    fn read_out_endpoint(&mut self, _buf: &mut [u8]) -> usize {
        // Real implementation: read from USB DPRAM EP buffer
        0
    }

    /// Checks if USB bus is configured by host.
    fn is_configured(&self) -> bool {
        // Real implementation: check SIE_STATUS register
        false
    }
}

impl Default for Rp2350UsbPeriph {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, P: OutputPin> Rp2350UsbHid<'a, P> {
    /// Creates a new RP2350 USB-HID device.
    ///
    /// # Arguments
    ///
    /// * `_usb` — the RP2350 USB peripheral (placeholder)
    /// * `led` — status LED pin (active-high)
    pub fn new(_usb: Rp2350UsbPeriph, led: P) -> Self {
        Self {
            _usb,
            led: StatusLed::new(led, true),
            buf: [0u8; 64],
            initialized: false,
            _lifetime: core::marker::PhantomData,
        }
    }

    /// Returns whether the device has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl<'a, P: OutputPin> UsbHidDevice for Rp2350UsbHid<'a, P> {
    fn init(&mut self) -> Result<(), EmbeddedTransportError> {
        self._usb.init_peripheral();
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
        self._usb.write_in_endpoint(&self.buf[..buf.len()]);
        Ok(())
    }

    fn recv_packet(&mut self, buf: &mut [u8]) -> Result<usize, EmbeddedTransportError> {
        if !self.initialized {
            return Err(EmbeddedTransportError::NotInitialized);
        }
        if buf.len() < 64 {
            return Err(EmbeddedTransportError::BufferTooSmall);
        }
        let len = self._usb.read_out_endpoint(&mut self.buf);
        if len > 0 {
            buf[..len].copy_from_slice(&self.buf[..len]);
            Ok(len)
        } else {
            Err(EmbeddedTransportError::Timeout)
        }
    }

    fn packet_size(&self) -> usize {
        64
    }

    fn is_configured(&self) -> bool {
        self._usb.is_configured()
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
    fn test_rp2350_create() {
        let usb = Rp2350UsbPeriph::new();
        let pin = TestPin { state: false };
        let hid = Rp2350UsbHid::new(usb, pin);
        assert!(!hid.is_initialized());
        assert_eq!(hid.packet_size(), 64);
    }

    #[test]
    fn test_rp2350_init() {
        let usb = Rp2350UsbPeriph::new();
        let pin = TestPin { state: false };
        let mut hid = Rp2350UsbHid::new(usb, pin);
        hid.init().unwrap();
        assert!(hid.is_initialized());
    }

    #[test]
    fn test_rp2350_send_before_init() {
        let usb = Rp2350UsbPeriph::new();
        let pin = TestPin { state: false };
        let mut hid = Rp2350UsbHid::new(usb, pin);
        let result = hid.send_packet(b"test");
        assert!(matches!(
            result,
            Err(EmbeddedTransportError::NotInitialized)
        ));
    }

    #[test]
    fn test_rp2350_send_after_init() {
        let usb = Rp2350UsbPeriph::new();
        let pin = TestPin { state: false };
        let mut hid = Rp2350UsbHid::new(usb, pin);
        hid.init().unwrap();
        let result = hid.send_packet(b"test");
        assert!(result.is_ok());
    }

    #[test]
    fn test_rp2350_recv_timeout() {
        let usb = Rp2350UsbPeriph::new();
        let pin = TestPin { state: false };
        let mut hid = Rp2350UsbHid::new(usb, pin);
        hid.init().unwrap();
        let mut buf = [0u8; 64];
        let result = hid.recv_packet(&mut buf);
        assert!(matches!(result, Err(EmbeddedTransportError::Timeout)));
    }

    #[test]
    fn test_rp2350_buffer_too_small() {
        let usb = Rp2350UsbPeriph::new();
        let pin = TestPin { state: false };
        let mut hid = Rp2350UsbHid::new(usb, pin);
        hid.init().unwrap();
        let mut buf = [0u8; 32];
        let result = hid.recv_packet(&mut buf);
        assert!(matches!(
            result,
            Err(EmbeddedTransportError::BufferTooSmall)
        ));
    }

    #[test]
    fn test_rp2350_set_led() {
        let usb = Rp2350UsbPeriph::new();
        let pin = TestPin { state: false };
        let mut hid = Rp2350UsbHid::new(usb, pin);
        hid.init().unwrap();
        hid.set_led(true).unwrap();
        assert!(hid.led.pin.state);
        hid.set_led(false).unwrap();
        assert!(!hid.led.pin.state);
    }
}
