use log::info;
use transport::{Transport, TransportError};

/// Custom transport that logs frames instead of sending them over the wire.
///
/// Demonstrates how to implement the [`Transport`] trait for a new physical
/// bus or a mock for testing.
struct LoggingTransport {
    initialized: bool,
    sent_frames: Vec<Vec<u8>>,
}

impl LoggingTransport {
    fn new() -> Self {
        Self {
            initialized: false,
            sent_frames: Vec::new(),
        }
    }
}

impl Transport for LoggingTransport {
    fn init(&mut self) -> Result<(), TransportError> {
        self.initialized = true;
        Ok(())
    }

    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        if !self.initialized {
            return Err(TransportError::NotInitialized);
        }
        self.sent_frames.push(data.to_vec());
        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        if !self.initialized {
            return Err(TransportError::NotInitialized);
        }
        Ok(vec![0x00, 0x00, 0x00, 0x00])
    }

    fn close(&mut self) -> Result<(), TransportError> {
        self.initialized = false;
        Ok(())
    }
}

fn main() {
    env_logger::init();

    info!("FIDO2 Transport Example");
    info!("Demonstrates implementing a custom Transport trait.");

    let transport = LoggingTransport::new();

    // Use dyn Transport to show object safety
    let mut boxed: Box<dyn Transport> = Box::new(transport);

    info!("Transport is object-safe: can be boxed as Box<dyn Transport>");

    // Demonstrate the lifecycle
    boxed.init().expect("init failed");
    boxed.send(b"frame 1").expect("send failed");
    boxed.send(b"frame 2").expect("send failed");

    info!("Sent 2 frames via custom transport.");

    let response = boxed.recv().expect("recv failed");
    info!("Received response: {} bytes", response.len());

    boxed.close().expect("close failed");
    info!("Transport closed.");

    // Show the DummyTransport (no-op, used in tests/simulator)
    let mut dummy = transport::DummyTransport::new();
    dummy.init().expect("dummy init");
    dummy.send(b"ignored").expect("dummy send");
    let recv_result = dummy.recv().expect("dummy recv");
    info!(
        "DummyTransport recv returns empty: {}",
        recv_result.is_empty()
    );

    info!("Example complete.");
}
