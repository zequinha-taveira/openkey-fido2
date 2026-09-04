//! Backend USB-HID concreto sobre o stack `usb-device`.
//!
//! Implementa [`UsbHidDevice`] sobre um [`UsbBusAllocator`] genérico
//! (`B: UsbBus`), separando o protocolo CTAPHID (report descriptors e
//! transferências de 64 bytes) do hardware USB concreto (fornecido pela HAL,
//! ex.: `rp235x_hal::usb::UsbBus`).
//!
//! O report descriptor segue a usage page FIDO Alliance (`0xF1D0`) com dois
//! reports de 64 bytes (IN e OUT), conforme exigido pelo CTAPHID (CTAP 2.1 §8.2).

use usb_device::bus::{InterfaceNumber, UsbBus, UsbBusAllocator};
use usb_device::class::{ControlIn, ControlOut, UsbClass};
use usb_device::control;
use usb_device::descriptor::DescriptorWriter;
use usb_device::device::{
    StringDescriptors, UsbDevice, UsbDeviceBuilder, UsbDeviceState, UsbVidPid,
};
use usb_device::endpoint::{EndpointAddress, EndpointIn, EndpointOut};
use usb_device::Result as UsbResult;

use super::usb_hid::UsbHidDevice;
use super::EmbeddedTransportError;

/// Tamanho do pacote USB-HID Full-Speed (CTAPHID).
const PACKET_SIZE: usize = 64;

/// Descritor de report HID para CTAPHID (usage page FIDO Alliance `0xF1D0`).
///
/// Define um report de entrada (IN) e um de saída (OUT), ambos de 64 bytes.
pub const CTAPHID_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01, // Usage (U2F/CTAPHID)
    0xA1, 0x01, // Collection (Application)
    0x09, 0x20, // Usage (Data In)
    0x15, 0x00, // Logical Minimum (0)
    0x26, 0xFF, 0x00, // Logical Maximum (255)
    0x75, 0x08, // Report Size (8)
    0x95, 0x40, // Report Count (64)
    0x81, 0x02, // Input (Data, Var, Abs)
    0x09, 0x21, // Usage (Data Out)
    0x15, 0x00, // Logical Minimum (0)
    0x26, 0xFF, 0x00, // Logical Maximum (255)
    0x75, 0x08, // Report Size (8)
    0x95, 0x40, // Report Count (64)
    0x91, 0x02, // Output (Data, Var, Abs)
    0xC0, // End Collection
];

/// Classe USB HID para CTAPHID.
///
/// Expõe um endpoint interrupt IN e um OUT, ambos de 64 bytes, e responde ao
/// pedido `GET_DESCRIPTOR` do report descriptor durante a enumeração.
pub struct CtapHidClass<'a, B: UsbBus> {
    iface: InterfaceNumber,
    ep_in: EndpointIn<'a, B>,
    ep_out: EndpointOut<'a, B>,
    /// Buffer para o último pacote recebido do host.
    out_buf: [u8; PACKET_SIZE],
    out_len: usize,
    out_ready: bool,
}

impl<'a, B: UsbBus> CtapHidClass<'a, B> {
    /// Cria a classe alocando um endpoint interrupt IN e um OUT no `alloc`.
    pub fn new(alloc: &'a UsbBusAllocator<B>) -> Self {
        Self {
            iface: alloc.interface(),
            ep_in: alloc.interrupt(PACKET_SIZE as u16, 1),
            ep_out: alloc.interrupt(PACKET_SIZE as u16, 1),
            out_buf: [0u8; PACKET_SIZE],
            out_len: 0,
            out_ready: false,
        }
    }

    /// Descritor HID de 9 bytes referenciando o report descriptor.
    fn hid_descriptor(&self) -> [u8; 9] {
        let len = CTAPHID_REPORT_DESCRIPTOR.len() as u16;
        [
            0x09, // bLength
            0x21, // bDescriptorType (HID)
            0x11,
            0x01, // bcdHID 1.11
            0x00, // bCountryCode
            0x01, // bNumDescriptors
            0x22, // bDescriptorType (Report)
            (len & 0xFF) as u8,
            (len >> 8) as u8,
        ]
    }

    /// Retira (e limpa) o pacote OUT recebido, se houver.
    fn take_data(&mut self, buf: &mut [u8]) -> Option<usize> {
        if !self.out_ready {
            return None;
        }
        let n = self.out_len;
        let m = core::cmp::min(n, buf.len());
        buf[..m].copy_from_slice(&self.out_buf[..m]);
        self.out_ready = false;
        self.out_len = 0;
        Some(m)
    }

    /// Modo composto: consome o pacote OUT recebido do host, se houver.
    ///
    /// Espelha [`UsbHidBackend::recv_packet`] sem possuir o [`UsbDevice`] —
    /// para quando esta classe é montada em conjunto com outras (ex.: HID +
    /// CCID) sobre um único dispositivo USB; o polling do stack fica sob
    /// responsabilidade do montador.
    pub fn recv_report(&mut self, buf: &mut [u8]) -> Option<usize> {
        self.take_data(buf)
    }

    /// Modo composto: envia um pacote IN ao host.
    ///
    /// Retorna `Err(BufferTooSmall)` acima de 64 bytes e `Err(SendFailed)`
    /// quando o endpoint ainda não está pronto (`WouldBlock`) — reenviar no
    /// próximo ciclo de polling.
    pub fn send_report(&mut self, buf: &[u8]) -> Result<(), EmbeddedTransportError> {
        if buf.len() > PACKET_SIZE {
            return Err(EmbeddedTransportError::BufferTooSmall);
        }
        self.ep_in
            .write(buf)
            .map(|_| ())
            .map_err(|_| EmbeddedTransportError::SendFailed)
    }
}

impl<B: UsbBus> UsbClass<B> for CtapHidClass<'_, B> {
    fn get_configuration_descriptors(&self, writer: &mut DescriptorWriter) -> UsbResult<()> {
        writer.interface(self.iface, 0x03, 0x00, 0x00)?;
        // DescriptorWriter::write já prefixa bLength (9) e bDescriptorType (0x21);
        // passa apenas o corpo de 7 bytes sem duplicar o cabeçalho.
        writer.write(0x21, &self.hid_descriptor()[2..])?;
        writer.endpoint(&self.ep_in)?;
        writer.endpoint(&self.ep_out)?;
        Ok(())
    }

    fn endpoint_out(&mut self, addr: EndpointAddress) {
        if addr == self.ep_out.address() {
            if let Ok(n) = self.ep_out.read(&mut self.out_buf) {
                self.out_len = n;
                self.out_ready = true;
            }
        }
    }

    fn control_in(&mut self, xfer: ControlIn<B>) {
        let req = *xfer.request();

        // GET_DESCRIPTOR (HID Descriptor 0x21 ou HID Report 0x22) — requisitado
        // pelo host durante a enumeração.
        if req.request_type == control::RequestType::Standard
            && req.recipient == control::Recipient::Interface
            && req.request == control::Request::GET_DESCRIPTOR
        {
            match (req.value >> 8) as u8 {
                0x21 => {
                    let desc = self.hid_descriptor();
                    let _ = xfer.accept_with(&desc);
                    return;
                }
                0x22 => {
                    let _ = xfer.accept_with(CTAPHID_REPORT_DESCRIPTOR);
                    return;
                }
                _ => {}
            }
        }

        // HID class requests IN que o driver Windows envia durante o start
        // (GET_REPORT 0x01, GET_IDLE 0x02, GET_PROTOCOL 0x03). Responder com
        // comprimento errado (ex.: ZLP onde o host espera 1..64 bytes) faz
        // CM_PROB_FAILED_START 10 no composto; CTAPHID não usa essas
        // features, então responde com payload zero NO comprimento esperado:
        // GET_REPORT → zeros até wLength (máx. 64), GET_IDLE → 1 byte 0
        // (idle indefinido), GET_PROTOCOL → 1 byte 1 (report protocol).
        if req.request_type == control::RequestType::Class
            && req.recipient == control::Recipient::Interface
        {
            match req.request {
                0x01 => {
                    // GET_REPORT (Input): zeros; nunca expõe estado interno.
                    static ZEROS: [u8; PACKET_SIZE] = [0u8; PACKET_SIZE];
                    let n = core::cmp::min(req.length as usize, PACKET_SIZE);
                    let _ = xfer.accept_with(&ZEROS[..n]);
                }
                0x02 => {
                    // GET_IDLE: 1 byte.
                    let _ = xfer.accept_with(&[0u8][..core::cmp::min(req.length as usize, 1)]);
                }
                0x03 => {
                    // GET_PROTOCOL: 1 byte, 1 = report protocol.
                    let _ = xfer.accept_with(&[1u8][..core::cmp::min(req.length as usize, 1)]);
                }
                // SET_* via IN com wLength=0 chegam aqui em alguns stacks;
                // aceitar também para não travar enumeração.
                0x09..=0x0B => {
                    let _ = xfer.accept(|_| Ok(0));
                }
                _ => {}
            }
        }
        // Demais pedidos ficam sem resposta (stall pelo framework).
    }

    fn control_out(&mut self, xfer: ControlOut<B>) {
        let req = *xfer.request();
        if req.request_type == control::RequestType::Class
            && req.recipient == control::Recipient::Interface
        {
            match req.request {
                // SET_REPORT (0x09) — CTAPHID usa interrupt OUT, não control;
                // apenas consome o estágio de dados.
                // SET_IDLE (0x0A) / SET_PROTOCOL (0x0B) — sem payload, mas
                // Windows os envia no barramento de controle durante o start.
                0x09..=0x0B => {
                    let _ = xfer.accept();
                }
                // GET_* que por algum motivo cheguem como OUT (wLength=0):
                // aceitar para não stallar.
                0x01..=0x03 => {
                    let _ = xfer.accept();
                }
                _ => {}
            }
        }
    }
}

/// Backend [`UsbHidDevice`] concreto sobre `usb-device`.
///
/// Encapsula um [`UsbDevice`] + [`CtapHidClass`] montados sobre um
/// [`UsbBusAllocator`] compartilhado. O `UsbBus` concreto (`B`) é fornecido
/// pela HAL da placa.
pub struct UsbHidBackend<'a, B: UsbBus> {
    usb_dev: UsbDevice<'a, B>,
    hid: CtapHidClass<'a, B>,
    initialized: bool,
}

impl<'a, B: UsbBus> UsbHidBackend<'a, B> {
    /// Cria o backend a partir de um `UsbBusAllocator` já montado.
    ///
    /// O `alloc` deve viver pelo menos tanto quanto o backend (tipicamente o
    /// escopo de `main`), pois `UsbDevice`/`CtapHidClass` o referenciam.
    pub fn new(alloc: &'a UsbBusAllocator<B>, vid: u16, pid: u16) -> Self {
        let hid = CtapHidClass::new(alloc);
        let usb_dev = UsbDeviceBuilder::new(alloc, UsbVidPid(vid, pid))
            .strings(&[StringDescriptors::default()
                .manufacturer("openkey-fido2")
                .product("FIDO2 Authenticator")
                .serial_number("openkey")])
            .unwrap()
            .max_packet_size_0(64)
            .unwrap()
            .device_class(0x00)
            .build();

        Self {
            usb_dev,
            hid,
            initialized: false,
        }
    }

    /// Executa um ciclo de polling do stack USB (deve ser chamado
    /// periodicamente; `recv_packet` já faz isso).
    pub fn poll(&mut self) -> bool {
        self.usb_dev.poll(&mut [&mut self.hid])
    }
}

impl<B: UsbBus> UsbHidDevice for UsbHidBackend<'_, B> {
    fn init(&mut self) -> Result<(), EmbeddedTransportError> {
        self.initialized = true;
        Ok(())
    }

    fn send_packet(&mut self, buf: &[u8]) -> Result<(), EmbeddedTransportError> {
        if !self.initialized {
            return Err(EmbeddedTransportError::NotInitialized);
        }
        if buf.len() > PACKET_SIZE {
            return Err(EmbeddedTransportError::BufferTooSmall);
        }
        self.hid
            .ep_in
            .write(buf)
            .map(|_| ())
            .map_err(|_| EmbeddedTransportError::SendFailed)
    }

    fn recv_packet(&mut self, buf: &mut [u8]) -> Result<usize, EmbeddedTransportError> {
        if !self.initialized {
            return Err(EmbeddedTransportError::NotInitialized);
        }
        self.usb_dev.poll(&mut [&mut self.hid]);
        match self.hid.take_data(buf) {
            Some(n) => Ok(n),
            None => Err(EmbeddedTransportError::Timeout),
        }
    }

    fn packet_size(&self) -> usize {
        PACKET_SIZE
    }

    fn is_configured(&self) -> bool {
        self.usb_dev.state() == UsbDeviceState::Configured
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use usb_device::bus::PollResult;
    use usb_device::endpoint::EndpointType;
    use usb_device::Result as UsbResult;
    use usb_device::UsbDirection;
    use usb_device::UsbError;

    /// Estado interno do mock de `UsbBus` (para simular o lado do host).
    struct MockInner {
        in_data: [u8; PACKET_SIZE],
        in_len: usize,
        out_data: [u8; PACKET_SIZE],
        out_len: usize,
        out_pending: bool,
        in_addr: Option<EndpointAddress>,
        out_addr: Option<EndpointAddress>,
    }

    impl Default for MockInner {
        fn default() -> Self {
            Self {
                in_data: [0; PACKET_SIZE],
                in_len: 0,
                out_data: [0; PACKET_SIZE],
                out_len: 0,
                out_pending: false,
                in_addr: None,
                out_addr: None,
            }
        }
    }

    /// Mock de `UsbBus` com estado compartilhado para os testes.
    struct MockUsbBus {
        state: Arc<Mutex<MockInner>>,
    }

    impl MockUsbBus {
        fn new(state: Arc<Mutex<MockInner>>) -> Self {
            Self { state }
        }

        fn queue_out(state: &Arc<Mutex<MockInner>>, data: &[u8]) {
            let mut inner = state.lock().unwrap();
            inner.out_data[..data.len()].copy_from_slice(data);
            inner.out_len = data.len();
            inner.out_pending = true;
        }

        fn sent(state: &Arc<Mutex<MockInner>>) -> (usize, [u8; PACKET_SIZE]) {
            let inner = state.lock().unwrap();
            (inner.in_len, inner.in_data)
        }
    }

    impl UsbBus for MockUsbBus {
        fn alloc_ep(
            &mut self,
            ep_dir: UsbDirection,
            _ep_addr: Option<EndpointAddress>,
            _ep_type: EndpointType,
            _max_packet_size: u16,
            _interval: u8,
        ) -> UsbResult<EndpointAddress> {
            let addr = EndpointAddress::from_parts(1, ep_dir);
            let mut inner = self.state.lock().unwrap();
            match ep_dir {
                UsbDirection::In => inner.in_addr = Some(addr),
                UsbDirection::Out => inner.out_addr = Some(addr),
            }
            Ok(addr)
        }

        fn enable(&mut self) {}

        fn reset(&self) {}

        fn set_device_address(&self, _addr: u8) {}

        fn write(&self, _ep_addr: EndpointAddress, buf: &[u8]) -> UsbResult<usize> {
            let mut inner = self.state.lock().unwrap();
            let n = core::cmp::min(buf.len(), PACKET_SIZE);
            inner.in_data[..n].copy_from_slice(&buf[..n]);
            inner.in_len = n;
            Ok(n)
        }

        fn read(&self, _ep_addr: EndpointAddress, buf: &mut [u8]) -> UsbResult<usize> {
            let mut inner = self.state.lock().unwrap();
            if inner.out_pending {
                let n = core::cmp::min(inner.out_len, buf.len());
                buf[..n].copy_from_slice(&inner.out_data[..n]);
                inner.out_pending = false;
                Ok(n)
            } else {
                Err(UsbError::WouldBlock)
            }
        }

        fn set_stalled(&self, _ep_addr: EndpointAddress, _stalled: bool) {}

        fn is_stalled(&self, _ep_addr: EndpointAddress) -> bool {
            false
        }

        fn suspend(&self) {}

        fn resume(&self) {}

        fn poll(&self) -> PollResult {
            let inner = self.state.lock().unwrap();
            if inner.out_pending {
                PollResult::Data {
                    ep_out: 1 << 1, // endpoint 1, direção OUT
                    ep_in_complete: 0,
                    ep_setup: 0,
                }
            } else {
                PollResult::None
            }
        }

        const QUIRK_SET_ADDRESS_BEFORE_STATUS: bool = false;
    }

    fn make_backend() -> (UsbHidBackend<'static, MockUsbBus>, Arc<Mutex<MockInner>>) {
        let state = Arc::new(Mutex::new(MockInner::default()));
        let bus = MockUsbBus::new(state.clone());
        let alloc: &'static UsbBusAllocator<MockUsbBus> =
            Box::leak(Box::new(UsbBusAllocator::new(bus)));
        let backend = UsbHidBackend::new(alloc, 0x1234, 0x5678);
        (backend, state)
    }

    #[test]
    fn test_report_descriptor_is_fido_usage_page() {
        // Usage Page (FIDO Alliance 0xF1D0) no início do descriptor.
        assert_eq!(&CTAPHID_REPORT_DESCRIPTOR[0..3], &[0x06, 0xD0, 0xF1]);
        // 34 bytes no total (padrão CTAPHID).
        assert_eq!(CTAPHID_REPORT_DESCRIPTOR.len(), 34);
    }

    #[test]
    fn test_endpoints_allocated_64_bytes() {
        let (backend, state) = make_backend();
        assert_eq!(backend.packet_size(), 64);

        let inner = state.lock().unwrap();
        assert!(inner.in_addr.is_some(), "IN endpoint deve ser alocado");
        assert!(inner.out_addr.is_some(), "OUT endpoint deve ser alocado");
        assert_eq!(inner.in_addr.unwrap().is_in(), true);
        assert_eq!(inner.out_addr.unwrap().is_out(), true);
    }

    #[test]
    fn test_send_packet_routes_to_in_endpoint() {
        let (mut backend, state) = make_backend();
        backend.init().unwrap();

        let packet = [0xABu8; 64];
        backend.send_packet(&packet).unwrap();

        let (len, data) = MockUsbBus::sent(&state);
        assert_eq!(len, 64);
        assert_eq!(&data[..], &packet[..]);
    }

    #[test]
    fn test_recv_packet_reads_from_out_endpoint() {
        let (mut backend, state) = make_backend();
        backend.init().unwrap();

        MockUsbBus::queue_out(&state, &[0xCDu8; 64]);

        let mut buf = [0u8; 64];
        let n = backend.recv_packet(&mut buf).unwrap();
        assert_eq!(n, 64);
        assert_eq!(&buf[..], &[0xCDu8; 64]);
    }

    #[test]
    fn test_recv_packet_timeout_when_empty() {
        let (mut backend, _state) = make_backend();
        backend.init().unwrap();

        let mut buf = [0u8; 64];
        let result = backend.recv_packet(&mut buf);
        assert!(matches!(result, Err(EmbeddedTransportError::Timeout)));
    }

    #[test]
    fn test_send_packet_before_init() {
        let (mut backend, _state) = make_backend();
        let result = backend.send_packet(&[0u8; 64]);
        assert!(matches!(
            result,
            Err(EmbeddedTransportError::NotInitialized)
        ));
    }

    #[test]
    fn test_hid_descriptor_layout() {
        let (backend, _state) = make_backend();
        let desc = backend.hid.hid_descriptor();
        assert_eq!(desc.len(), 9);
        assert_eq!(desc[0], 0x09); // bLength
        assert_eq!(desc[1], 0x21); // bDescriptorType (HID)
        assert_eq!(&desc[2..4], &[0x11, 0x01]); // bcdHID 1.11
        assert_eq!(desc[6], 0x22); // Report descriptor type
        let rpt_len = u16::from_le_bytes([desc[7], desc[8]]) as usize;
        assert_eq!(rpt_len, CTAPHID_REPORT_DESCRIPTOR.len());
        // O corpo passado ao DescriptorWriter::write tem 7 bytes (sem bLength/bDescriptorType):
        assert_eq!(&desc[2..], &[0x11, 0x01, 0x00, 0x01, 0x22, 0x22, 0x00]);
    }
}
