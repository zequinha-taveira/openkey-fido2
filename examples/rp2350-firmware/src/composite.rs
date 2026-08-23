//! Dispositivo USB composto (FIDO HID + CCID) para o RP2350.
//!
//! Monta UM dispositivo USB com DUAS interfaces sobre o mesmo
//! `UsbBusAllocator`, à maneira de um YubiKey composto:
//!
//! - Interface 0 — HID/CTAPHID ([`CtapHidClass`], usage page FIDO `0xF1D0`)
//! - Interface 1 — CCID/smart card T=0 ([`CcidClass`])
//!
//! O [`UsbHidBackend`](transport::embedded::UsbHidBackend) original permanece
//! intacto (dispositivo de interface única); este módulo é o caminho de
//! composição alternativo que constrói o [`UsbDevice`] diretamente sobre a
//! fatia `[&mut dyn UsbClass<B>]` das duas classes. As identidades USB
//! (`USB_VID`/`USB_PID` de `main`) alimentam o único builder, valendo para
//! ambas as interfaces nos flavors padrão e `yubikey5-identity`.
//!
//! O loop de polling é não bloqueante: cada ciclo chama o stack uma única
//! vez e processa as classes; quem consome os pacotes é o chamador via os
//! acessores públicos (`hid.recv_report`/`send_report`,
//! `ccid.take_pending_request`/`send_response`).

use usb_device::bus::{UsbBus, UsbBusAllocator};
use usb_device::device::{StringDescriptors, UsbDevice, UsbDeviceBuilder, UsbVidPid};

use transport::embedded::{CcidClass, CtapHidClass};

/// Dispositivo USB composto: CTAPHID (HID) + CCID (smart card).
pub struct CompositeUsbDevice<'a, B: UsbBus> {
    usb_dev: UsbDevice<'a, B>,
    /// Interface CTAPHID (consumida diretamente pelo loop CTAPHID).
    pub hid: CtapHidClass<'a, B>,
    /// Interface CCID (stub responde 6D00 até a integração dos applets).
    pub ccid: CcidClass<'a, B>,
}

impl<'a, B: UsbBus> CompositeUsbDevice<'a, B> {
    /// Cria o dispositivo composto a partir do allocator compartilhado.
    ///
    /// O `alloc` deve viver tanto quanto o dispositivo retornado (tipicamente
    /// o escopo de `main`). A mesma identidade VID/PID cobre as duas
    /// interfaces — exatamente como num YubiKey real.
    pub fn new(alloc: &'a UsbBusAllocator<B>, vid: u16, pid: u16) -> Self {
        // Ordem de alocação define a numeração: interface 0 = HID, 1 = CCID.
        let hid = CtapHidClass::new(alloc);
        let ccid = CcidClass::new(alloc);

        let usb_dev = UsbDeviceBuilder::new(alloc, UsbVidPid(vid, pid))
            .strings(&[StringDescriptors::default()
                .manufacturer("openkey-fido2")
                .product("FIDO2 Authenticator")
                .serial_number("openkey")])
            .unwrap()
            .max_packet_size_0(64)
            .unwrap()
            .device_class(0x00) // classes definidas por interface (IAD desnecessário)
            .build();
        // No usb-device 0.3 as classes são entregues ao stack no `poll`
        // (enumeração inclusiva) — ver `Self::poll`.

        Self { usb_dev, hid, ccid }
    }

    /// Executa um ciclo de polling das duas classes (não bloqueante).
    pub fn poll(&mut self) -> bool {
        let activity = self.usb_dev.poll(&mut [&mut self.hid, &mut self.ccid]);
        self.ccid.process();
        activity
    }
}
