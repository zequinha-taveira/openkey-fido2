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
//! ambas as interfaces nos flavors padrão e `yubikey5-identity`/`yubikey4-identity`
//! (família YubiKey 4/5, mesmo `1050:0407`, ADR-0025).
//!
//! O loop de polling é não bloqueante: cada ciclo chama o stack uma única
//! vez e processa as classes; quem consome os pacotes é o chamador via os
//! acessores públicos (`hid.recv_report`/`send_report`,
//! `ccid.take_pending_request`/`send_response`).

use usb_device::bus::{UsbBus, UsbBusAllocator};
use usb_device::device::{StringDescriptors, UsbDevice, UsbDeviceBuilder, UsbVidPid};

use device_profile::{UsbIdentity as DeviceUsbIdentity, UsbVendorPreset};
use transport::embedded::{CcidClass, CtapHidClass};

/// Identidade USB completa do dispositivo composto (VID/PID + strings).
///
/// Valores derivados dos presets de `device_profile::UsbIdentity` (fonte
/// única de verdade); este struct apenas acrescenta o serial honesto
/// (`openkey`) para o builder do `usb-device`.
pub struct UsbIdentity {
    pub vid: u16,
    pub pid: u16,
    pub manufacturer: &'static str,
    pub product: &'static str,
    pub serial: &'static str,
}

impl UsbIdentity {
    /// Deriva a identidade USB do preset de fornecedor (VID/PID +
    /// manufacturer/product de `device_profile`; serial `openkey`).
    pub const fn from_preset(preset: UsbVendorPreset) -> Self {
        let id = DeviceUsbIdentity::preset(preset);
        Self {
            vid: id.vid,
            pid: id.pid,
            manufacturer: id.manufacturer,
            product: id.product,
            serial: "openkey",
        }
    }
}

/// Identidade própria do projeto (pid.codes) — padrão dos builds distribuídos.
/// The default USB identity pid.codes is 0x1209:0x0001.
pub const OPENKEY_IDENTITY: UsbIdentity =
    UsbIdentity::from_preset(UsbVendorPreset::OpenKey);

/// Identidade opt-in YubiKey 5 — VID:PID `1050:0407` + strings do preset
/// `device_profile::UsbIdentity::yubikey()`.
///
/// The default USB identity pid.codes is 0x1209:0x0001; the YubiKey USB identity
/// that ykman / Yubico Authenticator auto-recognize is the opt-in VID:PID=Yubikey5
/// build, not for distribution.
///
/// O flavor `yubikey5-identity` troca TODA a identidade — números e strings —
/// para reconhecimento automático por ykman/Yubico Authenticator (casamento
/// por VID/PID + substring `yubico`+`yubikey` no nome do reader PCSC).
/// Família YubiKey 4/5 no modo OTP+FIDO+CCID (`0407`; `board_generic::YUBIKEY_4_5`,
/// `device_profile::UsbIdentity::yubikey()`). Feature `yubikey4-identity` é
/// alias de `yubikey5-identity` (ADR-0025). VID:PID de terceiro — **NÃO PARA
/// DISTRIBUIÇÃO**; builds publicados usam [`OPENKEY_IDENTITY`]. Serial
/// permanece honesto (`openkey`).
#[cfg(feature = "yubikey5-identity")]
pub const ACTIVE_IDENTITY: UsbIdentity =
    UsbIdentity::from_preset(UsbVendorPreset::YubiKey5);

/// Identidade ativa sem o flavor opt-in.
#[cfg(not(feature = "yubikey5-identity"))]
pub const ACTIVE_IDENTITY: UsbIdentity = OPENKEY_IDENTITY;

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
    /// o escopo de `main`). A mesma identidade cobre as duas interfaces —
    /// exatamente como num YubiKey real.
    pub fn new(alloc: &'a UsbBusAllocator<B>, identity: &UsbIdentity) -> Self {
        // Ordem de alocação define a numeração: interface 0 = HID, 1 = CCID.
        let hid = CtapHidClass::new(alloc);
        let ccid = CcidClass::new(alloc);

        let usb_dev = UsbDeviceBuilder::new(alloc, UsbVidPid(identity.vid, identity.pid))
            .strings(&[StringDescriptors::default()
                .manufacturer(identity.manufacturer)
                .product(identity.product)
                .serial_number(identity.serial)])
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
