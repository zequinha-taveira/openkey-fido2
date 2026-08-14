//! Boot bare-metal para o RP2350 (núcleo Arm Cortex-M33).
//!
//! Este crate é um binário `no_std` standalone (fora do workspace principal,
//! como `fuzz/`) que configura os clocks reais do RP2350 via `rp235x-hal`,
//! instala um heap alocador (`embedded-alloc`) e executa um loop de despacho
//! CTAPHID sobre as primitivas de framing/assembly do crate `transport`.
//!
//! O periférico USB real é integrado via `usb-device` (backend
//! [`transport::UsbHidBackend`] sobre `hal::usb::UsbBus` do RP2350).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use panic_halt as _;
use rp235x_hal as hal;

use embedded_alloc::LlffHeap;
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;

use usb_device::bus::UsbBusAllocator;

use transport::ctaphid::{
    ctaphid_capabilities, ChannelManager, CtaphidAssembler, CtaphidCommand, CtaphidErrorCode,
    CtaphidFragmenter, CtaphidMessage, CTAPHID_PACKET_SIZE,
};
use transport::embedded::UsbHidBackend;
use transport::embedded::UsbHidDevice;

/// Tamanho do heap em bytes (para `Vec` e estruturas alocadas do CTAPHID).
const HEAP_SIZE: usize = 8192;

/// Cristal externo de 12 MHz (Raspberry Pi Pico 2). Ajuste conforme a placa.
const XTAL_FREQ_HZ: u32 = 12_000_000u32;

/// Versão do firmware reportada no handshake `CTAPHID_INIT`.
const FW_MAJOR: u8 = 0;
const FW_MINOR: u8 = 1;
const FW_BUILD: u8 = 0;

/// VID/PID USB do dispositivo (placeholder — substituir pelo VID oficial).
const USB_VID: u16 = 0x1209; // pid.codes (VID temporário)
const USB_PID: u16 = 0x0001;

/// Alocador global de heap (linked-list first-fit via `embedded-alloc`).
#[global_allocator]
static ALLOCATOR: LlffHeap = LlffHeap::empty();

/// Bloco de início exigido pela Boot ROM do RP2350.
#[link_section = ".start_block"]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::secure_exe();

/// Metadados para `picotool info`.
#[link_section = ".bi_entries"]
#[used]
pub static PICOTOOL_ENTRIES: [hal::binary_info::EntryAddr; 5] = [
    hal::binary_info::rp_cargo_bin_name!(),
    hal::binary_info::rp_cargo_version!(),
    hal::binary_info::rp_program_description!(c"openkey-fido2 RP2350 authenticator firmware"),
    hal::binary_info::rp_cargo_homepage_url!(),
    hal::binary_info::rp_program_build_attribute!(),
];

/// Ponto de entrada. Configura clocks reais, heap e entra no loop CTAPHID.
#[hal::entry]
fn main() -> ! {
    // 1. Inicializa o heap antes de qualquer alocação.
    unsafe {
        embedded_alloc::init!(ALLOCATOR, HEAP_SIZE);
    }

    // 2. Periféricos singleton.
    let mut pac = hal::pac::Peripherals::take().unwrap();

    // 3. Watchdog — necessário pela configuração de clocks.
    let mut watchdog = hal::Watchdog::new(pac.WATCHDOG);

    // 4. Configuração real dos clocks (XOSC + PLLs); clock de sistema padrão 125 MHz.
    let clocks = hal::clocks::init_clocks_and_plls(
        XTAL_FREQ_HZ,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    )
    .unwrap();

    // 5. Timer (usado no WINK/keepalive).
    let mut timer = hal::Timer::new_timer0(pac.TIMER0, &mut pac.RESETS, &clocks);

    // 6. GPIO: LED de status (GPIO25 no Pico 2).
    let sio = hal::Sio::new(pac.SIO);
    let pins = hal::gpio::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );
    let mut led = pins.gpio25.into_push_pull_output();

    // 7. Transporte USB-HID real (usb-device sobre o periférico USB do RP2350).
    let usb_bus = UsbBusAllocator::new(hal::usb::UsbBus::new(
        pac.USB,
        pac.USB_DPRAM,
        clocks.usb_clock,
        true,
        &mut pac.RESETS,
    ));
    let mut hid = UsbHidBackend::new(&usb_bus, USB_VID, USB_PID);
    hid.init().ok();

    // 8. Estado do protocolo CTAPHID.
    let mut channels = ChannelManager::new();
    let mut assembler = CtaphidAssembler::new();

    // 9. Loop de despacho CTAPHID.
    loop {
        let mut buf = [0u8; CTAPHID_PACKET_SIZE];
        match hid.recv_packet(&mut buf) {
            Ok(_) => match assembler.process_packet(&buf) {
                Ok(Some(msg)) => {
                    let cmd = msg.cmd;
                    let (cid, resp_cmd, payload) = dispatch(&mut channels, msg);

                    if cmd == CtaphidCommand::Wink {
                        // Sinal visual de presença (LED GPIO25).
                        let _ = led.set_low();
                        timer.delay_ms(40);
                        let _ = led.set_high();
                    }

                    if let Ok(packets) = CtaphidFragmenter::fragment(cid, resp_cmd, &payload) {
                        for packet in packets {
                            let _ = hid.send_packet(&packet);
                        }
                    }
                }
                Ok(None) => {
                    // Aguardando pacotes de continuação (CONT).
                }
                Err((cid, code)) => {
                    let payload = alloc::vec![code.as_u8()];
                    if let Ok(packets) =
                        CtaphidFragmenter::fragment(cid, CtaphidCommand::Error, &payload)
                    {
                        for packet in packets {
                            let _ = hid.send_packet(&packet);
                        }
                    }
                }
            },
            Err(_) => {
                // Sem pacote no endpoint (placeholder/timeout) — continua o polling.
            }
        }
    }
}

/// Despacha uma mensagem CTAPHID completa e produz a resposta
/// `(cid, comando, payload)`.
fn dispatch(channels: &mut ChannelManager, msg: CtaphidMessage) -> (u32, CtaphidCommand, Vec<u8>) {
    match msg.cmd {
        CtaphidCommand::Init => {
            let capabilities = ctaphid_capabilities::CAPABILITY_CBOR
                | ctaphid_capabilities::CAPABILITY_WINK
                | ctaphid_capabilities::CAPABILITY_NMSG;
            let payload = channels.build_init_response(
                &msg.payload,
                FW_MAJOR,
                FW_MINOR,
                FW_BUILD,
                capabilities,
            );
            (msg.cid, CtaphidCommand::Init, payload)
        }
        CtaphidCommand::Ping => (msg.cid, CtaphidCommand::Ping, msg.payload),
        CtaphidCommand::Wink => (msg.cid, CtaphidCommand::Wink, Vec::new()),
        CtaphidCommand::Lock => (msg.cid, CtaphidCommand::Lock, Vec::new()),
        CtaphidCommand::Cancel => (msg.cid, CtaphidCommand::Cancel, Vec::new()),
        CtaphidCommand::Keepalive => (msg.cid, CtaphidCommand::Keepalive, msg.payload),
        CtaphidCommand::Error => (msg.cid, CtaphidCommand::Error, msg.payload),
        // O despacho do payload CTAP2 (CBOR) em si é integrado no próximo
        // incremento; por ora responde com erro "não especificado".
        CtaphidCommand::Cbor | CtaphidCommand::Msg => (
            msg.cid,
            CtaphidCommand::Error,
            alloc::vec![CtaphidErrorCode::Other.as_u8()],
        ),
        CtaphidCommand::Vendor(_) => (
            msg.cid,
            CtaphidCommand::Error,
            alloc::vec![CtaphidErrorCode::InvalidCmd.as_u8()],
        ),
    }
}
