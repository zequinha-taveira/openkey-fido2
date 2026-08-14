//! Boot bare-metal para o nRF52840 (núcleo Arm Cortex-M4F).
//!
//! Este crate é um binário `no_std` standalone (fora do workspace principal,
//! como `fuzz/`) que configura os clocks reais do nRF52840 via
//! `nrf52840-hal` (HFCLK externo), instala um heap alocador
//! (`embedded-alloc`) e executa um loop de despacho CTAPHID sobre as
//! primitivas de framing/assembly do crate `transport`.
//!
//! O periférico USBD ainda é a referência
//! [`transport::embedded::nrf52840::Nrf52840UsbHid`]; a integração com o
//! driver `nrf-usbd` real é um incremento futuro.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use nrf52840_hal as hal;
use panic_halt as _;

use embedded_alloc::LlffHeap;

use transport::ctaphid::{
    ctaphid_capabilities, ChannelManager, CtaphidAssembler, CtaphidCommand, CtaphidErrorCode,
    CtaphidFragmenter, CtaphidMessage, CTAPHID_PACKET_SIZE,
};
use transport::embedded::nrf52840::Nrf52840UsbHid;
use transport::embedded::UsbHidDevice;

/// Tamanho do heap em bytes (para `Vec` e estruturas alocadas do CTAPHID).
const HEAP_SIZE: usize = 8192;

/// Versão do firmware reportada no handshake `CTAPHID_INIT`.
const FW_MAJOR: u8 = 0;
const FW_MINOR: u8 = 1;
const FW_BUILD: u8 = 0;

/// Alocador global de heap (linked-list first-fit via `embedded-alloc`).
#[global_allocator]
static ALLOCATOR: LlffHeap = LlffHeap::empty();

/// Ponto de entrada. Configura clocks reais, heap e entra no loop CTAPHID.
#[cortex_m_rt::entry]
fn main() -> ! {
    // 1. Inicializa o heap antes de qualquer alocação.
    unsafe {
        embedded_alloc::init!(ALLOCATOR, HEAP_SIZE);
    }

    // 2. Periféricos singleton.
    let p = hal::pac::Peripherals::take().unwrap();

    // 3. Configuração real dos clocks: HFCLK a partir do cristal externo
    //    (32 MHz no nRF52840-DK).
    let clocks = hal::Clocks::new(p.CLOCK);
    let _clocks = clocks.enable_ext_hfosc();

    // 4. GPIO: LED de status (P0.13 = LED1 no nRF52840-DK).
    let port0 = hal::gpio::p0::Parts::new(p.P0);
    let led = port0.p0_13.into_push_pull_output(hal::gpio::Level::High);

    // 5. Transporte USB-HID (referência; driver USBD real é incremento futuro).
    let mut hid = Nrf52840UsbHid::new(led);
    hid.init().ok();

    // 6. Estado do protocolo CTAPHID.
    let mut channels = ChannelManager::new();
    let mut assembler = CtaphidAssembler::new();

    // 7. Loop de despacho CTAPHID.
    loop {
        let mut buf = [0u8; CTAPHID_PACKET_SIZE];
        match hid.recv_packet(&mut buf) {
            Ok(_) => match assembler.process_packet(&buf) {
                Ok(Some(msg)) => {
                    let cmd = msg.cmd;
                    let (cid, resp_cmd, payload) = dispatch(&mut channels, msg);

                    if cmd == CtaphidCommand::Wink {
                        // Sinal visual de presença.
                        let _ = hid.set_led(false);
                        let _ = hid.set_led(true);
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
                // Sem pacote no endpoint (referência/timeout) — continua o polling.
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
        // O despacho do payload CTAP2 (CBOR) em si é integrado em um incremento
        // posterior; por ora responde com erro "não especificado".
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
