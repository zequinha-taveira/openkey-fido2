//! Boot bare-metal para o RP2350 (núcleo Arm Cortex-M33).
//!
//! Este crate é um binário `no_std` standalone (fora do workspace principal,
//! como `fuzz/`) que configura os clocks reais do RP2350 via `rp235x-hal`,
//! instala um heap alocador (`embedded-alloc`) e executa um loop de despacho
//! CTAPHID sobre as primitivas de framing/assembly do crate `transport`.
//!
//! O periférico USB real é integrado via `usb-device`: um dispositivo
//! composto (módulo [`composite`]) expõe CTAPHID em HID e o slot CCID T=0
//! sobre `hal::usb::UsbBus` do RP2350, com a mesma identidade VID/PID.
//!
//! Compatibilidade: Waveshare **RP2350-Zero** usa o mesmo cristal de 12 MHz,
//! presença via BOOTSEL e USB Type-C (porta única); o LED de status é um
//! WS2812B em GPIO16 via PIO (pendente de driver — o binário atual referencia
//! apenas o GPIO25 do Pico 2).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use panic_halt as _;
use rp235x_hal as hal;

use embedded_alloc::LlffHeap;
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;

use usb_device::bus::UsbBusAllocator;

use board_generic::profiles::RP2350_ZERO;

// Stack do autenticador: applets Yubico compartilham um único StorageEngine
// (mesmo kv ⇒ mesma identidade) e um CryptoEngine com a MESMA chave-mestra.
// Família YubiKey 4/5 no mesmo PID (1050:0407) é coberta pelo modo composto.
use authenticator::{
    register_multiprotocol_applets, ManagementApplet, OathApplet, OpenPgpApplet, PivApplet,
};
use crypto::CryptoEngine;
use storage::StorageEngine;
use transport::iso7816::CardRouter;

use ctap2::{Ctap2Authenticator, Ctap2Error};
use transport::ctaphid::{
    ctaphid_capabilities, ChannelManager, CtaphidAssembler, CtaphidCommand, CtaphidErrorCode,
    CtaphidFragmenter, CtaphidMessage, CTAPHID_PACKET_SIZE,
};
use transport::embedded::usb_ccid_backend::MAX_PAYLOAD_LEN;

mod bootsel_presence;
mod composite;
mod qspi_flash;

use bootsel_presence::Rp2350UserPresence;
use composite::CompositeUsbDevice;
use storage::FlashStorageBackend;

/// Tamanho do heap em bytes (para `Vec` e estruturas alocadas do CTAPHID e CBOR).
const HEAP_SIZE: usize = 65536;

/// Cristal externo de 12 MHz (Raspberry Pi Pico 2). Ajuste conforme a placa.
const XTAL_FREQ_HZ: u32 = 12_000_000u32;

/// Versão do firmware reportada no handshake `CTAPHID_INIT`.
const FW_MAJOR: u8 = 0;
const FW_MINOR: u8 = 1;
const FW_BUILD: u8 = 0;

/// Identidade USB do dispositivo: definida em [`composite::UsbIdentity`]
/// (VID/PID + manufacturer/product/serial), selecionada pelo mesmo flag
/// `yubikey5-identity`/`yubikey4-identity` (família YubiKey 4/5, mesmo
/// `1050:0407`, ADR-0025). Padrão: pid.codes do openkey-fido2; o flavor opt-in
/// reivindica identidade YubiKey 5 da Yubico — **NÃO PARA DISTRIBUIÇÃO**.

/// Alocador global de heap (linked-list first-fit via `embedded-alloc`).
#[global_allocator]
static ALLOCATOR: LlffHeap = LlffHeap::empty();

// === Entropia bare-metal para o getrandom "custom" ===
//
// O ring 0.17 depende de getrandom incondicionalmente, e o getrandom 0.2
// emite compile_error para alvos bare-metal. Com a feature "custom"
// habilitada (Cargo.toml), TODAS as chamadas — inclusive as do ring via
// SystemRandom — caem na função registrada abaixo.
//
// Semente: BootRandom de 128 bits gerado pelo ROM do RP2350 na inicialização
// (fonte TRNG), misturado com jitter do contador de ciclos. Saída: splitmix64.
//
// **ATENÇÃO (dev-only):** um PRNG semeado uma vez por boot NÃO substitui um
// stream TRNG contínuo — nonces ECDSA dependem disto. Produção exige wiring
// direto do periférico TRNG via PAC (registrado no TODO como follow-up).

use core::sync::atomic::{AtomicU32, Ordering};

/// Estado do PRNG (splitmix64, 64 bits em dois atomics de 32 — o alvo não
/// tem AtomicU64). 0 = ainda não semeado.
static RNG_STATE_LO: AtomicU32 = AtomicU32::new(0);
static RNG_STATE_HI: AtomicU32 = AtomicU32::new(0);

fn rng_state_load() -> u64 {
    let lo = RNG_STATE_LO.load(Ordering::Relaxed) as u64;
    let hi = RNG_STATE_HI.load(Ordering::Relaxed) as u64;
    (hi << 32) | lo
}

fn rng_state_store(v: u64) {
    RNG_STATE_LO.store(v as u32, Ordering::Relaxed);
    RNG_STATE_HI.store((v >> 32) as u32, Ordering::Relaxed);
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Semeia o PRNG com BootRandom do ROM (TRNG por boot) + jitter de ciclos.
/// Chamar cedo no boot. Falha do ROM → semente só de jitter (degradado).
/// Retorna true se a semente veio do TRNG.
fn entropy_seed() -> bool {
    // BootRandom: 128 bits do TRNG gerados pelo ROM na inicialização.
    let boot = hal::rom_data::sys_info_api::boot_random()
        .ok()
        .flatten()
        .map(|r| r.0);
    let mut seed = match boot {
        Some(b) => (b as u64) ^ ((b >> 64) as u64),
        None => 0,
    };
    // Jitter adicional: contadores que variam entre boots/tempo real.
    let cycles = cortex_m::peripheral::DWT::cycle_count() as u64;
    seed ^= splitmix64(&mut (cycles | 1));
    rng_state_store(seed | 1);
    boot.is_some()
}

/// Implementação custom exigida pela feature "custom" do getrandom 0.2.
fn entropy_fill(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    let mut state = rng_state_load();
    if state == 0 {
        return Err(getrandom::Error::UNSUPPORTED);
    }
    for chunk in buf.chunks_mut(8) {
        let word = splitmix64(&mut state);
        chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
    }
    rng_state_store(state);
    Ok(())
}

getrandom::register_custom_getrandom!(entropy_fill);

/// Prova de uso do ring no alvo: SystemRandom deve compilar e consumir a
/// implementação custom acima (exercitado no boot; falha = pânico visível).
fn ring_smoke() -> bool {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut out = [0u8; 16];
    rng.fill(&mut out).is_ok()
}

/// Bloco de início exigido pela Boot ROM do RP2350.
#[link_section = ".start_block"]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::secure_exe();

// Este binário é direcionado à Waveshare RP2350-Zero (perfil `RP2350_ZERO`):
// o pino de status abaixo DEVE ser o registrado no perfil (WS2812B em GPIO16).
// O perfil YubiKey 4/5 (`YUBIKEY_4_5`) reusa a mesma pinagem (ADR-0025).
// Se o perfil mudar, esta asserção de compilação falha e força a revisão.
const _: () = assert!(RP2350_ZERO.led_pin == 16);
const _: () = assert!(board_generic::profiles::YUBIKEY_4_5.led_pin == 16);

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

    // 1b. Semeia a entropia bare-metal (antes de qualquer uso do ring).
    entropy_seed();
    let _ring_ok = ring_smoke();

    // 1c. Applets Yubico (ISO 7816-4) sobre um único storage compartilhado
    //     PERSISTIDO na flash QSPI física: serial do Management e estado OATH
    //     vivem no mesmo kv e sobrevivem a power cycles (dois slots +
    //     recuperação, ver FlashStorageBackend). A chave-mestra é gerada via
    //     SystemRandom — que já consome o getrandom custom semeado em 1b.
    //     Falhas aqui são fatais: sem applets não há CCID.
    let flash = qspi_flash::QspiFlashDevice::open().expect("flash QSPI (região de credenciais)");
    let backend = FlashStorageBackend::new(flash).expect("backend de dois slots");
    let storage = core::cell::RefCell::new(StorageEngine::with_backend(Box::new(backend)));
    let crypto = CryptoEngine::new().expect("crypto engine");
    let mut oath = OathApplet::new(&storage, crypto.clone()).expect("applet OATH");
    let mut management =
        ManagementApplet::new(&storage, crypto.clone()).expect("applet Management");
    let mut piv = PivApplet::new(&storage, crypto.clone()).expect("applet PIV");
    let mut openpgp = OpenPgpApplet::new(&storage, crypto.clone()).expect("applet OpenPGP");
    let mut router = CardRouter::new();
    register_multiprotocol_applets(
        &mut router,
        &mut management,
        &mut oath,
        &mut piv,
        &mut openpgp,
    );

    // 1d. Autenticador CTAP2 para FIDO2/WebAuthn via USB-HID.
    #[cfg(feature = "yubikey5-identity")]
    let aaguid = board_generic::profiles::YUBIKEY_4_5.aaguid;
    #[cfg(not(feature = "yubikey5-identity"))]
    let aaguid = board_generic::profiles::RP2350_ZERO.aaguid;

    let ctap_storage = StorageEngine::new().expect("ctap storage");
    let mut ctap2_auth = Ctap2Authenticator::new(aaguid, crypto.clone(), ctap_storage)
        .expect("ctap2 authenticator");
    ctap2_auth.set_user_presence(Some(Box::new(Rp2350UserPresence::new())));

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

    // 6. GPIO: LED de status. Na RP2350-Zero o pino 16 alimenta a WS2812B —
    //    o protocolo WS2812 (PIO) ainda não está implementado; o toggle
    //    simples abaixo é um placeholder do sinal de status no pino correto.
    let sio = hal::Sio::new(pac.SIO);
    let pins = hal::gpio::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );
    let mut led = pins.gpio16.into_push_pull_output();

    // 7. Dispositivo USB composto real (usb-device sobre o periférico USB do
    //    RP2350): interface 0 = CTAPHID (HID), interface 1 = CCID (T=0) —
    //    mesma identidade VID/PID para ambas, como num YubiKey composto.
    let usb_bus = UsbBusAllocator::new(hal::usb::UsbBus::new(
        pac.USB,
        pac.USB_DPRAM,
        clocks.usb_clock,
        true,
        &mut pac.RESETS,
    ));
    let mut device = CompositeUsbDevice::new(&usb_bus, &composite::ACTIVE_IDENTITY);

    // 8. Estado do protocolo CTAPHID.
    let mut channels = ChannelManager::new();
    let mut assembler = CtaphidAssembler::new();

    // 9. Loop de despacho CTAPHID + CCID (não bloqueante).
    loop {
        // Um único ciclo de polling alimenta as duas classes do dispositivo.
        device.poll();

        // CCID: APDUs brutos vão para o roteador ISO 7816-4. O SELECT pelo
        // AID escolhe o applet (A000000527471117 ⇒ Management; A0000005272101
        // ⇒ OATH; + PIV/OpenPGP via `register_multiprotocol_applets`) e os
        // demais comandos são despachados ao applet selecionado.
        // Respostas saem como `DATA || SW` no XfrBlock. O caminho CTAPHID
        // abaixo permanece intocado.
        if device.ccid.is_pending() {
            let mut apdu_scratch = [0u8; MAX_PAYLOAD_LEN];
            if let Some(len) = device.ccid.take_pending_request(&mut apdu_scratch) {
                let response = router.process(&apdu_scratch[..len]);
                let _ = device.ccid.send_response(&response.to_bytes());
            }
        }

        // CTAPHID: consome o pacote recebido, se houver.
        let mut buf = [0u8; CTAPHID_PACKET_SIZE];
        match device.hid.recv_report(&mut buf) {
            Some(_) => match assembler.process_packet(&buf) {
                Ok(Some(msg)) => {
                    let cmd = msg.cmd;
                    let (cid, resp_cmd, payload) = dispatch(&mut channels, &mut ctap2_auth, msg);

                    if cmd == CtaphidCommand::Wink {
                        // Sinal visual de presença (WS2812B em GPIO16 na
                        // RP2350-Zero — placeholder até o driver PIO).
                        let _ = led.set_low();
                        timer.delay_ms(40);
                        let _ = led.set_high();
                    }

                    if let Ok(packets) = CtaphidFragmenter::fragment(cid, resp_cmd, &payload) {
                        send_hid_packets(&mut device, &mut router, &packets);
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
                        send_hid_packets(&mut device, &mut router, &packets);
                    }
                }
            },
            None => {
                // Sem pacote no endpoint (placeholder/timeout) — continua o
                // polling.
            }
        }
    }
}

/// Envia todos os pacotes de uma mensagem CTAPHID fragmentada, realizando polling
/// no barramento USB até que cada pacote seja aceito pelo endpoint IN de hardware.
fn send_hid_packets<B: usb_device::bus::UsbBus>(
    device: &mut CompositeUsbDevice<'_, B>,
    router: &mut CardRouter,
    packets: &[[u8; CTAPHID_PACKET_SIZE]],
) {
    for packet in packets {
        let mut sent = false;
        for _ in 0..500_000 {
            device.poll();
            if device.ccid.is_pending() {
                let mut apdu_scratch = [0u8; MAX_PAYLOAD_LEN];
                if let Some(len) = device.ccid.take_pending_request(&mut apdu_scratch) {
                    let response = router.process(&apdu_scratch[..len]);
                    let _ = device.ccid.send_response(&response.to_bytes());
                }
            }
            if device.hid.send_report(packet).is_ok() {
                sent = true;
                break;
            }
        }
        if !sent {
            break;
        }
    }
}

/// Despacha uma mensagem CTAPHID completa e produz a resposta
/// `(cid, comando, payload)`.
fn dispatch(
    channels: &mut ChannelManager,
    ctap2_auth: &mut Ctap2Authenticator,
    msg: CtaphidMessage,
) -> (u32, CtaphidCommand, Vec<u8>) {
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
        CtaphidCommand::Cbor => {
            if msg.payload.is_empty() {
                let payload = alloc::vec![Ctap2Error::InvalidLength.as_u8()];
                (msg.cid, CtaphidCommand::Cbor, payload)
            } else {
                let cmd_byte = msg.payload[0];
                let cbor_data = msg.payload[1..].to_vec();
                let mut payload = alloc::vec![0u8]; // Byte 0 = CTAP2_OK (0x00)
                match ctap2_auth.process_command(cmd_byte, cbor_data) {
                    Ok(mut resp_bytes) => {
                        payload.append(&mut resp_bytes);
                        (msg.cid, CtaphidCommand::Cbor, payload)
                    }
                    Err(err) => {
                        (msg.cid, CtaphidCommand::Cbor, alloc::vec![err.as_u8()])
                    }
                }
            }
        }
        CtaphidCommand::Msg => (
            msg.cid,
            CtaphidCommand::Error,
            alloc::vec![CtaphidErrorCode::InvalidCmd.as_u8()],
        ),
        CtaphidCommand::Vendor(_) => (
            msg.cid,
            CtaphidCommand::Error,
            alloc::vec![CtaphidErrorCode::InvalidCmd.as_u8()],
        ),
    }
}
