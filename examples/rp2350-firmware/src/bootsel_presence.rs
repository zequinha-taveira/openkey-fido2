//! Detecção física de User Presence (toque) via botão BOOTSEL e sinalização LED
//! para a Waveshare RP2350-Zero e Raspberry Pi Pico 2.

use ctap2::UserPresence;

/// Atraso por contagem de ciclos (a 125 MHz: 125_000 ciclos ≈ 1 ms).
#[inline(always)]
fn delay_cycles(cycles: u32) {
    let mut count = cycles / 3;
    while count > 0 {
        unsafe {
            core::arch::asm!("nop");
        }
        count -= 1;
    }
}

/// Envia dados GRB para o LED RGB WS2812B no GPIO16 do RP2350.
///
/// Executado a partir de RAM com interrupções mascaradas para manter o timing
/// preciso de 800 kHz.
#[link_section = ".data.ram_func"]
#[inline(never)]
pub fn ws2812_write(data: [u8; 3]) {
    cortex_m::interrupt::free(|_| unsafe {
        let sio_gpio_out_set = 0xd000_0014 as *mut u32;
        let sio_gpio_out_clr = 0xd000_0018 as *mut u32;
        let pin_mask: u32 = 1 << 16;

        for byte in data {
            for bit_idx in (0..8).rev() {
                let bit = (byte >> bit_idx) & 1;
                if bit == 1 {
                    // Bit 1: T1H ~800ns, T1L ~450ns
                    core::ptr::write_volatile(sio_gpio_out_set, pin_mask);
                    for _ in 0..20 {
                        core::arch::asm!("nop");
                    }
                    core::ptr::write_volatile(sio_gpio_out_clr, pin_mask);
                    for _ in 0..8 {
                        core::arch::asm!("nop");
                    }
                } else {
                    // Bit 0: T0H ~400ns, T0L ~850ns
                    core::ptr::write_volatile(sio_gpio_out_set, pin_mask);
                    for _ in 0..8 {
                        core::arch::asm!("nop");
                    }
                    core::ptr::write_volatile(sio_gpio_out_clr, pin_mask);
                    for _ in 0..20 {
                        core::arch::asm!("nop");
                    }
                }
            }
        }
        // Reset delay > 50us
        for _ in 0..1500 {
            core::arch::asm!("nop");
        }
    });
}

/// Controla a indicação visual de presença (WS2812B em GPIO16 + GPIO25 padrão).
pub fn set_presence_led(on: bool) {
    unsafe {
        let sio_gpio_oe_set = 0xd000_0024 as *mut u32;
        let sio_gpio_out_set = 0xd000_0014 as *mut u32;
        let sio_gpio_out_clr = 0xd000_0018 as *mut u32;

        // Garante GPIO16 e GPIO25 como saídas
        core::ptr::write_volatile(sio_gpio_oe_set, (1 << 16) | (1 << 25));

        if on {
            // GPIO25 High
            core::ptr::write_volatile(sio_gpio_out_set, 1 << 25);
            // WS2812B: Verde suave (G=20, R=0, B=0)
            ws2812_write([20, 0, 0]);
        } else {
            // GPIO25 Low
            core::ptr::write_volatile(sio_gpio_out_clr, 1 << 25);
            // WS2812B: Desligado
            ws2812_write([0, 0, 0]);
        }
    }
}

/// Lê o estado físico do botão BOOTSEL no RP2350.
///
/// O botão BOOTSEL está ligado à linha CS da flash QSPI (ativo-baixo: puxa para GND).
/// Para ler com segurança:
/// 1. Interrupções desabilitadas (`cortex_m::interrupt::free`).
/// 2. Coloca o drive do CS em Hi-Z (`OEOVER = 2` em `IO_QSPI.io[1].ctrl`).
/// 3. Executa em RAM (`.data.ram_func`) sem acessar XIP flash.
/// 4. Amostra o bit 1 em `SIO.gpio_hi_in`.
/// 5. Restaura o controle normal do CS.
#[link_section = ".data.ram_func"]
#[inline(never)]
pub fn read_bootsel_button() -> bool {
    cortex_m::interrupt::free(|_| unsafe {
        // No RP2350:
        // IO_QSPI base: 0x40030000
        // io[1].ctrl address = 0x4003000c
        // SIO GPIO_HI_IN address = 0xd0000008 (bit 1 = QSPI_CS_N)
        let io_qspi_cs_ctrl = 0x4003_000c as *mut u32;
        let sio_gpio_hi_in = 0xd000_0008 as *const u32;

        let original_ctrl = core::ptr::read_volatile(io_qspi_cs_ctrl);

        // OEOVER (bits 13:12) = 2 (Disable output / Hi-Z)
        let hi_z_ctrl = (original_ctrl & !(0x3 << 12)) | (0x2 << 12);
        core::ptr::write_volatile(io_qspi_cs_ctrl, hi_z_ctrl);

        // Aguarda estabilização do pull-up/pull-down (1000 ciclos de NOP)
        let mut count = 1000;
        while count > 0 {
            core::arch::asm!("nop");
            count -= 1;
        }

        // Lê o estado do pino: 0 = pressionado (ligado a GND), 1 = solto
        let hi_in = core::ptr::read_volatile(sio_gpio_hi_in);
        let pressed = (hi_in & (1 << 1)) == 0;

        // Restaura o controle normal do CS
        core::ptr::write_volatile(io_qspi_cs_ctrl, original_ctrl);

        pressed
    })
}

/// Implementação de `UserPresence` para a placa RP2350-Zero.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rp2350UserPresence;

impl Rp2350UserPresence {
    pub fn new() -> Self {
        Self
    }
}

impl UserPresence for Rp2350UserPresence {
    fn is_present(&mut self) -> bool {
        // Janela de espera: até 15 segundos (150 iterações de 100 ms)
        let timeout_iterations = 150;
        let mut confirmed = false;

        for i in 0..timeout_iterations {
            // Pisca o LED a cada 100ms
            set_presence_led(i % 2 == 0);

            // Verifica o botão BOOTSEL
            if read_bootsel_button() {
                // Debounce de 15ms
                delay_cycles(15 * 125_000);
                if read_bootsel_button() {
                    confirmed = true;
                    break;
                }
            }

            // Aguarda ~100ms
            delay_cycles(100 * 125_000);
        }

        // Desliga o LED piscante
        set_presence_led(false);

        if confirmed {
            // Feedback de confirmação: pisca 2x rápido em azul/ciano
            for _ in 0..2 {
                ws2812_write([0, 20, 20]); // Ciano
                delay_cycles(50 * 125_000);
                ws2812_write([0, 0, 0]);
                delay_cycles(50 * 125_000);
            }
            true
        } else {
            false
        }
    }
}
