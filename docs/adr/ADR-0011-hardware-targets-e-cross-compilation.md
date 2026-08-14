# ADR-0011: Compilação Cruzada e Targets de Hardware Embarcado (no_std)

## Contexto

O projeto **openkey-fido2** foi desenhado com arquitetura em camadas visando execução tanto em ambiente host simulado quanto em microcontroladores de hardware real.

Para viabilizar a implantação em microcontroladores comerciais com recursos criptográficos e USB/NFC de hardware, foram selecionadas três famílias principais de chips:
1. **Raspberry Pi RP2350** (Dual Cortex-M33 / Hazard3 RISC-V, TrustZone, SHA-256 accelerator, OTP) — Target: `thumbv8m.main-none-eabihf`.
2. **Nordic Semiconductor nRF52840** (Cortex-M4F, Bluetooth 5.3, NFC Tag Type 4, USB FS, ARM CryptoCell-310) — Target: `thumbv7em-none-eabihf`.
3. **STMicroelectronics STM32L4** (Cortex-M4F, Ultra-low-power, USB FS, Hardware RNG) — Target: `thumbv7em-none-eabihf`.

Era necessário definir a estratégia de compilação cruzada, organização do toolchain de build, compatibilidade estrita `no_std + alloc` e configuração de runners para flash/debug.

---

## Decisão

1. **Configuração de Toolchain e Cargo (`.cargo/config.toml`)**:
   - Definição padrão de flags de link (`-C link-arg=-Tlink.x` e `-C link-arg=-Tdefmt.x` opcionais).
   - Configuração de runners (`probe-rs run --chip <CHIP>` / `elf2uf2-rs`) para facilitar o workflow de desenvolvimento e gravação direta no microcontrolador via USB/SWD.
   - Aliases no Cargo para compilação rápida de targets embarcados (`cargo build-rp2350`, etc.).

2. **Compatibilidade `no_std` com `alloc`**:
   - O firmware opera sob `#![no_std]` em targets bare-metal, utilizando `extern crate alloc;` para estruturas dinâmicas de protocolo (CBOR payloads, buffers de fragmentação).
   - A inicialização do heap allocator é delegada à aplicação de inicialização da board (ex.: `embedded-alloc` com buffer estático configurado no `main.rs` do firmware).
   - Dependências são configuradas com `default-features = false` para compatibilidade com targets sem suporte a `std`.

3. **Abstração de Periféricos e Ecossistema `usb-device`**:
   - Os adaptadores de hardware implementam as traits `UsbHidDevice`, `UsbCcidDevice` e `NfcDevice` de `firmware/transport`, conectando-se a instâncias de `usb-device::bus::UsbBus` e drivers de rádio NFC dos respectivos HALs.

4. **Pipelines de Verificação e Automação**:
   - Comandos dedicados no `justfile` e no `BUILD.md` para verificar e compilar o firmware contra os targets ARM Cortex-M (`just check-targets`, `just build-rp2350`).
   - Adição de step no CI para garantir que o código não quebra em targets bare-metal.

---

## Consequências

### Positivas
- Compilação automatizada e reproduzível para microcontroladores ARM Cortex-M33 e Cortex-M4F.
- Modularidade total: o mesmo núcleo de protocolo (`ctap2`, `crypto`, `authenticator`) opera no simulador host e no silício real.
- Facilidade de gravação e teste em hardware com `probe-rs` e `elf2uf2`.

### Considerações
- O ambiente do desenvolvedor requer os targets `thumbv8m.main-none-eabihf` e/ou `thumbv7em-none-eabihf` instalados via `rustup target add <target>`.
- O firmware final bare-metal precisa fornecer uma rotina de panic (`panic-halt` ou `panic-probe-rs`) e inicialização do heap allocator.
