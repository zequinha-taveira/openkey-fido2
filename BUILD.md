# BUILD.md — Guia de Compilação do openkey-fido2

Este documento descreve como compilar, testar e verificar o projeto **openkey-fido2** em diferentes plataformas e cenários.

---

## Pré-requisitos

### Obrigatórios

| Ferramenta | Versão mínima | Instalação |
|-----------|---------------|------------|
| **Rust** | 1.85+ | [rustup.rs](https://rustup.rs) |
| **Cargo** | (incluído no Rust) | via `rustup` |

### Opcionais

| Ferramenta | Uso | Instalação |
|-----------|-----|------------|
| **Python** | 3.10+ | Testes E2E (`tests/python/`) |
| **just** | Task runner | `cargo install just` |
| **cargo-tarpaulin** | Cobertura de código | `cargo install cargo-tarpaulin` |
| **cargo-fuzz** | Fuzzing | `cargo install cargo-fuzz` (requer Rust nightly) |

### Verificar instalação

```bash
rustc --version    # rustc 1.85.0 ou superior
cargo --version
python --version   # 3.10+ (apenas para E2E)
just --version     # opcional
```

---

## Compilação

### Build padrão (debug + otimizado)

```bash
cargo build --workspace
```

> O profile `[profile.dev]` usa `opt-level = 2` e `lto = true` para aproximar a performance de release durante o desenvolvimento.

### Build release

```bash
cargo build --workspace --release
```

O profile release usa:
- `codegen-units = 1` — melhor otimização
- `opt-level = "s"` — otimizado para tamanho (ideal para firmware)
- `strip = true` — remove símbolos de debug
- `lto = true` — link-time optimization
- `panic = "abort"` — menor footprint (sem unwinding)

### Build de um crate específico

```bash
cargo build -p crypto           # apenas criptografia
cargo build -p ctap2            # apenas protocolo CTAP2
cargo build -p fido2-simulator  # apenas o simulador
cargo build -p authenticator    # apenas o authenticator
```

### Compilação Cruzada (Hardware Embarcado / `no_std`)

O projeto suporta compilação bare-metal para microcontroladores ARM Cortex-M:

| Target | Arquitetura | Microcontroladores Alvo |
|--------|-------------|-------------------------|
| `thumbv8m.main-none-eabihf` | ARMv8-M (Cortex-M33 com FPU) | Raspberry Pi **RP2350** |
| `thumbv7em-none-eabihf` | ARMv7E-M (Cortex-M4F com FPU) | Nordic **nRF52840**, ST **STM32L4** |

#### Instalação dos targets

```bash
rustup target add thumbv8m.main-none-eabihf
rustup target add thumbv7em-none-eabihf
```

#### Compilação para targets de hardware

```bash
# RP2350 (Cortex-M33)
cargo build -p transport --target thumbv8m.main-none-eabihf --features embedded --no-default-features

# nRF52840 / STM32L4 (Cortex-M4F)
cargo build -p transport --target thumbv7em-none-eabihf --features embedded --no-default-features

# Checar todos os targets via just
just check-targets
```

#### Firmware bare-metal executável (RP2350)

Além da crate `transport`, há um **binário `no_std` completo de boot** para o
RP2350 em [`examples/rp2350-firmware/`](examples/rp2350-firmware/):

```bash
# Gerar o binário ELF para o RP2350 (Cortex-M33)
cd examples/rp2350-firmware && cargo build

# Via just
just build-rp2350-firmware
```

O crate é **standalone** (workspace próprio, como `fuzz/`), portanto não é
compilado por `cargo build --workspace`. Ele configura os clocks reais via
`rp235x-hal` (XOSC + PLLs), instala um heap `embedded-alloc` e executa um loop
de despacho CTAPHID sobre o crate `transport`, usando o backend USB real
(`usb-device` + `hal::usb::UsbBus` do RP2350, via `transport::UsbHidBackend`).
O artefato final é um binário ELF em
`examples/rp2350-firmware/target/thumbv8m.main-none-eabihf/debug/`.

O backend USB real vive no crate `transport` atrás da feature `usb-device`
(módulo `embedded::usb_hid_backend`). Testes em host com um `MockUsbBus`:

```bash
cargo test -p transport --features usb-device
```

#### Firmware bare-metal executável (nRF52840)

Há um binário equivalente para o **nRF52840** (Nordic, Cortex-M4F) em
[`examples/nrf52840-firmware/`](examples/nrf52840-firmware/):

```bash
# Gerar o binário ELF para o nRF52840 (Cortex-M4F)
cd examples/nrf52840-firmware && cargo build

# Via just
just build-nrf52840-firmware
```

Configura clocks reais via `nrf52840-hal` (HFCLK externo), heap
`embedded-alloc` e o loop CTAPHID (referência `Nrf52840UsbHid`/`Nrf52840Nfc`).

#### Virtual CTAPHID Bridge (Linux/UHID)

[`tools/ctaphid_bridge.py`](tools/ctaphid_bridge.py) cria um dispositivo
USB-HID virtual (`/dev/uhid`, **Linux only**) e conecta o
`fido2-simulator --raw-cbor` a navegadores / FIDO Conformance Tool. A framing
CTAPHID e o wrapping CBOR são testáveis em host:

```bash
python -m pytest tests/python/test_ctaphid_bridge.py -v
```

---

## Testes

### Testes unitários e de integração (Rust)

```bash
cargo test --workspace
```

### Testes de um crate específico

```bash
cargo test -p crypto        # testes de criptografia (Ed25519, ES256, ES384, PS256, RS256, ECIES)
cargo test -p ctap2         # testes de protocolo CTAP2 (MakeCredential, GetAssertion, etc.)
cargo test -p storage       # testes de armazenamento seguro
cargo test -p transport     # testes de transporte (requer feature: cargo test -p transport --features embedded)
cargo test -p test-suite    # suíte de integração completa
```

### Testes end-to-end (Python)

Requer o simulador compilado e Python 3.10+ com `pytest`:

```bash
# 1. Compilar o simulador
cargo build -p fido2-simulator

# 2. Instalar dependências Python
pip install pytest cbor2

# 3. Rodar os testes
python -m pytest tests/python -v
```

Suítes de teste Python disponíveis:

| Suíte | Cobertura |
|-------|-----------|
| `conformance/` | Conformidade estrita CTAP 2.1 (raw CBOR wire format) |
| `test_firmware_sim.py` | MakeCredential, GetAssertion, GetInfo |
| `test_client_pin.py` | setPIN, changePIN, getPINToken, rate limiting |
| `test_extensions.py` | credProtect, credBlob, minPinLength, hmac-secret |
| `test_algorithms.py` | ES256, Ed25519, RS256 via simulador |
| `test_attestation.py` | Packed, Self attestation |
| `test_ctap2_commands.py` | Reset, GetNextAssertion, EnumerateRPs, BioEnroll |
| `test_persistence.py` | Persistência entre reinicializações |
| `test_security_features.py` | SecurityFeatures, perfil RP2350 |

---

## Qualidade de Código

### Formatação

```bash
# Verificar (sem modificar)
cargo fmt --check --all

# Aplicar automaticamente
cargo fmt --all
```

### Linter (Clippy)

```bash
# Warnings tratados como erros
cargo clippy --workspace -- -D warnings

# Com todas as features habilitadas
cargo clippy --workspace --all-features -- -D warnings
```

### Verificação completa (CI local)

```bash
# Via cargo
cargo build --workspace && cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --check --all

# Via just (equivalente)
just ci
```

---

## Cobertura de Código

```bash
# Instalar (uma vez)
cargo install cargo-tarpaulin

# Gerar relatórios (Xml + Html)
cargo tarpaulin --workspace --out Xml --out Html --output-dir coverage --timeout 300

# Via just
just coverage
```

Os relatórios são gerados em `coverage/`:
- `coverage/cobertura.xml` — formato Cobertura XML
- `coverage/tarpaulin-report.html` — visualização HTML

---

## Fuzzing

O projeto inclui um harness de fuzzing para o parser CBOR em `fuzz/`:

```bash
# Instalar (uma vez, requer nightly)
rustup install nightly
cargo install cargo-fuzz

# Rodar (60 segundos por padrão)
cargo +nightly fuzz run decode_cbor --fuzz-dir fuzz -- -max_total_time=60

# Via just
just fuzz                     # decode_cbor, 60s
just fuzz decode_cbor 300     # decode_cbor, 5 minutos

# Listar alvos disponíveis
just fuzz-list
```

---

## Documentação

```bash
# Gerar documentação de todas as crates
cargo doc --workspace --no-deps

# Gerar e abrir no browser
cargo doc --workspace --no-deps --open

# Via just
just doc
just doc-open
```

---

## Simulador

O simulador expõe o firmware via JSON line protocol para testes e desenvolvimento:

```bash
# Compilar
cargo build -p fido2-simulator

# Executar interativamente (stdin/stdout)
cargo run -p fido2-simulator

# Via just
just sim
```

### Protocolo JSON Line

O simulador aceita comandos JSON no stdin e responde no stdout:

```json
{"command": "make_credential", "params": {...}}
{"command": "get_assertion", "params": {...}}
{"command": "get_info"}
{"command": "reset"}
```

---

## Exemplos

```bash
cargo run -p basic-example         # uso básico do EmbeddedAuthenticator
cargo run -p ccid-example          # transport CCID
cargo run -p crypto-example        # criptografia (Ed25519, ES256, ECIES, HMAC, SHA-256)
cargo run -p transport-example     # implementação customizada de Transport
cargo run -p storage-example       # operações de armazenamento seguro
cargo run -p ctap2-example         # interação direta com CTAP2
```

---

## Referência Rápida (`just`)

Todos os comandos acima estão disponíveis via [`just`](https://github.com/casey/just):

```bash
just --list          # listar comandos disponíveis
just build           # compilar workspace
just build-release   # compilar em release
just test            # testes Rust
just test-e2e        # testes E2E Python
just check           # build + fmt + clippy + test
just ci              # build + test + clippy + fmt-check
just clippy          # linter
just fmt             # formatar código
just fmt-check       # verificar formatação
just sim             # simulador interativo
just doc             # gerar documentação
just coverage        # relatório de cobertura
just fuzz            # fuzzing (60s)
just clean           # limpar artefatos
```

---

## Workspace: Estrutura de Crates

```
openkey-fido2/
├── firmware/
│   ├── authenticator/     # EmbeddedAuthenticator (API final)
│   ├── board-generic/     # HAL, BoardDefinition, SecurityFeatures
│   ├── device-profile/    # DeviceProfileBuilder, CapabilityDiscovery
│   ├── storage/           # StorageEngine, encryption at rest
│   └── transport/         # Transport trait, CTAPHID, HALs embedded
├── protocol/
│   ├── ctap2/             # CTAP2 state machine, extensões, comandos
│   ├── crypto/            # ring + x25519-dalek (Ed25519, ES256, ES384, PS256, RS256, ECIES)
│   └── webauthn/          # Validação WebAuthn
├── simulator/             # fido2-simulator (JSON line protocol)
├── examples/              # basic, ccid, crypto, ctap2, storage, transport
├── tests/                 # test-suite (Rust) + tests/python (E2E)
├── fuzz/                  # fuzzing harness (CBOR parser)
└── docs/adr/              # Architecture Decision Records (ADR-0001..0010)
```

---

## Dependências Principais

| Crate | Versão | Uso |
|-------|--------|-----|
| `ring` | 0.17 | Criptografia (Ed25519, ECDSA, RSA, AEAD, HKDF, RNG) |
| `x25519-dalek` | 2.0 | Chaves X25519 estáticas persistíveis (ECIES) |
| `ciborium` | 0.2 | Serialização/deserialização CBOR |
| `serde` | 1.0 | Framework de serialização |
| `thiserror` | 2.0 | Tipos de erro ergonômicos |
| `zeroize` | 1.7 | Zeroização segura de memória |
| `rsa` | 0.9 | Geração de chaves RSA |
| `rand` | 0.8 | Geração de números aleatórios |

---

## Licença

Licenciado sob **MIT OR Apache-2.0**. Veja [`LICENSE-MIT`](LICENSE-MIT) e [`LICENSE-APACHE`](LICENSE-APACHE).
