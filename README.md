# openkey-fido2

[![CI](https://github.com/zequinha-taveira/openkey-fido2/actions/workflows/ci.yml/badge.svg)](https://github.com/zequinha-taveira/openkey-fido2/actions/workflows/ci.yml)
[![Dev Build](https://github.com/zequinha-taveira/openkey-fido2/actions/workflows/dev-build.yml/badge.svg)](https://github.com/zequinha-taveira/openkey-fido2/actions/workflows/dev-build.yml)
[![Release](https://github.com/zequinha-taveira/openkey-fido2/actions/workflows/release.yml/badge.svg)](https://github.com/zequinha-taveira/openkey-fido2/actions/workflows/release.yml)
[![E2E](https://github.com/zequinha-taveira/openkey-fido2/actions/workflows/e2e.yml/badge.svg)](https://github.com/zequinha-taveira/openkey-fido2/actions/workflows/e2e.yml)
[![Coverage](https://github.com/zequinha-taveira/openkey-fido2/actions/workflows/coverage.yml/badge.svg)](https://github.com/zequinha-taveira/openkey-fido2/actions/workflows/coverage.yml)
[![Docs](https://img.shields.io/badge/docs-cargo--doc-blue.svg)](https://docs.rs/openkey-fido2)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#licença)

Firmware FIDO2/WebAuthn em Rust para authenticators embarcados. Implementa CTAP2, WebAuthn, criptografia via `ring`, e armazenamento seguro de credenciais.

## Arquitetura

```
┌─────────────────────────────────────────────────────────┐
│              EmbeddedAuthenticator (authenticator)        │
│   Coordena todas as camadas e expõe a API final          │
└───────────────┬─────────────────────────────────────────┘
                │
    ┌───────────┼───────────┐
    ▼           ▼           ▼
┌────────┐ ┌─────────┐ ┌──────────────┐
│webauthn│ │ device  │ │  board       │
│        │ │-profile │ │ -generic     │
└───┬────┘ └─────────┘ └──────────────┘
    │
    ▼
┌────────┐     ┌─────────┐     ┌─────────┐
│ ctap 2 │◄──►│ storage │◄──►│  crypto │
└────────┘     └─────────┘     └─────────┘
```

## Crates

| Crate | Caminho | Responsabilidade |
|-------|---------|------------------|
| `authenticator` | `firmware/authenticator/` | API final (`EmbeddedAuthenticator`) |
| `webauthn` | `protocol/webauthn/` | Validação de requests WebAuthn |
| `ctap2` | `protocol/ctap2/` | Estado CTAP2 (MakeCredential, GetAssertion, ClientPIN, etc.) |
| `crypto` | `protocol/crypto/` | Operações criptográficas (Ed25519, ES256, HMAC-SHA256, ChaCha20-Poly1305) |
| `storage` | `firmware/storage/` | Armazenamento com encryption at rest |
| `board-generic` | `firmware/board-generic/` | HAL e profiles de boards |
| `device-profile` | `firmware/device-profile/` | Configuração de produto e capability discovery |
| `transport` | `firmware/transport/` | Trait Transport + stubs USB-HID/CCID |
| `fido2-simulator` | `simulator/` | Simulador host com JSON line protocol |
| `test-suite` | `tests/` | Testes de integração Rust + Python E2E |

## Funcionalidades

### Core CTAP2
- **MakeCredential** — criação de credenciais com attestation `none`
- **GetAssertion** — assertions com allow_list, exclude_list, sign counter
- **GetInfo** — capacidades dinâmicas (algoritmos, extensões, transports) e
  `firmwareVersion` inteiro no wire format CTAP 2.1
- **GetNextAssertion** — suporte a múltiplas credenciais
- **Reset** — limpeza de credenciais e PIN
- **Selection** — seleção de dispositivo

### ClientPIN (CTAP2 §6)
- `getPINRetries` — contador de tentativas (inicial: 8)
- `setPIN` — configurar PIN (mínimo 4 bytes)
- `changePIN` — trocar PIN com verificação
- `getPINToken` e `getPinUvAuthTokenUsingPinWithPermissions` — tokens via PIN
- Protocolos PIN/UV 1 e 2 — P-256 ECDH, AES-CBC e HMAC conforme CTAP2.1
- `pinUvAuthParam` — verificação de MAC, permissões e binding de RP em MakeCredential,
  GetAssertion e Credential Management
- Bloqueio após 3 tentativas consecutivas, com estado persistido

### Criptografia
- **Ed25519** — assinatura/verificação via `ring`
- **ES256 (ECDSA P-256)** — suporte completo com COSE key
- **HMAC-SHA256** — para derivação e autenticação
- **ChaCha20-Poly1305** — encrypt at rest de credenciais
- **SystemRandom** — nonces criptográficos imprevisíveis

### Extensões WebAuthn
- **credProtect** — política de proteção de credencial
- **credBlob** — blob customizado por credencial (máx 32 bytes)
- **minPinLength** — comprimento mínimo de PIN discovery
- **hmac-secret** — segredo compartilhado via HMAC-SHA256

### Armazenamento
- **Encryption at rest** — chaves privadas nunca em plaintext
- **FileStorageBackend** — persistência local em JSON (dev)
- **FlashStorageBackend** — backend de dois slots sobre `FlashDevice`, com `SimulatedFlash` para testes de power-loss
- **Wear leveling** — rotação de writes
- **Credential pruning** — LRU quando `max_credential_count` atingido

### Transportes
- **USB-HID** — backend concreto `CtapHidClass`/`UsbHidBackend` sobre `usb-device`
  (report descriptor FIDO `0xF1D0`), integrado ao `examples/rp2350-firmware`;
  `EmbeddedAuthenticator` aceita `Box<dyn Transport>` por injeção; validação
  física em placa pendente
- **CCID** — backend concreto `CcidClass`/`UsbCcidBackend` (T=0 sobre
  `usb-device`) e roteador ISO 7816-4 puro (`transport::iso7816`): SELECT
  por AID completo/prefixo, applets plugáveis (`Applet`) e encadeamento de
  resposta `61 XX`/GET RESPONSE; applets CTAP2/OATH na próxima fase
- **NFC / BLE** — stubs de `Transport` com ciclo de vida testável; stacks de
  hardware pendentes
- **Firmware bare-metal** — `examples/rp2350-firmware` (boot + loop CTAPHID +
  slot CCID num único dispositivo USB composto, `src/composite.rs`) e
  `examples/nrf52840-firmware` (boot + loop CTAPHID)
- **Virtual CTAPHID Bridge** — `tools/ctaphid_bridge.py` (UHID, Linux)

## Comandos

```bash
# Compilar workspace
cargo build --workspace

# Testes unitários e de integração Rust
cargo test --workspace

# Testes E2E Python (requer simulador compilado)
cargo build -p fido2-simulator
python -m pytest tests/python -v

# Lint e formatação
cargo fmt --check --workspace
cargo clippy --workspace -- -D warnings

# Simulador interativo
cargo run -p fido2-simulator

# Exemplos
cargo run -p basic-example
cargo run -p ccid-example

# Cobertura de codigo (requer cargo install cargo-tarpaulin)
cargo tarpaulin --workspace --out Xml --out Html --output-dir coverage

# Fuzzing do parser CBOR (requer nightly + cargo install cargo-fuzz)
cargo +nightly fuzz run decode_cbor --fuzz-dir fuzz
```

Os mesmos comandos estão disponíveis via [`just`](https://github.com/casey/just):
`just build`, `just test`, `just test-e2e`, `just check`, `just coverage`,
`just fuzz`. Veja `just --list`.

Para um guia detalhado de compilação, testes, fuzzing e opções de build, consulte [`BUILD.md`](BUILD.md).

## CI

| Workflow | Arquivo | O que roda |
|----------|---------|------------|
| CI | `.github/workflows/ci.yml` | `cargo build/test --workspace`, `cargo fmt --check`, `cargo clippy -D warnings` |
| Dev Build | `.github/workflows/dev-build.yml` | Build debug + testes + artefatos dev (`fido2-simulator`, wheel `openkey_core`, RP2350 `.elf`/`.uf2`, `SHA256SUMS`, diagnostics) em todo push/PR |
| E2E | `.github/workflows/e2e.yml` | Compila o simulador e roda `pytest tests/python` |
| Coverage | `.github/workflows/coverage.yml` | `cargo tarpaulin` (relatórios Xml + Html como artifact) |

Detalhes do harness de fuzzing em [`fuzz/README.md`](fuzz/README.md).

## Board Profiles

| Board | AAGUID | Features |
|-------|--------|----------|
| NRF52840 | único | BLE ready, ARM CryptoCell |
| STM32L4 | único | low-power, hardware RNG |
| ESP32C3 | único | Wi-Fi/BLE, RISC-V |
| RP2350 | único | RISC-V, secure boot, trust zone |
| GENERIC | único | perfil padrão para desenvolvimento |

## Segurança

- Sem `unsafe` nas crates `protocol/*` e `firmware/*` exceto `examples/rp2350-firmware/src/qspi_flash.rs` (uso justificado no header do módulo, conforme `AGENTS.md`) e `vendor/ring` (crate externa vendida em `examples/rp2350-firmware/vendor/ring`, fora do controle do projeto)
- Nenhum log de chaves privadas, seeds ou PINs
- Nonces via `SystemRandom` (imprevisíveis)
- Comparação constant-time para PINs
- Chaves zeradas após uso quando possível
- Wear leveling no `StorageEngine` é contador informativo (`warn`-only) sem rotação de setor — documentado em `firmware/storage/src/storage.rs:447`

## Licença

Licenciado sob MIT OR Apache-2.0, conforme `license` em `Cargo.toml`.
