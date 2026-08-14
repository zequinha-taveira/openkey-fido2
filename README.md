# openkey-fido2

[![CI](https://github.com/zequinha-taveira/openkey-fido2/actions/workflows/ci.yml/badge.svg)](https://github.com/zequinha-taveira/openkey-fido2/actions/workflows/ci.yml)
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
- **GetInfo** — capacidades dinâmicas (algoritmos, extensões, transports)
- **GetNextAssertion** — suporte a múltiplas credenciais
- **Reset** — limpeza de credenciais e PIN
- **Selection** — seleção de dispositivo

### ClientPIN (CTAP2 §6)
- `getPINRetries` — contador de tentativas (inicial: 8)
- `setPIN` — configurar PIN (mínimo 4 bytes)
- `changePIN` — trocar PIN com verificação
- `getPINToken` — derivar token via HMAC-SHA256
- `getPINHashEnc` — hash criptografado do PIN
- Bloqueio após 3 tentativas consecutivas
- PIN protocols 1 e 2 suportados

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
- **FlashStorageBackend** — stub para flash embedded
- **Wear leveling** — rotação de writes
- **Credential pruning** — LRU quando `max_credential_count` atingido

### Transportes
- **USB-HID** stub — placeholder para implementação futura
- **CCID** stub — interface para smartcard

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

- Sem blocos `unsafe` no codebase
- Nenhum log de chaves privadas, seeds ou PINs
- Nonces via `SystemRandom` (imprevisíveis)
- Comparação constant-time para PINs
- Chaves zeradas após uso quando possível

## Licença

Licenciado sob MIT OR Apache-2.0, conforme `license` em `Cargo.toml`.
