# openkey-fido2

[![Coverage](https://github.com/zequinha-taveira/openkey-fido2/actions/workflows/coverage.yml/badge.svg)](https://github.com/zequinha-taveira/openkey-fido2/actions/workflows/coverage.yml)
[![Nightly](https://github.com/zequinha-taveira/openkey-fido2/actions/workflows/nightly.yml/badge.svg)](https://github.com/zequinha-taveira/openkey-fido2/actions/workflows/nightly.yml)
[![CodeQL](https://github.com/zequinha-taveira/openkey-fido2/actions/workflows/codeql.yml/badge.svg)](https://github.com/zequinha-taveira/openkey-fido2/actions/workflows/codeql.yml)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![Licença](https://img.shields.io/badge/licen%C3%A7a-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

Autenticador FIDO2/WebAuthn embarcado em Rust: protocolo CTAP2, criptografia via `ring`, armazenamento com encryption at rest e firmware bare-metal (`no_std`) para RP2350, nRF52840 e STM32L4.

## Mapa de crates

| Crate | Caminho | Responsabilidade |
|-------|---------|------------------|
| `authenticator` | `firmware/authenticator/` | `EmbeddedAuthenticator`, API final |
| `webauthn` | `protocol/webauthn/` | Validação WebAuthn, delega ao CTAP2 |
| `ctap2` | `protocol/ctap2/` | MakeCredential, GetAssertion, ClientPIN, etc. |
| `crypto` | `protocol/crypto/` | Ed25519, P-256/P-384, RSA, HMAC, ChaCha20-Poly1305 |
| `storage` | `firmware/storage/` | Credenciais com encryption at rest |
| `board-generic` | `firmware/board-generic/` | HAL e profiles de boards |
| `device-profile` | `firmware/device-profile/` | Configuração de produto e capabilities |
| `fido2-simulator` | `simulator/` | Binário host (JSON line protocol) para testes |
| `test-suite` | `tests/` | Testes de integração Rust + E2E Python |

Dependências: `authenticator → webauthn → ctap2 → crypto/storage`. Sem dependências circulares.

## Quickstart

Pré-requisitos: Rust 1.85+, Python 3.10+ (E2E), `just` opcional. Detalhes em [`BUILD.md`](BUILD.md).

```bash
cargo build --workspace      # compila tudo
cargo test --workspace       # testes Rust
cargo build -p fido2-simulator
python -m pytest tests/python -v   # testes E2E
cargo fmt --check --workspace
cargo clippy --workspace -- -D warnings
```

Com `just`: `just build`, `just test`, `just test-e2e`, `just sim`, `just check`.

## Simulador e firmware

- `cargo run -p fido2-simulator` — expõe o firmware via stdin/stdout (`--raw-cbor` para framing binário).
- Firmware RP2350: `just build-rp2350-uf2` (requer `gcc-arm-none-eabi`); validação física em [`docs/hardware/rp2350-zero-validation.md`](docs/hardware/rp2350-zero-validation.md).
- **Identidade USB:** The default USB identity pid.codes is `0x1209:0x0001`; the YubiKey USB identity that ykman / Yubico Authenticator auto-recognize is the opt-in VID:PID=Yubikey5 (`0x1050:0x0407`) build, not for distribution.

## Documentação

- [`AGENTS.md`](AGENTS.md) — guia do agente e fluxo de trabalho
- [`TODO.md`](TODO.md) — estado do projeto e incrementos
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — padrões de código e PRs
- [`docs/architecture.md`](docs/architecture.md) — arquitetura e fluxos
- [`docs/adr/`](docs/adr/) — decisões de arquitetura
- [`SECURITY.md`](SECURITY.md) — política de segurança
- [`CHANGELOG.md`](CHANGELOG.md) — histórico de versões

## Segurança

Sem `unsafe` sem justificativa em ADR, sem log de material sensível, nonces via `SystemRandom`. Mudanças em `protocol/crypto/` exigem revisão e testes de regressão. Ver [`SECURITY.md`](SECURITY.md).

## Licença

MIT OR Apache-2.0 ([`LICENSE-MIT`](LICENSE-MIT), [`LICENSE-APACHE`](LICENSE-APACHE)).
