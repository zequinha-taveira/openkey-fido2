---
name: openkey-fido2
description: Use when working on the openkey-fido2 project — a FIDO2/WebAuthn authenticator firmware written in Rust. Covers project overview, architecture, how to build/test, and current state. Trigger on mentions of FIDO2, WebAuthn, CTAP2, authenticator, openkey, or when working in this repository.
---

# openkey-fido2 — Project Overview

## What It Is

Openkey-fido2 is an embedded FIDO2/WebAuthn authenticator firmware written in Rust. It implements the CTAP2 (Client to Authenticator Protocol v2) and WebAuthn standards for passwordless authentication.

The project is structured as a Cargo workspace with 11 crates covering protocol implementation, cryptography, storage, board abstraction, and a host simulator for testing.

## Current State

### Completed (✅)
- Core CTAP2: MakeCredential, GetAssertion, GetInfo, GetVersion, ProcessCommand
- Crypto: Ed25519, HMAC-SHA256, SHA-256, ChaCha20-Poly1305, SystemRandom nonces
- Storage: Encryption at rest, credential lookup, sign counter, encrypted private keys
- Device Profile: BoardDefinition builder, DeviceProfileBuilder, CapabilityDiscovery
- 5 pre-defined board profiles: NRF52840, STM32L4, ESP32C3, RP2350, GENERIC
- All Quick Wins: CredProtect enum, Reset handler, Selection handler, justfile, docs metadata

### Not Started (❌)
- ClientPIN (CTAP2 0x06)
- WebAuthn Extensions integration (credProtect in MakeCredential, credBlob, minPinLength, hmac-secret)
- Real persistence backends (FileStorage, FlashStorage)
- Additional algorithms: ES256, RS256
- Transports: USB-HID, CCID, NFC, BLE GATT
- Attestation formats: Packed, Self
- Remaining CTAP2 commands: GetNextAssertion, EnumerateRPs, BioEnroll

## Workspace Structure

```
├── firmware/
│   ├── authenticator/    ← EmbeddedAuthenticator (final API)
│   ├── storage/          ← Credential storage with encryption at rest
│   ├── board-generic/    ← HAL and board profiles
│   └── device-profile/   ← Product config and capability discovery
├── protocol/
│   ├── ctap2/            ← CTAP2 state machine (MakeCredential, GetAssertion, etc.)
│   ├── crypto/           ← Cryptographic operations (Ed25519, HMAC, SHA, ChaCha20)
│   └── webauthn/         ← WebAuthn request validation
├── simulator/            ← Host binary exposing firmware via JSON line protocol
├── tests/                ← Rust integration tests + Python E2E tests
├── examples/
│   ├── basic/            ← Minimal usage example
│   └── ccid/             ← CCID transport example
├── docs/adr/             ← Architecture Decision Records
├── AGENTS.md             ← Agent workflow guide
├── TODO.md               ← Increment tracking
└── README.md             ← Build/usage instructions
```

## Key Dependencies

```
authenticator
    ├── webauthn
    │   └── ctap2
    │       ├── crypto
    │       └── storage
    │           └── crypto
    ├── board-generic
    └── device-profile
        └── board-generic
```

## Build & Test Commands

```bash
# Build entire workspace
cargo build --workspace

# Run all Rust tests
cargo test --workspace

# Run E2E tests (requires simulator compiled)
cargo build -p fido2-simulator
python -m pytest tests/python -v

# Lint and format check
cargo fmt --check --workspace
cargo clippy --workspace -- -D warnings

# Run simulator interactively
cargo run -p fido2-simulator

# Run examples
cargo run -p basic-example
cargo run -p ccid-example
```

## Conventions

- Language: pt-BR for docs/comments, English for code
- Errors: Use `thiserror` for crate errors, map to `Ctap2Error` at protocol boundaries
- No `unsafe` without ADR justification
- No logging of cryptographic material
- One PR = one logical change
- Tests required for new code (Rust + Python E2E when applicable)

## Key Files

| File | Purpose |
|------|---------|
| `AGENTS.md` | Mandatory workflow guide for agents |
| `TODO.md` | Current increment state and planned work |
| `README.md` | How to build and run |
| `docs/adr/` | Architecture decisions |
| `protocol/ctap2/src/ctap2.rs` | Main CTAP2 command dispatch and handlers |
| `firmware/storage/src/storage.rs` | Credential storage engine |
| `firmware/authenticator/src/authenticator.rs` | Final `EmbeddedAuthenticator` API |
