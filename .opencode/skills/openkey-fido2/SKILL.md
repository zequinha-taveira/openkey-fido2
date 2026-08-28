---
name: openkey-fido2
description: Use when working on the openkey-fido2 project — a FIDO2/WebAuthn authenticator firmware written in Rust. Covers project overview, architecture, how to build/test, and current state. Trigger on mentions of FIDO2, WebAuthn, CTAP2, authenticator, openkey, or when working in this repository.
---

# openkey-fido2 — Project Overview

## What It Is

Openkey-fido2 is an embedded FIDO2/WebAuthn authenticator firmware written in Rust. It implements the CTAP2 (Client to Authenticator Protocol v2) and WebAuthn standards for passwordless authentication.

The project is structured as a Cargo workspace with 16 crates covering protocol implementation, cryptography, storage, board abstraction, transports, examples, and host tooling.

## Context Routing

Load this skill only when the task concerns openkey-fido2 or its FIDO2/WebAuthn
implementation. It is the final project-specific context layer in the route
defined by `AGENTS.md` and ADR-0018:

```text
Issue → AGENTS.md → relevant specification → relevant ADR →
relevant source files → relevant skill
```

Use the skill for project conventions, structure, and current-state pointers.
Do not treat it as a replacement for protocol specifications, ADRs, or source
code.

## Current State

### Completed (✅)
- Core CTAP2: MakeCredential, GetAssertion, GetInfo, GetVersion, Reset, Selection, GetNextAssertion, LargeBlobs, Credential Management, and Enterprise Attestation
- ClientPIN CTAP 2.1 wire format with protocols 1 and 2, retry handling, permissions, and Python conformance coverage
- WebAuthn extensions: credProtect, credBlob, minPinLength, hmac-secret, and largeBlobKey
- Crypto: Ed25519, ES256, ES384, PS256, RS256, HMAC-SHA256, SHA-256, ChaCha20-Poly1305, hybrid X25519, and SystemRandom nonces
- Storage: encryption at rest, file and simulated flash backends, wear leveling, credential pruning, RP enumeration, and sign counter persistence (in-memory and backend, with restart coverage)
- Device Profile: BoardDefinition builder, DeviceProfileBuilder, CapabilityDiscovery, security features, and five board profiles
- Attestation: None, Packed, and Self formats with configurable device profiles
- Transport infrastructure: CTAPHID framing, channel management, reference HALs, USB-HID/CCID adapters, and the RP2350 usb-device backend
- Conformance tooling: raw CBOR simulator mode, Python CTAP 2.1 tests, and the virtual CTAPHID bridge
- GetInfo `firmwareVersion` exposed as a CTAP 2.1 integer with deterministic profile mapping
- Quick Wins: credProtect enum, Reset, Selection, justfile, and docs metadata

### Remaining Work (🚧)
- Implement built-in UV and `getUVRetries` when supported by hardware
- Connect concrete board drivers to the authenticator for USB-HID and USB-CCID
- Integrate NFC ISO 14443 and BLE GATT stacks; current types remain hardware stubs
- Validate firmware on physical boards (probe-rs flashing, USB enumeration, browser flows)
- Run FIDO Conformance Tool and artifact signing when external access and protected secrets are available

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
