# Arquitetura do openkey-fido2

## Visão Geral

O projeto é um firmware FIDO2/WebAuthn para authenticadores embarcados, escrito em Rust. Ele implementa CTAP2 (Client-Tangent Application Protocol), WebAuthn, criptografia segura e armazenamento de credenciais com encryption at rest.

## Diagrama de Camadas

```
┌─────────────────────────────────────────────────────────────────┐
│                    EmbeddedAuthenticator (authenticator)         │
│   Coordena todas as camadas e expõe a API final                │
└───────────────┬────────────────────────────────────────────────┘
                │
    ┌──────────┼──────────┐
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

## Camadas e Responsabilidades

### `authenticator` (`firmware/authenticator/`)
- Coordena todas as camadas. `EmbeddedAuthenticator` é a API final.
- Orquestra CTAP2, WebAuthn, storage e board-generic.

### `webauthn` (`protocol/webauthn/`)
- Validação de requests WebAuthn, delega ao CTAP2.

### `ctap2` (`protocol/ctap2/`)
- Implementação do estado CTAP2 (MakeCredential, GetAssertion, GetInfo, etc.).
- Módulos: `ctap2.rs` (handler, request/response), `crypto/` (ClientPIN, attestation, etc.), `storage/` (storage-engine).

### `crypto` (`protocol/crypto/`)
- Operações criptográficas (Ed25519, ES256, HMAC-SHA256, ChaCha20-Poly1305, SHA-256).

### `storage` (`firmware/storage/`)
- Armazenamento de credenciais com encryption at rest.
- `StorageEngine` com `FileStorageBackend` e `FlashStorageBackend`.

### `board-generic` (`firmware/board-generic/`)
- HAL e perfis pré-definidos de boards (NRF52840, STM32L4, RP2350, etc.).

### `device-profile` (`firmware/device-profile/`)
- Configuração de produto e capability discovery.
- `DeviceProfileBuilder` com overrides.

### `transport` (`firmware/transport/`)
- Abstração de transportes (USB-HID, CCID, NFC, BLE GATT).

### `fido2-simulator` (`simulator/`)
- Binário host que expõe o firmware via JSON line protocol para testes.

### `examples` (`examples/`)
- Exemplos mínimos de uso do EmbeddedAuthenticator.

### `tests` (`tests/`)
- Testes de integração Rust e E2E Python.

## Dependências entre Crates

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

**Regra**: setas apontam de quem depende para quem é dependido. Nunca crie dependências circulares.

## Fluxo de Dados

1. **Autenticação**: CTAP2 protocolo (ctap2/) → Hardware (CTAP2 authenticator)
2. **Validação**: WebAuthn (webauthn/) → CTAP2 (ctap2/)
3. **Criptografia**: Crypto (crypto/) → Storage (storage/)
4. **Armazenamento**: StorageEngine → Credential descriptografado → Crypto
5. **Board Profile**: DeviceProfile → BoardDefinition → Hardware
6. **Capability Discovery**: GetInfo → DeviceProfile → CTAP2 auth

## Documentação

| Arquivo | Propósito |
|---------|-----------|
| `AGENTS.md` | Guia do agente (estado do repositório) |
| `TODO.md` | Estado do projeto e incrementos |
| `README.md` | Visão geral e como compilar |
| `docs/adr/` | Decisões de arquitetura (ADR) |
| `CONTRIBUTING.md` | Padrões de código e testes |
