# Documentação de Arquitetura do openkey-fido2

Diagrama de dependências entre os crates do projeto:

```
┌─────────────────────────────────────────────────────────────────┐
│                    openkey-fido2 (workspace)                     │
│                                                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    Cargo.toml                             │  │
│  │  workspace: [dependencies]                                 │  │
│  │  ├── ring → crypto/                                      │  │
│  │  ├── thiserror → ctap2/                                  │  │
│  │  ├── serde → ctap2/, webauthn/, crypto/                  │  │
│  │  ├── ciborium → ctap2/, simulator/                       │  │
│  │  └── rsa → crypto/                                       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │               firmware/                                   │  │
│  │                                                             │  │
│  │  ├── authenticator/   → Coordena todas as camadas.       │  │
│  │  │   └── EmbeddedAuthenticator (API final)                │  │
│  │  ├── board-generic/   → HAL e perfis pré-definidos        │  │
│  │  │   └── profiles.rs + board_generic.rs                    │  │
│  │  ├── device-profile/  → Configuração de produto           │  │
│  │  ├── ctap2/           → CTAP2 protocolo                   │  │
│  │  │   ├── ctap2.rs (handler, request/response)           │  │
│  │  │   ├── crypto/ (client_pin, attestation, etc.)        │  │
│  │  │   └── storage/ (storage-engine)                       │  │
│  │  ├── crypto/          → Operações criptográficas         │  │
│  │  │   ├── ed25519.rs (key pair)                           │  │
│  │  │   ├── hmac_sha256.rs (key derivation)                 │  │
│  │  │   └── ecies.rs (ECIES encryption)                    │  │
│  │  ├── storage/         → Armazenamento de credenciais     │  │
│  │  │   └── storage.rs (StorageEngine)                      │  │
│  │  ├── transport/        → Abstração de transportes       │  │
│  │  └── webauthn/         → Validação de requests WebAuthn  │  │
│  │       └── ctap2/ → delega ao CTAP2                     │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              simulator/                                   │  │
│  │  Exposi o firmware via JSON line protocol para testes    │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              tests/                                       │  │
│  │  Rust + Python (simulador) + E2E examples                  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

## Crates e Responsabilidades

### `authenticator` (firmware/authenticator/)
Coordena todas as camadas. `EmbeddedAuthenticator` é a API final.

### `webauthn` (protocol/webauthn/)
Validação de requests WebAuthn, delega ao CTAP2.

### `ctap2` (protocol/ctap2/)
Implementação do estado CTAP2 (MakeCredential, GetAssertion, GetInfo, etc.).

### `crypto` (protocol/crypto/)
Operações criptográficas (Ed25519, HMAC-SHA256, ChaCha20-Poly1305, SHA-256).

### `storage` (firmware/storage/)
Armazenamento de credenciais com encryption at rest.

### `board-generic` (firmware/board-generic/)
HAL e perfis pré-definidos de boards (NRF52840, STM32L4, RP2350, etc.).

### `device-profile` (firmware/device-profile/)
Configuração de produto e capability discovery.

### `fido2-simulator` (simulator/)
Binário host que expõe o firmware via JSON line protocol para testes.

### `examples` (examples/)
Exemplos mínimos de uso do EmbeddedAuthenticator.

### `tests` (tests/)
Testes de integração Rust e E2E Python.

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

- `AGENTS.md` — guia do agente (estado deste repositório)
- `TODO.md` — estado do projeto
- `README.md` — visão geral e como compilar
- `docs/adr/` — decisões de arquitetura
- `CONTRIBUTING.md` — padrões de código e testes