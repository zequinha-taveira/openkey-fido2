# openkey-fido2 — Especificação Técnica

Versão: 0.1.0
Última atualização: 2026-08-11

---

## 1. Visão Geral

**openkey-fido2** é um firmware FIDO2/WebAuthn para authenticadores embarcados, escrito em Rust. Implementa o protocolo CTAP2 (Client-to-Authenticator Protocol 2), validação WebAuthn, operações criptográficas via `ring`, e armazenamento seguro de credenciais com encryption at rest.

**Objetivo**: Fornecer uma implementação de referência, segura e modular de um autenticador FIDO2 que possa rodar em hardware embarcado (no_std) e ser testado em host (std).

---

## 2. Escopo Funcional

### 2.1 Comandos CTAP2 Implementados (Core)

| Comando | Código | Status | Descrição |
|---------|--------|--------|-----------|
| `MakeCredential` | 0x01 | ✅ | Cria credencial com attestation `none` |
| `GetAssertion` | 0x02 | ✅ | Retorna assertion com allow_list e sign counter |
| `GetInfo` | 0x04 | ✅ | Capacidades dinâmicas (algoritmos, extensões, transports) |
| `GetVersion` | 0x0F | ✅ | Retorna versões de firmware/hardware (`GetVersionResponse`) |
| `ClientPIN` | 0x06 | ✅ | getPINRetries, setPIN, changePIN, getPINToken, getPINHashEnc (ECDH keyAgreement stub) |
| `Reset` | 0x07 | ✅ | Limpeza completa de credenciais e PIN |
| `GetNextAssertion` | 0x08 | ✅ | Próxima credencial quando múltiplas |
| `EnumerateRPsInitial` | 0x3B | ✅ | Primeiro RP na enumeração |
| `EnumerateRPsNext` | 0x3C | ✅ | Próximo RP na enumeração |
| `Selection` | 0x0B | ✅ | Seleção de dispositivo (reutiliza GetVersion) |
| `BioEnroll` | 0x09 | ✅ | Stub (retorna UnsupportedOption) |

### 2.2 Extensões WebAuthn Suportadas

| Extensão | Status | Descrição |
|----------|--------|-----------|
| `credProtect` | ✅ | Política de proteção de credencial (3 níveis) |
| `credBlob` | ✅ | Blob customizado por credencial (máx 32 bytes) |
| `minPinLength` | ✅ | Comprimento mínimo de PIN discovery |
| `hmac-secret` | ✅ | Segredo compartilhado via HMAC-SHA256 |

### 2.3 Algoritmos Criptográficos

| Algoritmo | COSE ID | Uso | Status |
|-----------|---------|-----|--------|
| Ed25519 | -8 | Assinatura/Verificação | ✅ |
| ES256 (ECDSA P-256) | -7 | Assinatura/Verificação | ✅ |
| RS256 (RSA-PKCS1) | -257 | Assinatura/Verificação | ✅ |
| HMAC-SHA256 | - | Derivação, autenticação | ✅ |
| ChaCha20-Poly1305 | - | Encryption at rest | ✅ |
| SHA-256 | - | Hash | ✅ |
| X25519 + HKDF-SHA256 | - | ECIES híbrido (sealed-box efêmero) | ✅ |

### 2.4 Perfis de Board Suportados

| Board | AAGUID | Features de Segurança |
|-------|--------|----------------------|
| NRF52840 | Único | BLE ready, ARM CryptoCell |
| STM32L4 | Único | Low-power, hardware RNG |
| ESP32C3 | Único | Wi-Fi/BLE, RISC-V |
| RP2350 | Único | RISC-V, secure boot, trust zone |
| GENERIC | Único | Perfil padrão desenvolvimento |

---

## 3. Arquitetura

### 3.1 Diagrama de Camadas

```
┌─────────────────────────────────────────────────────────────────┐
│                    EmbeddedAuthenticator (authenticator)         │
│   Coordena todas as camadas e expõe a API final                │
└───────────────┬────────────────────────────────────────────────┘
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

### 3.2 Crates e Responsabilidades

| Crate | Caminho | Responsabilidade Principal |
|-------|---------|---------------------------|
| `authenticator` | `firmware/authenticator/` | API final `EmbeddedAuthenticator`, orquestração |
| `webauthn` | `protocol/webauthn/` | Validação requests WebAuthn, delega ao CTAP2 |
| `ctap2` | `protocol/ctap2/` | Estado CTAP2, handlers de comandos, ClientPIN, attestation |
| `crypto` | `protocol/crypto/` | Primitivas criptográficas (Ed25519, ES256, HMAC, ChaCha20-Poly1305, ECIES) |
| `storage` | `firmware/storage/` | `StorageEngine`, backends (File, Flash), encryption at rest |
| `board-generic` | `firmware/board-generic/` | HAL, `BoardDefinition`, 5 perfis pré-definidos |
| `device-profile` | `firmware/device-profile/` | `DeviceProfileBuilder`, capability discovery, overrides |
| `transport` | `firmware/transport/` | Trait `Transport` + stubs (USB-HID, CCID, NFC, BLE) |
| `fido2-simulator` | `simulator/` | Binário host, JSON line protocol para testes |
| `test-suite` | `tests/` | Testes integração Rust + Python E2E |

### 3.3 Grafo de Dependências

```
authenticator        ──► webauthn, ctap2, crypto, storage, board-generic,
                        device-profile, transport
webauthn             ──► ctap2, crypto, storage
ctap2                ──► crypto, storage
storage              ──► crypto
device-profile       ──► board-generic, ctap2
crypto, board-generic, transport ──► (sem dependências internas)
```

**Regra**: Setas apontam de quem depende para quem é dependido. Zero dependências circulares.

---

## 4. Fluxos de Dados Principais

### 4.1 MakeCredential

```
Host → CTAP2 Command (CBOR)
       ↓
EmbeddedAuthenticator.process_command()
       ↓
Ctap2Authenticator.make_credential()
       ├─→ CryptoEngine.generate_key_pair() (Ed25519) / generate_p256_key_pair() / generate_rsa_key_pair()
       ├─→ StorageEngine.store_credential() (encryption at rest)
       └─→ Attestation (Packed/Self/None) em `attestation_info` (BTreeMap)
       ↓
CTAP2 Response (CBOR) → Host
```

### 4.2 GetAssertion

```
Host → CTAP2 Command (CBOR) com allow_list
       ↓
EmbeddedAuthenticator.process_command()
       ↓
Ctap2Authenticator.get_assertion()
       ├─→ StorageEngine.get_credential() + find_by_rp_id() (allow_list)
       ├─→ CryptoEngine.sign() / sign_p256() / sign_rsa() com credencial privada
       ├─→ Sign counter increment (update_sign_count, em memória)
       └─→ Se múltiplas: estado get_next_assertion_state
       ↓
CTAP2 Response (CBOR) → Host
```

### 4.3 ClientPIN

```
Host → ClientPIN(subCommand=setPIN, newPinEnc, pinAuth)
       ↓
handle_client_pin() (free fn)
       ├─→ Decrypt newPinEnc/pinHashEnc com ChaCha20-Poly1305 (nonce fixo [0u8; 12])
       ├─→ Hash PIN com SHA-256
       ├─→ Armazenar pin_hash no storage (sem salt)
       └─→ Reset retry counter = 8
       (ECDH X25519 e validação de pinProtocol ainda não implementados)
       ↓
Response: success
```

---

## 5. Estruturas de Dados Core

### 5.1 Credential e StoredCredential (armazenada)

```rust
struct Credential {
    credential_id: Vec<u8>,          // Credential ID opaco entregue ao RP
    public_key: Vec<u8>,             // Chave pública no formato bruto do algoritmo
    private_key: Vec<u8>,            // Vazia quando a credencial está persistida
    sign_count: u32,                 // Contador de assinaturas (monotônico)
    rp_id_hash: Vec<u8>,             // SHA-256(rp_id)
    user_handle: Option<Vec<u8>>,    // user.id (discoverable credentials)
    cred_blob: Vec<u8>,              // Extensão credBlob (máx. 32 bytes)
    created_at: u64,                 // Timestamp de criação
    algorithm: i32,                  // COSE (-8 EdDSA, -7 ES256, -257 RS256)
    rp_id: String,                   // RP ID plaintext (para EnumerateRPs)
}

struct StoredCredential {
    credential: Credential,          // Credential com private_key vazia
    encrypted_private_key: Vec<u8>,  // Chave privada cifrada (ChaCha20-Poly1305)
    nonce: Vec<u8>,                  // Nonce de 12 bytes, único por credencial
}
```

### 5.2 DeviceProfile

```rust
struct DeviceProfile {
    product_name: &'static str,
    vendor_name: &'static str,
    aaguid: [u8; 16],
    firmware_version: &'static str,
    hardware_version: &'static str,
    transports: Vec<Transport>,     // UsbCcid, UsbHid, Nfc, Ble
    protocols: Vec<Protocol>,       // Ctap2, Ctap21, U2f, WebAuthn
    attestation: AttestationType,   // None, Packed, SelfAttested
    attestation_format: AttestationFormat,
    attestation_cert: Option<AttestationCertificate>,
    pin_policy: PinPolicy,          // Disabled, Optional, Required
    rk_support: bool,
    uv_support: bool,
    up_support: bool,
    storage_encrypted: bool,
    crypto_accelerator: bool,
    extensions: Vec<Extension>,     // CredProtect, CredBlob, MinPinLength, HmacSecret
    max_credentials: u16,
    max_credential_id_length: u16,
    max_cred_blob_length: u32,
    rp_count: u32,
    transport_config: Option<TransportConfig>,
    security: SecurityFeatures,
}
```

`DeviceProfile.firmware_version` permanece uma string semver para configuração
do produto. O campo `firmwareVersion` do `GetInfo` é convertido para inteiro
CTAP 2.1 conforme o ADR-0020; `GetVersion` mantém sua resposta textual.

### 5.3 SecurityFeatures

```rust
struct SecurityFeatures {
    secure_boot: bool,
    trust_zone: bool,
    hardware_rng: bool,
    sha256_accelerator: bool,
    debug_disable: bool,
    otp_memory: bool,
    unique_id: bool,
    tamper_detection: bool,
}
```

---

## 6. Interfaces (Traits)

### 6.1 Transport Trait

```rust
pub trait Transport: Send + Sync {
    fn init(&mut self) -> Result<(), TransportError>;
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError>;
    fn recv(&mut self) -> Result<Vec<u8>, TransportError>;
    fn close(&mut self) -> Result<(), TransportError>;
}
```

### 6.2 StorageBackend Trait

```rust
pub trait StorageBackend: Send + Sync {
    fn read(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError>;
    fn write(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError>;
    fn delete(&mut self, key: &str) -> Result<(), StorageError>;
    fn list_keys(&self) -> Result<Vec<String>, StorageError>;
}
```

### 6.3 ClientPin Trait

```rust
pub trait ClientPin {
    fn get_pin_retries(&self) -> u8;
    fn get_pin_token(&mut self) -> Result<Vec<u8>, Ctap2Error>;
    fn set_pin(&mut self, pin: &[u8]) -> Result<(), Ctap2Error>;
    fn change_pin(&mut self, old_pin: &[u8], new_pin: &[u8]) -> Result<(), Ctap2Error>;
    fn get_pin_hash_enc(&mut self) -> Result<Vec<u8>, Ctap2Error>;
    fn reset_pin_retries(&mut self);
    fn decrement_pin_retries(&mut self);
    fn verify_pin(&mut self, pin: &[u8]) -> Result<(), Ctap2Error>;
}
```

---

## 7. Requisitos Não-Funcionais

### 7.1 Segurança

- **Zero `unsafe`**: Nenhum bloco `unsafe` sem ADR justificando
- **Zeroização**: Chaves privadas zeradas no drop (`Zeroize` derive)
- **Constant-time**: Comparação de PINs/tokens em tempo constante
- **Nonces imprevisíveis**: `SystemRandom` (ring) para todos os nonces
- **Rate limiting PIN**: Bloqueio após 3 falhas consecutivas, exige power cycle
- **Sem logs sensíveis**: Nenhum log de chaves privadas, seeds, PINs
- **Encryption at rest**: Chaves privadas nunca em plaintext no storage
- **AAD em ECIES**: Chave pública efêmera como AAD no sealed-box

### 7.2 Compatibilidade

- **MSRV**: Rust 1.70+
- **no_std**: ❌ ainda não implementado — crypto/ctap2/storage usam `std` (ex.: `std::fs`, `HashMap`); apenas `hybrid.rs` e `client_pin.rs` usam `alloc`
- **Embedded targets**: ARM Cortex-M (thumbv7em-none-eabihf), RISC-V (riscv32imc-unknown-none-elf)
- **Host targets**: x86_64, aarch64 (Linux, macOS, Windows)

### 7.3 Performance

- **Sign counter**: Persistência atômica, sem blocking I/O no path crítico
- **Credential lookup**: O(1) por ID, O(n) por RP ID (n = credenciais do RP)
- **Memory**: < 64KB RAM para operação típica (excluindo buffers de transporte)

---

## 8. Formatos de Serialização

### 8.1 CBOR (CTAP2)

Todos os comandos/respostas CTAP2 usam CBOR (RFC 8949) com encoding determinístico.

### 8.2 COSE Keys

Chaves públicas no formato COSE (RFC 9052):
- Ed25519: kty=1 (OKP), crv=6 (Ed25519), x=public_key
- ES256: kty=2 (EC2), crv=1 (P-256), x, y coordenadas
- RS256: kty=3 (RSA), n=modulus, e=exponent

### 8.3 JSON Line Protocol (Simulador)

```
{"type": "request", "command": 0x01, "payload": {...}}
{"type": "response", "status": 0x00, "payload": {...}}
{"type": "event", "event": "button_press", "data": {...}}
```

---

## 9. Testes

### 9.1 Estratégia

| Camada | Tipo | Local | Cobertura Alvo |
|--------|------|-------|----------------|
| Crypto | Unitário | `protocol/crypto/src/*.rs` | 100% funções públicas |
| CTAP2 | Unitário | `protocol/ctap2/src/*.rs` | 90%+ handlers |
| Storage | Unitário | `firmware/storage/src/*.rs` | 90%+ engine |
| Device Profile | Unitário | `firmware/device-profile/src/*.rs` | 100% builders |
| Transport | Unitário | `firmware/transport/src/*.rs` | 100% stubs |
| Integração | Integração | `tests/src/lib.rs` | Fluxos MakeCredential/GetAssertion |
| E2E | Python | `tests/python/test_*.py` | Cenários reais via simulador |
| Fuzzing | CBOR parser | `fuzz/` | `decode_cbor` harness |

### 9.2 Comandos de Validação

```bash
# Lint + Formatação
cargo fmt --check --workspace
cargo clippy --workspace -- -D warnings

# Testes Unitários + Integração
cargo test --workspace

# Testes E2E
cargo build -p fido2-simulator
python -m pytest tests/python -v

# Cobertura
cargo tarpaulin --workspace --out Xml --out Html

# Fuzzing (nightly)
cargo +nightly fuzz run decode_cbor --fuzz-dir fuzz
```

---

## 10. CI/CD

### 10.1 Workflows

| Workflow | Trigger | Jobs |
|----------|---------|------|
| CI | push, PR | build-test (cargo build/test), lint (fmt+clippy), fuzz-smoke (60s) |
| E2E | push, PR | build simulator/examples, pytest tests/python |
| Coverage | push, PR, workflow_dispatch | cargo tarpaulin, upload artifacts |
| Release | push main, release created, workflow_dispatch | build, test, artifacts, GitHub Release |

### 10.2 Gates de Merge

- ✅ `cargo build --workspace` passa
- ✅ `cargo test --workspace` passa
- ✅ `cargo fmt --check --workspace` passa
- ✅ `cargo clippy --workspace -- -D warnings` passa
- ✅ Testes E2E Python passam
- ⚠️ Cobertura ≥ 80% (linhas) — meta ainda não aplicada no CI (sem gate configurado)

---

## 11. Versionamento e Release

- **SemVer**: MAJOR.MINOR.PATCH
- **MSRV policy**: Mínimo 6 meses sem bump, documentado em CHANGELOG
- **Release artifacts**: Binários (simulator, exemplos), wheel Python `openkey_core`, docs
- **Changelog**: `CHANGELOG.md` (ainda não criado)

---

## 12. Documentação Associada

| Arquivo | Propósito |
|---------|-----------|
| `README.md` | Visão geral, comandos, badges |
| `AGENTS.md` | Guia do agente (fluxo de trabalho obrigatório) |
| `TODO.md` | Estado do projeto, incrementos rastreados |
| `CONTRIBUTING.md` | Padrões de código, testes, processo PR |
| `architecture.md` | Diagramas, contratos, fluxos de dados |
| `docs/adr/ADR-*.md` | Decisões de arquitetura |
| `spec.md` | Este arquivo — especificação técnica completa |

---

## 13. Rastreabilidade (ADRs)

| ADR | Título | Impacto na Spec |
|-----|--------|-----------------|
| ADR-0001 | ring para criptografia | Seção 7.1, 2.3 |
| ADR-0002 | Simulador JSON line protocol | Seção 8.3 |
| ADR-0003 | Arquitetura em camadas | Seção 3.1, 3.2 |
| ADR-0004 | std vs no_std | Seção 7.2 |
| ADR-0005 | Isolamento contexto agentes | Processo dev (AGENTS.md) |
| ADR-0006 | Side-channel mitigation | Seção 7.1 (constant-time, zeroize) |
| ADR-0007 | Arquitetura execução subagents | Processo dev |
| ADR-0008 | Sealed-box efêmero ECIES | Seção 2.3 (X25519+HKDF+ChaCha20) |
| ADR-0018 | Roteamento progressivo de contexto | Processo dev (AGENTS.md e subagents) |
| ADR-0019 | Subagent ciclo de defeitos ponta a ponta | Processo dev (defect-cycle) |

---

## 14. Glossário

| Termo | Definição |
|-------|-----------|
| AAGUID | Authenticator Attestation GUID (16 bytes, identifica modelo) |
| CTAP2 | Client-to-Authenticator Protocol versão 2 |
| COSE | CBOR Object Signing and Encryption (RFC 9052) |
| ECIES | Elliptic Curve Integrated Encryption Scheme |
| RP | Relying Party (serviço que solicita autenticação) |
| UV | User Verification (verificação de usuário: PIN, biometria) |
| Sign Counter | Contador monotônico por credencial (anti-clone) |
| CredProtect | Extensão que define política de proteção da credencial |
| CredBlob | Extensão para armazenar blob customizado (≤32 bytes) |

---

## 15. Apêndice: Códigos de Erro CTAP2 Principais

| Código | Nome | Uso |
|--------|------|-----|
| 0x00 | CTAP1_ERR_SUCCESS / CTAP2_OK | Sucesso |
| 0x01 | CTAP2_ERR_INVALID_COMMAND | Comando inválido |
| 0x02 | CTAP2_ERR_INVALID_PARAMETER | Parâmetro inválido |
| 0x03 | CTAP2_ERR_INVALID_LENGTH | Tamanho inválido |
| 0x04 | CTAP2_ERR_INVALID_SEQ | Sequência inválida |
| 0x05 | CTAP2_ERR_TIMEOUT | Timeout |
| 0x06 | CTAP2_ERR_CHANNEL_BUSY | Canal ocupado |
| 0x07 | CTAP2_ERR_LOCK_REQUIRED | Lock necessário |
| 0x08 | CTAP2_ERR_INVALID_CHANNEL | Canal inválido |
| 0x09 | CTAP2_ERR_CBOR_UNEXPECTED_TYPE | Tipo CBOR inesperado |
| 0x0A | CTAP2_ERR_INVALID_CBOR | CBOR inválido |
| 0x0B | CTAP2_ERR_MISSING_PARAMETER | Parâmetro obrigatório ausente |
| 0x0C | CTAP2_ERR_LIMIT_EXCEEDED | Limite excedido |
| 0x0D | CTAP2_ERR_UNSUPPORTED_EXTENSION | Extensão não suportada |
| 0x0E | CTAP2_ERR_CREDENTIAL_EXCLUDED | Credencial excluída |
| 0x10 | CTAP2_ERR_PROCESSING | Processando |
| 0x11 | CTAP2_ERR_INVALID_CREDENTIAL | Credencial inválida |
| 0x12 | CTAP2_ERR_USER_ACTION_PENDING | Ação do usuário pendente |
| 0x13 | CTAP2_ERR_OPERATION_DENIED | Operação negada |
| 0x14 | CTAP2_ERR_KEY_STORE_FULL | Armazenamento cheio |
| 0x15 | CTAP2_ERR_NO_OPERATIONS | Nenhuma operação pendente |
| 0x16 | CTAP2_ERR_UNSUPPORTED_ALGORITHM | Algoritmo não suportado |
| 0x17 | CTAP2_ERR_INVALID_CREDENTIAL_MANAGEMENT | Gerenciamento credencial inválido |
| 0x18 | CTAP2_ERR_PIN_INVALID | PIN inválido |
| 0x19 | CTAP2_ERR_PIN_AUTH_INVALID | PIN auth inválido |
| 0x1A | CTAP2_ERR_PIN_AUTH_BLOCKED | PIN auth bloqueado |
| 0x1B | CTAP2_ERR_PIN_NOT_SET | PIN não configurado |
| 0x1C | CTAP2_ERR_PIN_REQUIRED | PIN requerido |
| 0x1D | CTAP2_ERR_UV_BLOCKED | UV bloqueado |

---

*Fim da especificação*
