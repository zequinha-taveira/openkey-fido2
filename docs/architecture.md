# Arquitetura do openkey-fido2

## Visão Geral

Firmware FIDO2/WebAuthn em Rust para authenticators embarcados. A arquitetura
é em camadas com dependências unidirecionais: camadas superiores dependem de
inferiores, nunca o contrário.

## Diagrama de Dependências

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         EmbeddedAuthenticator                           │
│                         (firmware/authenticator)                        │
│   Coordena todas as camadas e expõe a API final                         │
└───────────────┬─────────────────────────────────────────────────────────┘
                │
    ┌───────────┼───────────┬───────────────────┐
    ▼           ▼           ▼                   ▼
┌────────┐ ┌─────────┐ ┌──────────────┐ ┌────────────────┐
│webauthn│ │ device  │ │  board       │ │   transport    │
│        │ │-profile │ │ -generic     │ │                │
└───┬────┘ └────┬────┘ └──────┬───────┘ └────────────────┘
    │           │             │
    ▼           ▼             │
┌────────┐     │             │
│ ctap2  │◄────┘             │
└───┬────┘                   │
    │                        │
    ├──► storage ──► crypto  │
    │         │               │
    └─────────┴───────────────┘
```

## Contratos entre Módulos

### `authenticator` → API Final

- **Entrada**: requests WebAuthn ou CBOR brutos
- **Saída**: responses CTAP2 serializadas
- **Contrato**: `EmbeddedAuthenticator` é a única API pública consumida por
  aplicações. Todas as outras crates são detalhes de implementação.

### `webauthn` → Validação

- **Entrada**: `MakeCredentialRequest`, `GetAssertionRequest`
- **Saída**: response CTAP2 ou `WebAuthnError`
- **Contrato**: valida campos obrigatórios (`rp_id`, `client_data_hash`)
  antes de delegar ao CTAP2. Não contém estado mutável além do `Ctap2Authenticator`.

### `ctap2` → Protocolo

- **Entrada**: comando CTAP2 (byte + payload CBOR)
- **Saída**: `Ctap2Error` ou response CBOR
- **Contrato**: implementa a máquina de estado CTAP2. Erros de camadas
  inferiores são mapeados para `Ctap2Error` nas fronteiras do protocolo.

### `crypto` → Primitivas

- **Entrada**: bytes + chaves
- **Saída**: signatures, ciphertexts, hashes
- **Contrato**: toda operação criptográfica passa por `CryptoEngine`.
  Chaves privadas nunca saem em plaintext. Comparação é constant-time.

### `storage` → Persistência

- **Entrada**: `Credential` (plaintext), chave
- **Saída**: `StoredCredential` (chave cifrada)
- **Contrato**: encryption at rest via ChaCha20-Poly1305. `StorageBackend`
  é injetável (file vs flash). Wear leveling simulado é contador informativo
  (`warn`-only, threshold 10k com throttle a cada 1000, sem rotação real;
  ver `firmware/storage/src/storage.rs:447` e `ADR-0016`). Estado
  persistido inclui credenciais, signCount, PIN e large blobs; Reset
  apaga o backend.

### `transport` → Comunicação

- **Entrada**: frames do host
- **Saída**: frames de resposta
- **Contrato**: trait `Transport` é object-safe (`Box<dyn Transport>`).
  Cada transporte implementa `init/send/recv/close`. Adaptadores
  (`FramedUsbHidTransport`, `FramedCcidTransport`) conectam dispositivos
  `embedded-hal` à trait; `CtapHidClass`/`UsbHidBackend` implementam USB-HID
  sobre `usb-device`; NFC e BLE permanecem stubs que retornam `Unimplemented`.

### `board-generic` → HAL

- **Entrada**: definições estáticas de board
- **Saída**: `BoardDefinition`, `BoardHAL`
- **Contrato**: perfis são `const` (vivem em flash). `BoardTrait` abstrai
  GPIO/I2C/SPI para implementações por board.

### `device-profile` → Configuração

- **Entrada**: `BoardDefinition`
- **Saída**: `DeviceProfile`, `Capabilities`
- **Contrato**: `DeviceProfileBuilder` configura produto. `CapabilityDiscovery`
  gera snapshot runtime para `GetInfo`.

## Fluxo de Dados: MakeCredential

```
Host                    Transport              Authenticator           WebAuthn            CTAP2              Storage
 │                         │                       │                    │                   │                   │
 │── CBOR request ────────►│                       │                    │                   │                   │
 │                         │── frame ─────────────►│                    │                   │                   │
 │                         │                       │── validate ───────►│                   │                   │
 │                         │                       │                    │── make_credential►│                   │
 │                         │                       │                    │                   │── store ─────────►│
 │                         │                       │                    │                   │◄── stored ────────│
 │                         │                       │                    │◄── response ──────│                   │
 │                         │◄── frame ─────────────│                    │                   │                   │
 │◄── CBOR response ───────│                       │                    │                   │                   │
```

## Fluxo de Dados: GetAssertion

```
Host                    Transport              Authenticator           CTAP2              Crypto             Storage
 │                         │                       │                    │                   │                   │
 │── CBOR request ────────►│                       │                    │                   │                   │
 │                         │── frame ─────────────►│                    │                   │                   │
 │                         │                       │── get_assertion ──►│                   │                   │
 │                         │                       │                    │── get_credential ─────────────────────►│
 │                         │                       │                    │◄── StoredCredential ──────────────────│
 │                         │                       │                    │── decrypt ───────►│                   │
 │                         │                       │                    │◄── private_key ──│                   │
 │                         │                       │                    │── sign ──────────►│                   │
 │                         │                       │                    │◄── signature ────│                   │
 │                         │◄── frame ─────────────│                    │                   │                   │
 │◄── CBOR response ───────│                       │                    │                   │                   │
```

## Regras de Dependência

1. **Sem ciclos**: setas apontam de quem depende para quem é dependido
2. **Crypto é folha**: apenas `ring`, `rsa`, `rand` como dependências externas
3. **Transport é folha**: apenas `log` + `thiserror`
4. **Storage depende de crypto**: para encryption at rest
5. **CTAP2 depende de storage + crypto**: para persistência e assinaturas
6. **Authenticator depende de tudo**: é o ponto de composição

## Mapeamento de Crates

| Crate | Caminho | Diretório | Responsabilidade |
|-------|---------|-----------|------------------|
| `authenticator` | `firmware/authenticator/` | firmware | API final |
| `webauthn` | `protocol/webauthn/` | protocol | Validação WebAuthn |
| `ctap2` | `protocol/ctap2/` | protocol | Estado CTAP2 |
| `crypto` | `protocol/crypto/` | protocol | Primitivas criptográficas |
| `storage` | `firmware/storage/` | firmware | Persistência cifrada |
| `transport` | `firmware/transport/` | firmware | Trait + stubs |
| `board-generic` | `firmware/board-generic/` | firmware | HAL + perfis |
| `device-profile` | `firmware/device-profile/` | firmware | Configuração |
| `fido2-simulator` | `simulator/` | raiz | Simulador host |
| `test-suite` | `tests/` | raiz | Testes Rust + Python |

## Estratégia std/no_std (ADR-0004)

- **Crates de protocolo** (`crypto`, `ctap2`, `webauthn`): `extern crate alloc`
  para compatibilidade com targets embarcados
- **Crates de firmware** (`storage`, `transport`, `board-generic`): prontos
  para `no_std` quando necessário
- **Simulador e exemplos**: `std` completo para desenvolvimento

## Pontos de Extensão

| Extensão | Onde adicionar | Contrato |
|----------|---------------|----------|
| Novo algoritmo | `crypto::CryptoEngine` + `ctap2::Ctap2Capabilities` | Adicionar método + COSE key builder |
| Novo transporte | `firmware/transport/` | Implementar `Transport` trait |
| Novo board | `board-generic::profiles` | `BoardDefinition` com `const fn` |
| Nova extensão WebAuthn | `ctap2::Extensions` + handler | Adicionar campo + validação |
| Novo backend de storage | `storage::StorageBackend` | Implementar trait + injetar |
