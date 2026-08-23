# openkey-fido2 — Rastreio de Incrementos

Estado atual do projeto e incrementos planejados. Itens marcados com ✅ estão
completos; itens com 🚧 estão em progresso; itens com ❌ são incrementos futuros.

## Estado Atual

### Core CTAP2
- ✅ MakeCredential com attestation `none`, `self`, `packed`
- ✅ GetAssertion com sign counter incremental e multi-assertion (`GetNextAssertion`)
- ✅ GetInfo com capabilities dinâmicas e `maxLargeBlobDataSize`
- ✅ GetVersion
- ✅ ProcessCommand (dispatch CBOR)
- ✅ Suporte a allow_list e exclude_list
- ✅ Rejeição de allow_list de RP incorreto (anti-hijacking)
- ✅ Rejeição de algoritmo não suportado
- ✅ Rejeição de payload CBOR com bytes residuais após o item completo
- ✅ **Extensão LargeBlobs (CTAP 2.1 §6.10, Opcode 0x0C)**: leitura e escrita fragmentada com storage seguro de 4096B
- ✅ **Extensão `largeBlobKey`**: geração de chave simétrica de 32B por credencial e retorno no MakeCredential/GetAssertion
- ✅ **Credential Management (CTAP 2.1 §6.8, Opcode 0x0A)**: `getCredsMetadata`, `enumerateRPs`, `enumerateCredentials`, `updateUserInformation`, `deleteCredential`
- ✅ **Enterprise Attestation**: validação contra RP list corporativa e bypass de anonymization

### Criptografia
- ✅ Ed25519 key pair generation via `ring`
- ✅ Sign/Verify Ed25519
- ✅ ES256 (ECDSA P-256 + SHA-256, alg `-7`)
- ✅ ES384 (ECDSA P-384 + SHA-384, alg `-35`)
- ✅ PS256 (RSA-PSS + SHA-256, alg `-37`)
- ✅ RS256 (RSA PKCS#1 v1.5 + SHA-256, alg `-257`)
- ✅ HMAC-SHA256
- ✅ SHA-256
- ✅ ChaCha20-Poly1305 (encrypt at rest)
- ✅ Nonce generation via `SystemRandom`

### Criptografia Híbrida (ECIES)
- ✅ Módulo `hybrid.rs` com X25519 + HKDF-SHA256 + ChaCha20-Poly1305
- ✅ `hybrid_encrypt` / `hybrid_decrypt` / `hybrid_generate_keypair` (chaves efêmeras via `ring`)
- ✅ **Suporte a chaves X25519 estáticas persistíveis (`x25519-dalek`)**: `hybrid_generate_static_keypair`, `hybrid_diffie_hellman`, `hybrid_decrypt_static`
- ✅ KDF simétrico (salt = `ephemeral_pk || recipient_pk` em ambos os lados)
- ✅ AAD com `ephemeral_public_key` (proteção contra adulteração)
- ✅ Zeroização de material sensível via `zeroize`
- ✅ Integrar com `CryptoEngine` (`generate_x25519_key_pair`, `x25519_diffie_hellman`, `hybrid_encrypt`, `hybrid_decrypt_static`)
- ✅ ADR-0006 registrar decisão de design (side-channel mitigation)
- ✅ ADR-0008 registrar decisão de design (sealed-box ECIES com suporte a chaves efêmeras e estáticas)
- ✅ Limitação anterior do `ring` resolvida com `x25519-dalek` mantendo compatibilidade `no_std`

### Armazenamento
- ✅ StorageEngine com encryption at rest
- ✅ Credential lookup por ID e por RP ID
- ✅ Sign counter persistence (memória + backend, corrigido em 2026-08-16)
- ✅ Private key nunca armazenado em plaintext
- ✅ **Persistência real do CTAP2 Reset** — `StorageEngine::clear` apaga as chaves do backend, não apenas o cache em memória; PIN, credenciais e large blobs não ressuscitam após reinício. Crate: `storage`. Critério: `test_clear_persists_to_backend` + E2E `test_reset_persists_across_restart` e `test_reset_clears_credentials_across_restart_wire` passando.
- ✅ **Persistência do signCount no backend** — `update_sign_count` grava o registro atualizado via `StorageBackend::write`, mantendo o contador monotônico entre reinícios. Crate: `storage`. Critério: `test_sign_count_persists_to_backend` + E2E `test_sign_counter_survives_restart` e `test_sign_counter_monotonic_across_restart_wire` passando.
- ✅ **Recarga de large blobs no startup** — `load_from_backend` restaura a chave reservada `sys:large_blobs`. Crate: `storage`. Critério: `test_large_blobs_reload_from_backend` + E2E `test_large_blobs_survive_restart` passando.
- ✅ **Testes E2E de reinício** — `tests/python/test_persistence.py` (PIN, Reset, signCount via JSON) e `tests/python/conformance/test_persistence_restart.py` (wire format CBOR: credenciais, Reset, signCount, large blobs). Critério: `pytest tests/python/test_persistence.py tests/python/conformance/test_persistence_restart.py` passando (14 testes).

### Device Profile & Board
- ✅ BoardDefinition builder pattern
- ✅ DeviceProfileBuilder com overrides
- ✅ CapabilityDiscovery para runtime
- ✅ 5 board profiles pré-definidos (NRF52840, STM32L4, ESP32C3, RP2350, GENERIC)
- ✅ AAGUIDs únicos por board
- ✅ SecurityFeatures struct (secure_boot, trust_zone, hardware_rng, sha256_accelerator, debug_disable, otp_memory, unique_id, tamper_detection)
- ✅ Perfil RP2350 com security features completos
- ✅ Propagação de SecurityFeatures em DeviceProfile

### Testes
- ✅ Testes unitários Rust (crypto, storage, ctap2, device-profile)
- ✅ Testes de integração Rust (allow_list, exclude_list, sign counter)
- ✅ Testes end-to-end Python via simulador
- ✅ Testes Python dos exemplos (basic, ccid)
- ✅ Testes do virtual board (CBOR, GPIO, I2C, SPI, CCID, perfis)

### Infraestrutura
- ✅ Workspace Cargo com 16 crates
- ✅ Simulador com JSON line protocol
- ✅ Exemplos básicos funcionando
- ✅ AGENTS.md (guia do agente)
- ✅ TODO.md (este arquivo)
- ✅ Virtual board em Python (`simulator/python/board/`): cbor, gpio, i2c, spi, ccid, board, profiles
- ✅ **Release CI criado: `.github/workflows/release.yml`** (build, test, artifacts, criação de release)

---

## Quick Wins

Itens que podem ser implementados imediatamente com baixo esforço:

- ✅ **Adicionar `credProtect` enum em `protocol/ctap2/src/ctap2.rs`** — Criar enum `CredProtectPolicy` com valores `UserVerificationOptional`, `UserVerificationOptionalWithCredentialIDList`, `UserVerificationRequired`. Crate: `ctap2`. Critério: `cargo test -p ctap2` passando.
- ✅ **Implementar `Reset` (0x07) em `protocol/ctap2/src/ctap2.rs`** — Adicionar handler no `process_command` que limpa todas as credenciais do storage. Crate: `ctap2`, `storage`. Critério: teste unitário `test_reset` passando.
- ✅ **Adicionar `justfile` na raiz** — Criar `justfile` com comandos: `build`, `test`, `test-e2e`, `fmt`, `clippy`, `sim`, `example-basic`, `example-ccid`. Crate: N/A. Critério: `just --list` mostra todos os comandos.
- ✅ **Implementar `Selection` (0x0B) em `protocol/ctap2/src/ctap2.rs`** — Retornar `GetVersionResponse` existente (reutilizar handler). Crate: `ctap2`. Critério: teste unitário `test_selection` passando.
- ✅ **Adicionar `Cargo.toml` metadata para `cargo doc`** — Configurar `[package.metadata.docs.rs]` com `all-features`. Crate: workspace. Critério: `cargo doc --workspace` gera documentação sem erros.

---

## Incrementos Futuros

### Prioridade Alta

#### ClientPIN (CTAP2 0x06)

- ✅ **Definir módulo `client_pin.rs` em `protocol/ctap2/src/`** — Criar structs: `ClientPinRequest` (subCommand, pinProtocol, keyAgreement, pinAuth, newPinEnc, pinHashEnc), `ClientPinResponse` (keyAgreement, pinUvAuthToken, retries, powerCycleState). Crate: `ctap2`. Critério: módulo compila com `cargo build -p ctap2`.
- ✅ **Implementar trait `ClientPin` em `protocol/ctap2/src/client_pin.rs`** — Definir trait com métodos: `get_pin_retries()`, `set_pin()`, `change_pin()`, `verify_pin()`. Crate: `ctap2`. Critério: trait definida e compilável.
- ✅ **Implementar `getPINRetries` (subCommand 0x01)** — Retornar contador de tentativas atual (iniciar em 8). Crate: `ctap2`, `storage`. Critério: teste unitário `test_get_pin_retries` passando.
- ✅ **Implementar `setPIN` (subCommand 0x03)** — Validar comprimento mínimo (4 bytes), armazenar `LEFT(SHA-256(pin), 16)` no storage. Crate: `ctap2`, `storage`, `crypto`. Critério: teste unitário `test_set_pin` passando, rejeitar PIN < 4 chars.
- ✅ **Implementar `changePIN` (subCommand 0x04)** — Verificar PIN atual via hash, validar novo PIN, atualizar hash. Crate: `ctap2`, `storage`, `crypto`. Critério: teste unitário `test_change_pin` passando, rejeitar PIN atual errado.
- ✅ **Migrar `getPINToken` (subCommand 0x05) para CTAP2** — P-256 ECDH, AES-256-CBC e HMAC conforme CTAP 2.1 §6.5.5.7.1; pinHashEnc decifrado e comparado em tempo constante; decremento de retries antes da verificação.
- ✅ **Substituir `getPINHashEnc` legado** — O subcomando não existe em CTAP 2.1; o fluxo é coberto por `getPinUvAuthTokenUsingPinWithPermissions` (0x09).
- ✅ **Implementar `getKeyAgreement` (subCommand 0x02)** — Par P-256 efêmero via `ring::agreement::ECDH_P256`, retorno de COSE_Key `{1:2, 3:-25, -1:1, -2:x, -3:y}`; chave privada mantida na sessão e consumida no subcomando seguinte (nunca reutilizada entre transações).
- ✅ **Negociar `pinUvAuthProtocol` conforme CTAP2** — Protocolos 1 e 2 em `crypto::pin_protocol` (KDF SHA-256/HKDF, AES-256-CBC, HMAC-SHA-256 truncado/completo), migração registrada em `docs/adr/ADR-0017-clientpin-ctap2-wire-format.md`.
- ✅ **Implementar `getPinUvAuthTokenUsingPinWithPermissions` (subCommand 0x09)** — permissions/rpId, validação de permissões contra GetInfo (`UNAUTHORIZED_PERMISSION 0x40`), token de 32 bytes cifrado por subcomando.
- ✅ **Implementar `getPinUvAuthTokenUsingUvWithPermissions` (subCommand 0x06)** — Sem built-in UV, retorna `UV_BLOCKED` (0x3C).
- ✅ **Implementar PIN retry counter decrement/increment** — Decrementar em tentativa falha, reset em sucesso, bloquear após 3 falhas consecutivas (powerCycleState=true, `PIN_AUTH_BLOCKED`). Crate: `ctap2`, `storage`. Critério: testes unitários de retry passando.
- ✅ **Adicionar handler `ClientPIN` no `process_command`** — Codec próprio de array/mapa CBOR (chaves inteiras 0x01..0x0A) e response em mapa canônico 0x01..0x05. Critério: `cargo test -p ctap2 -- client_pin` passando.
- ✅ **Erros CTAP2 de PIN no `Ctap2Error`** — `PinInvalid` 0x31, `PinBlocked` 0x32, `PinAuthInvalid` 0x33, `PinAuthBlocked` 0x34, `PinNotSet` 0x35, `PinRequired` 0x36, `PinPolicyViolation` 0x37, `PinTokenExpired` 0x38, `UvBlocked` 0x3C, `UnauthorizedPermission` 0x40, `MissingParameter` 0x14.
- ✅ **GetInfo com `pinUvAuthProtocols` [1, 2] e options `clientPin`/`pinUvAuthToken`** — `uv` permanece ausente; `clientPin` anunciado como suporte da feature (exigido pelo python-fido2 para enviar setPIN).
- ✅ **Testes E2E Python: `tests/python/conformance/test_client_pin.py`** — Fluxo completo com `fido2.ctap2.pin.ClientPin` (python-fido2 2.2.1) nos protocolos 1 e 2: setPIN → getPINRetries → getPINToken → changePIN → getPINToken+permissions, com códigos de erro da spec. Critério: `pytest tests/python/conformance/test_client_pin.py -v` passando (15 testes).
- ✅ **Wiring do `pinUvAuthParam` em MakeCredential/GetAssertion/CredentialManagement** — Requests carregam o campo CTAP2.1; MakeCredential/GetAssertion validam MAC sobre `clientDataHash`, permissões e binding de RP; Credential Management valida MAC sobre `subCommand || subCommandParams`. Cobertura Rust e E2E Python adicionada.
- ✅ **`firmwareVersion` do GetInfo como inteiro (CTAP 2.1 §6.4)** — Mapeamento determinístico do semver do perfil documentado no ADR-0020; wire e consumidores Python validam tipo e valor.
- 🚧 **Built-in UV (`uv` option e `getUVRetries` 0x07)** — Depende de hardware de verificação de usuário embutida; hoje `getUVRetries` retorna `UnsupportedOption`.

#### Extensões WebAuthn

- ✅ **Implementar `credProtect` em `protocol/ctap2/src/ctap2.rs`** — Adicionar campo `credProtect` no `MakeCredentialRequest`, aplicar política na criação. Crate: `ctap2`. Critério: teste unitário `test_cred_protect` passando.
- ✅ **Adicionar `credProtect` no `GetInfoResponse`** — Incluir `"credProtect"` na lista de extensions quando suportado. Crate: `ctap2`. Critério: `GetInfo` retorna `credProtect` em extensions.
- ✅ **Implementar `credBlob` get em `protocol/ctap2/src/ctap2.rs`** — Adicionar campo `credBlob` (máx 32 bytes) no `Credential`, recuperar via GetAssertion. Crate: `ctap2`, `storage`. Critério: teste unitário `test_cred_blob_get` passando.
- ✅ **Implementar `credBlob` set em `protocol/ctap2/src/ctap2.rs`** — Validar tamanho máximo (32 bytes), armazenar no credential. Crate: `ctap2`, `storage`. Critério: teste unitário `test_cred_blob_set` passando, rejeitar > 32 bytes.
- ✅ **Implementar `minPinLength` discovery em `protocol/ctap2/src/ctap2.rs`** — Adicionar campo `minPinLength` no `MakeCredentialRequest`, retornar comprimento mínimo configurado. Crate: `ctap2`. Critério: teste unitário `test_min_pin_length` passando.
- ✅ **Adicionar `minPinLength` no `GetInfoResponse`** — Incluir `"minPinLength"` na lista de extensions. Crate: `ctap2`. Critério: `GetInfo` retorna `minPinLength` em extensions.
- ✅ **Implementar `hmac-secret` conforme CTAP 2.1 §12.5** — MakeCredential booleano gera/persiste `CredRandomWithUV`/`WithoutUV`; GetAssertion deriva segredo compartilhado inline (`keyAgreement` ECDH + KDF do protocolo PIN/UV 1/2), verifica `saltAuth`, decifra salts (32/64B) e devolve `HMAC-SHA-256(CredRandom, salt_i)` cifrado com nonce fresco. Módulo `protocol/ctap2/src/hmac_secret.rs`. Crate: `ctap2`, `crypto`, `storage`. Critério: testes `test_hmac_secret_roundtrip_protocol_{1,2}` e suíte `tests/python/conformance/test_hmac_secret.py` passando.
- ✅ **Testes E2E Python: `tests/python/test_extensions.py`** — Testar credProtect, credBlob, minPinLength, hmac-secret. Crate: `tests`. ⬅️ depende de todas as extensões. Critério: `pytest tests/python/test_extensions.py -v` passando.

#### Persistência Real

- ✅ **Adicionar trait `StorageBackend` em `firmware/storage/src/storage.rs`** — Definir trait com métodos: `read(key) -> Vec<u8>`, `write(key, value) -> Result`, `delete(key) -> Result`. Crate: `storage`. Critério: trait definida e compilável.
- ✅ **Implementar `FileStorageBackend` em `firmware/storage/src/storage.rs`** — Backend usando arquivo JSON local para desenvolvimento. Crate: `storage`. Critério: teste unitário `test_file_storage` passando.
- ✅ **Adicionar `StorageEngine::with_backend(backend: Box<dyn StorageBackend>)`** — Permitir injeção de backend customizado. Crate: `storage`. ⬅️ depende de `StorageBackend`. Critério: `StorageEngine` aceita backend customizado.
- ✅ **Implementar backend de flash simulado em `firmware/storage/src/storage.rs`** — `FlashDevice`, `SimulatedFlash` e `FlashStorageBackend` modelam erase/program, commits em dois slots e recuperação de power-loss. Adaptadores físicos por board permanecem pendentes; ver `docs/adr/ADR-0016-flash-simulada-e-gates-de-release.md`.
- ✅ **Adicionar wear leveling básico em `firmware/storage/src/storage.rs`** — Implementar contador de writes por setor, rotacionar quando threshold atingido. Crate: `storage`. ⬅️ depende de `FlashStorageBackend`. Critério: teste unitário `test_wear_leveling` passando.
- ✅ **Implementar credential pruning em `firmware/storage/src/storage.rs`** — Remover credenciais mais antigas quando `max_credential_count` atingido (LRU). Crate: `storage`. Critério: teste unitário `test_credential_pruning` passando, respeitar `max_credential_count`.
- ✅ **Adicionar `created_at` timestamp real em `Credential`** — Usar `embedded-hal` timer ou timestamp do sistema. Crate: `storage`. Critério: credenciais têm timestamp válido.
- ✅ **Testes E2E Python: `tests/python/test_persistence.py`** — Testar persistência entre reinicializações do simulador. Crate: `tests`. ⬅️ depende de `FileStorageBackend`. Critério: `pytest tests/python/test_persistence.py -v` passando.

### Prioridade Média

#### Algoritmos Adicionais

- ✅ **Adicionar ES256 (ECDSA P-256) em `protocol/crypto/src/crypto.rs`** — Implementar `generate_p256_key_pair()`, `sign_p256()`, `verify_p256()` via `ring::signature::ECDSA_P256_SHA256_ASN1`. Crate: `crypto`. Critério: teste unitário `test_es256_sign_verify` passando.
- ✅ **Adicionar RS256 (RSA-PKCS1) em `protocol/crypto/src/crypto.rs`** — Implementar `generate_rsa_key_pair()`, `sign_rsa()`, `verify_rsa()` via `ring::signature::RSA_PKCS1_2048_8192_SHA256`. Geração de chave usa a crate `rsa` (ring não gera chaves RSA). Crate: `crypto`. Critério: teste unitário `test_rsa_sign_verify` passando.
- ✅ **Adicionar COSE key para ES256 em `protocol/ctap2/src/ctap2.rs`** — Implementar `build_cose_key_p256(x, y)` com labels COSE correto (kty=2, alg=-7). Crate: `ctap2`. ⬅️ depende de ES256. Critério: teste unitário `test_cose_key_p256` passando.
- ✅ **Adicionar COSE key para RS256 em `protocol/ctap2/src/ctap2.rs`** — Implementar `build_cose_key_rsa(n, e)` com labels COSE correto (kty=3, alg=-257). Crate: `ctap2`. ⬅️ depende de RS256. Critério: teste unitário `test_cose_key_rsa` passando.
- ✅ **Implementar negociação de algoritmo em `MakeCredential`** — Iterar `pubKeyCredParams`, selecionar primeiro algoritmo suportado, retornar erro se nenhum. Crate: `ctap2`. ⬅️ depende de ES256 e RS256. Critério: teste unitário `test_algorithm_negotiation` passando.
- ✅ **Atualizar `GetInfoResponse` com algoritmos suportados** — Incluir COSE algorithms na response. Crate: `ctap2`. ⬅️ depende de ES256 e RS256. Critério: `GetInfo` retorna lista de algoritmos.
- ✅ **Testes E2E Python: `tests/python/test_algorithms.py`** — Testar MakeCredential/GetAssertion com ES256 e RS256. Crate: `tests`. ⬅️ depende de todos os algoritmos. Critério: `pytest tests/python/test_algorithms.py -v` passando.

#### Transportes

- ✅ **Definir trait `Transport` em novo crate `firmware/transport/`** — Métodos: `init()`, `send(data)`, `recv() -> Vec<u8>`, `close()`. Trait object-safe (`Box<dyn Transport>`), erros via `TransportError` (`thiserror`). Inclui `DummyTransport` no-op para testes. Crate: `transport`. Critério: trait definida e compilável.
- ✅ **Integrar `UsbHidTransport` por injeção host-verificável** — `EmbeddedAuthenticator::new_with_profile_and_transport` aceita `Box<dyn Transport>` e mantém o ciclo de vida explícito; composição, erros e framing multipartido são testados com mocks no host. Drivers/periféricos concretos de board e validação física permanecem pendentes.
- 🚧 **Integrar `UsbCcidTransport`** — parcela host-verificável concluída: `FramedCcidTransport` pode ser injetado no `EmbeddedAuthenticator`, inicializado explicitamente e exercitado com APDU e propagação de erros em mock; falta ligar um driver USB-CCID concreto de board e validar em hardware.
- 🚧 **Implementar `NfcTransport` em `firmware/transport/src/nfc.rs`** — O tipo atual ainda é um stub; falta integrar frontend NFC ISO 14443 e o stack de hardware. Crate: `transport`.
- 🚧 **Implementar `BleGattTransport` em `firmware/transport/src/ble_gatt.rs`** — O tipo atual ainda é um stub; falta integrar um servidor BLE GATT e stack Bluetooth. Crate: `transport`.
- ✅ **Adicionar `TransportConfig` em `firmware/device-profile/src/profile.rs`** — `TransportType` com `UsbHid`, `UsbCcid`, `Nfc`, `BleGatt` e atalhos `TransportConfig::usb_hid()/usb_ccid()/nfc()/ble_gatt()`. Crate: `device-profile`. Critério: `DeviceProfileBuilder::transport_config()` aceita config.
- ✅ **Integrar transport no `EmbeddedAuthenticator`** — `init_transport` instancia o stub conforme `profile.transport_config`; acessores `transport()` / `transport_mut()`. Crate: `authenticator`. Critério: `EmbeddedAuthenticator` usa transport configurado.
- ✅ **Testes unitários dos stubs de transporte** — 19 testes em `firmware/transport/src/` (ciclo de vida, `NotInitialized` antes de `init`, `Unimplemented` em I/O, object safety). Crate: `transport`. Critério: `cargo test -p transport` passando.
- ✅ **Definir trait contracts embedded-hal para transportes** — Módulo `transport::embedded` com traits `UsbHidDevice`, `UsbCcidDevice`, `NfcDevice`, `BleGattDevice`, `EmbeddedTransportError`, `StatusLed`. Feature gate `embedded` com `embedded-hal 1.0`. Crate: `transport`. Critério: `cargo build -p transport --features embedded` compila.
- ✅ **Implementação de referência USB-HID para RP2350** — `Rp2350UsbHid` implementa `UsbHidDevice` com placeholder do periférico USB. Crate: `transport::embedded::rp2350`. Critério: `cargo test -p transport --features embedded` passando.
- ✅ **Implementação completa de CTAPHID Framing e Fragmentação (CTAP 2.1 §8.2)** — Módulo `firmware/transport/src/ctaphid/` com `CtaphidPacket` (INIT e CONT 64B), `CtaphidFragmenter` (segmentação de payloads até 7609B), `CtaphidAssembler` (remontagem com validação de sequência, canal, cancelamento e timeout) e `ChannelManager` (alocação de CIDs e handshake `CTAPHID_INIT`). Crate: `transport`. Critério: testes unitários de fragmentação/montagem passando.
- ✅ **Implementar reference HALs para NRF52840 e STM32L4** — `Nrf52840UsbHid` (Nordic USBD), `Nrf52840Nfc` (Nordic NFCT Tag Type 4), e `Stm32l4UsbHid` (STM32 USB FS PMA). Crate: `transport::embedded`. Critério: testes de ciclo de vida passando.
- ✅ **Implementar adaptadores de transporte concreto `FramedUsbHidTransport` e `FramedCcidTransport`** — Bridges que conectam `UsbHidDevice` e `UsbCcidDevice` à trait unificada `Transport`. Crate: `transport`. Critério: testes de envio/recepção de pacotes passando.
- ✅ **Criar ADR-0009: CTAPHID Framing e Transportes de Hardware Real** — Documentação arquitetural em `docs/adr/ADR-0009-ctaphid-framing-e-hardware-transports.md`. Crate: N/A. Critério: ADR criado e referenciado.

#### Attestation

- ✅ **Definir enum `AttestationFormat` em `protocol/ctap2/src/ctap2.rs`** — Valores: `None`, `Packed`, `Self_`, `U2F`, `AndroidKey`, `Apple`. Crate: `ctap2`. Critério: enum definida e compilável.
- ✅ **Implementar `PackedAttestation` em `protocol/ctap2/src/attestation.rs`** — Gerar `attStmt` com `{alg, sig, x5c}` ou `{alg, sig, ecdaaKeyId}`. Crate: `ctap2`. Critério: teste unitário `test_packed_attestation` passando.
- ✅ **Implementar `SelfAttestation` em `protocol/ctap2/src/attestation.rs`** — Gerar `attStmt` com `{alg, sig}` usando chave da credencial. Crate: `ctap2`. Critério: teste unitário `test_self_attestation` passando.
- ✅ **Adicionar `AttestationCertificate` struct em `protocol/ctap2/src/attestation.rs`** — Armazenar certificado X.509 e chave privada para attestation. Crate: `ctap2`. Critério: struct definida e compilável.
- ✅ **Implementar `set_attestation_certificate` em `Ctap2Authenticator`** — Permitir configurar certificado para attestation. Crate: `ctap2`. ⬅️ depende de `AttestationCertificate`. Critério: teste unitário `test_set_attestation_cert` passando.
- ✅ **Adicionar `attestation_format` no `DeviceProfile`** — Permitir configurar formato de attestation no profile. Crate: `device-profile`. Critério: `DeviceProfileBuilder` aceita `attestation_format`.
- ✅ **Integrar attestation no `MakeCredential`** — Selecionar formato baseado no `DeviceProfile`. Crate: `ctap2`. ⬅️ depende de `AttestationFormat` e `DeviceProfile`. Critério: `MakeCredential` usa formato configurado.
- ✅ **Testes E2E Python: `tests/python/test_attestation.py`** — Testar Packed e Self attestation. Crate: `tests`. ⬅️ depende de todos os formatos. Critério: `pytest tests/python/test_attestation.py -v` passando.

#### Comandos CTAP2 Restantes

- ✅ **Implementar `Reset` (0x07) completo em `protocol/ctap2/src/ctap2.rs`** — Limpar todas as credenciais, resetar estado de enumeração, retornar `Ctap2Error::Success`. Crate: `ctap2`, `storage`. Critério: teste unitário `test_reset_full` passando.
- ✅ **Implementar `GetNextAssertion` (0x08) em `protocol/ctap2/src/ctap2.rs`** — Retornar próxima credencial quando `numberOfCredentials > 1`. Crate: `ctap2`. ⬅️ estado mantido em `Ctap2Authenticator::get_next_assertion_state`. Critério: teste unitário `test_get_next_assertion` passando.
- ✅ **Adicionar `GetAssertionResponse::number_of_credentials` e `next`** — Campos para rastrear quantas credenciais faltam e se há mais. Crate: `ctap2`. Critério: `get_assertion` popula campos quando >1 credencial.
- ✅ **Implementar `EnumerateRPsInitial` (0x3B) em `protocol/ctap2/src/ctap2.rs`** — Retornar primeiro RP com `rpId`, `rpHash`, `totalRPs`. Crate: `ctap2`, `storage`. ⬅️ estado mantido em `Ctap2Authenticator::enumerate_rps_state`. Critério: teste unitário `test_enumerate_rps_initial` passando.
- ✅ **Implementar `EnumerateRPsNext` (0x3C) em `protocol/ctap2/src/ctap2.rs`** — Retornar próximo RP na enumeração. Crate: `ctap2`, `storage`. ⬅️ depende de `EnumerateRPsInitial`. Critério: teste unitário `test_enumerate_rps_next` passando.
- ✅ **Adicionar `enumerate_rps` método em `StorageEngine`** — Retornar lista de RP IDs únicos com hash. Crate: `storage`. Critério: teste unitário `test_storage_enumerate_rps` passando.
- ✅ **Implementar `BioEnroll` (0x09) stub em `protocol/ctap2/src/ctap2.rs`** — Retornar `Ctap2Error::UnsupportedOption` para enroll; retornar características para subCommand 0x03. Crate: `ctap2`. Critério: testes `test_bio_enroll_stub` e `test_bio_characteristics` passando.
- ✅ **Testes E2E Python: `tests/python/test_ctap2_commands.py`** — Testar Reset, GetNextAssertion, EnumerateRPs, BioEnroll. Crate: `tests`. ⬅️ depende de todos os comandos. Critério: `pytest tests/python/test_ctap2_commands.py -v` passando.
- ✅ **Adicionar `rp_id` campo em `Credential`** — Armazenar plaintext do RP ID para suportar EnumerateRPs. Crate: `storage`. Critério: credenciais armazenam `rp_id` válido.

#### Configuração do Autenticador (CTAP 2.1 §6.11, Opcode 0x0D)

- ✅ **Implementar `authenticatorConfig` (0x0D) em `protocol/ctap2/src/authnr_config.rs`** — Subcomandos `enableEnterpriseAttestation` (0x01, one-shot `packed`), `toggleAlwaysUv` (0x02), `setMinPINLength` (0x03, `newMinPINLength`/`minPinLengthRpIDs`/`forceChangePin`/`currentPIN` cifrado com segredo compartilhado da sessão), `makeCredUvNotRqd` (0x04) e `setMinPINLengthRPIDs` (0x05, até 32 RP IDs). Autenticação `pinUvAuthParam` sobre `0x0D || subCommand || subCommandParams` com permissão `acfg` (0x20), flags persistidas em `StorageEngine`, `pin_shared_secret` zeroizado. Crate: `ctap2` (`authnr_config.rs`), `crypto` (`Zeroizing` Debug redigido), `storage` (`delete`). Critério: 13 testes `cargo test -p ctap2 -- authnr_config` passando, `alwaysUv` negando MC/GA sem `uv`, `forceChangePin` bloqueando `getPinToken`, `EP` consumido como `packed` no próximo MC. ADR: `docs/adr/ADR-0021-authnr-config-e-gates-de-hardware.md`.
- ✅ **`StorageEngine::delete` genérico para flags de configuração** — Remoção de `sys:cfg_*` do `kv_store` e backend. Crate: `storage`. Critério: `authnr_config::tests` usando `StorageEngine::delete` passando.

#### Hardware / User Presence

- ✅ **Reaproveitar o botão BOOTSEL do RP2350 para user presence** — zero fiação extra: o BOOTSEL já vem no board (ligado ao CS da flash QSPI, não é GPIO comum). Implementado `firmware/board-generic/src/bootsel.rs` (trait `UserPresenceButton` + `BootselButton` + `Rp2350Qspi` + testes press/release) e integrado ao fluxo `up`: trait `ctap2::UserPresence` + `Ctap2Authenticator::set_user_presence` (check em MakeCredential/GetAssertion → `Ctap2Error::OperationDenied`), `BoardTrait::button_pressed()` e `EmbeddedAuthenticator::set_user_presence_button()` (injeta o `BootselButton`). Auto-wiring: enum `UserPresenceSource::Bootsel` no perfil `RP2350` + `EmbeddedAuthenticator::new_with_board` conecta o BOOTSEL ao fluxo `up` automaticamente. Crate: `board-generic`, `ctap2`, `authenticator`. Critério: `press`/`release` do BOOTSEL detectados; `up` negado quando o botão não está pressionado.

### Prioridade Baixa

#### Segurança Avançada

- ✅ **Adicionar `SecurityFeatures` em `firmware/board-generic/src/board_generic.rs`** — Struct com flags: secure_boot, trust_zone, hardware_rng, sha256_accelerator, debug_disable, otp_memory, unique_id, tamper_detection. Crate: `board-generic`. Critério: struct definida e compilável.
- ✅ **Adicionar security features ao perfil RP2350** — Configurar RP2350 com secure_boot, trust_zone, hardware_rng, sha256_accelerator, debug_disable, otp_memory, unique_id. Crate: `board-generic`. Critério: `RP2350.security.has_any() == true`.
- ✅ **Propagar SecurityFeatures em DeviceProfile** — Adicionar campo `security` em DeviceProfile e DeviceProfileBuilder, propagar via `from_board`. Crate: `device-profile`. Critério: `DeviceProfileBuilder::from_board(&RP2350).build().security.secure_boot == true`.
- ✅ **Adicionar `SecurityFeatures` serializable em `protocol/ctap2/src/ctap2.rs`** — Struct serializable com mesmo layout, usado em `GetInfoResponse` via `Option<SecurityFeatures>`. Crate: `ctap2`. Critério: `get_info()` inclui campo `security` quando `has_any_features() == true`.
- ✅ **Propagar security features em `Ctap2Capabilities`** — Campo `security` em `Ctap2Capabilities`, populado em `ctap2_capabilities()` do authenticator. Crate: `ctap2`, `authenticator`. Critério: GetInfo do RP2350 retorna security features.
- ✅ **Adicionar `SecurityFeatures` ao `CapabilityDiscovery`** — Campo `security` em `Capabilities`, propagado do `DeviceProfile`. Crate: `device-profile`. Critério: `capability.security.secure_boot == true` para RP2350.
- ✅ **Testes unitários Rust** — Testes para SecurityFeatures, builder methods, propagação via DeviceProfile, GetInfo com RP2350. Crate: `tests`. 10 testes novos.
- ✅ **Testes E2E Python** — Suíte `tests/python/test_security_features.py` cobrindo SecurityFeatures struct, perfil RP2350, boards sem security, VirtualBoard. 18 testes.
- ✅ **Adicionar constant-time comparison em `protocol/crypto/src/crypto.rs`** — Função `constant_time_eq(a, b) -> bool` para comparação segura de PINs/tokens. Crate: `crypto`. Critério: teste unitário `test_constant_time_eq` passando.
- ✅ **Adicionar `zeroize` para chaves privadas em `firmware/storage/src/storage.rs`** — Derivar `Zeroize` em `Credential` e `StoredCredential` com `#[zeroize(drop)]`. Crate: `storage`. Critério: `test_credential_private_key_zeroized_on_drop` passando.
- ✅ **Implementar rate limiting para PIN attempts em `protocol/ctap2/src/client_pin.rs`** — Bloquear após 3 tentativas, exigir power cycle. Crate: `ctap2`. ⬅️ depende de `ClientPIN`. Critério: teste unitário `test_pin_rate_limiting` passando.
- ✅ **Adicionar documentação sobre side-channel mitigation em ADR** — Criado `docs/adr/ADR-0006-side-channel-mitigation.md` documentando constant-time eq, zeroize, PIN hash rotation, rate limiting. Crate: N/A. Critério: ADR criado e referenciado.

#### Ferramentas

- ✅ **Criar `justfile` na raiz do workspace** — Comandos: `build`, `test`, `test-e2e`, `fmt`, `clippy`, `sim`, `example-basic`, `example-ccid`, `doc`, `clean`. Crate: N/A. Critério: `just --list` mostra todos os comandos.
- ✅ **Adicionar `.github/workflows/ci.yml`** — Jobs `build-test` (build + test), `lint` (fmt + clippy) e `fuzz-smoke` (60s em push). Crate: N/A. Critério: CI roda em push/PR.
- ✅ **Adicionar `.github/workflows/e2e.yml`** — Compila simulador, exemplos e wheel `openkey_core`; roda `pytest tests/python -v`. Crate: N/A. Critério: E2E roda em push/PR.
- ✅ **Configurar `cargo-tarpaulin` ou `cargo-llvm-cov`** — `.github/workflows/coverage.yml` + alvo `just coverage` gerando Xml/Html em `coverage/`. Crate: N/A. Critério: `cargo tarpaulin` gera relatório.
- ✅ **Adicionar `fuzz/` directory com harness básico** — Crate `openkey-fuzz` fora do workspace, alvo `decode_cbor` (requests CTAP2 + roundtrip `Value`); `decode_cbor` agora é público em `ctap2`. Crate: novo `fuzz`. Critério: `cargo fuzz run decode_cbor` executa.
- ✅ **Adicionar `README.md` badges** — CI, E2E, Coverage, docs, Rust 1.70+, licença. Crate: N/A. Critério: badges visíveis no README.

#### Documentação

- ✅ **Criar `docs/adr/ADR-0005-isolamento-contexto-agentes.md`** — Padrão de isolamento de contexto e estado compartilhado controlado. Criado em 2026-08-05.
- ✅ **Revisar ADRs existentes para numeração consistente** — Verificado: ADR-0001 a ADR-0008 existem e correspondem às referências no TODO.md. Criado ADR-0008 (sealed-box/ECIES) que estava faltando. Critério: mapeamento consistente entre TODO.md e arquivos.
- ✅ **Criar `CONTRIBUTING.md` na raiz** — Guia de contribuição com padrões de código, testes, PRs. Crate: N/A. Critério: arquivo criado e referenciado.
- ✅ **Criar `docs/architecture.md`** — Diagramas de dependência, contratos entre módulos, fluxos de dados MakeCredential/GetAssertion, regras de dependência, pontos de extensão. Criado em 2026-08-10.
- ✅ **Adicionar doc comments em todas as APIs públicas** — `///` comments adicionados em `Ctap2Error` (22 variantes), `Ctap2Command` (11 variantes), todos os request/response structs do CTAP2, módulo e métodos do `webauthn`. Crates: `ctap2`, `webauthn`. Critério: documentação completa nas APIs públicas.
- ✅ **Adicionar exemplos em `examples/` para cada crate** — Criados `examples/crypto-example/` (Ed25519, ES256, hybrid, HMAC, SHA-256) e `examples/transport-example/` (custom Transport trait impl). Crates: `examples`. Critério: `cargo run -p crypto-example` e `cargo run -p transport-example` funcionam.

#### Hardware Real & Cross-Compilation Targets

- ✅ **Criar ADR-0011: Compilação Cruzada e Targets de Hardware Embarcado (no_std)** — Documentar estratégia de targets bare-metal (`thumbv8m.main-none-eabihf` para RP2350 e `thumbv7em-none-eabihf` para nRF52840/STM32L4), `no_std + alloc` e runners (`probe-rs`). Crate: N/A. Critério: `docs/adr/ADR-0011-hardware-targets-e-cross-compilation.md` criado.
- ✅ **Configuração de Toolchain e Cargo Config (`.cargo/config.toml`)** — Configuração de flags de link e aliases de compilação cruzada (`check-rp2350`, `check-nrf52840`, `check-stm32l4`, `build-rp2350`, `build-nrf52840`, `build-stm32l4`). Crate: N/A. Critério: `.cargo/config.toml` criado e aliases funcionais.
- ✅ **Compatibilidade `no_std` em `firmware/transport`** — Ajustar `transport` com `#![cfg_attr(not(feature = "std"), no_std)]`, `extern crate alloc`, imports de `Vec`, `String`, `ToString` e features condicionais. Crate: `transport`. Critério: `cargo check -p transport --target thumbv8m.main-none-eabihf --features embedded --no-default-features` e `--target thumbv7em-none-eabihf` compilando com 0 erros.
- ✅ **Atualizar `BUILD.md` e `justfile` com comandos de compilação cruzada** — Adicionar alvos `build-rp2350`, `build-nrf52840`, `build-stm32l4` e `check-targets`. Crate: N/A. Critério: `just check-targets` executando com sucesso.
- ✅ **Aplicação bare-metal de boot para RP2350 (`examples/rp2350-firmware`)** — Build cruzado reproduzível até ELF com `cargo build -p rp2350-firmware` a partir de `examples/rp2350-firmware/`; `memory.x` mantém `.start_block`/`.bi_entries` e o `link.x` do `cortex-m-rt` resolve os símbolos de runtime exigidos por `rp_binary_info`. Não há validação física.
- ✅ **Aplicação bare-metal de boot para nRF52840 (`examples/nrf52840-firmware`)** — A partir de `examples/nrf52840-firmware/`, `cargo check --locked --target thumbv7em-none-eabihf` e `cargo build --locked --target thumbv7em-none-eabihf` concluem sem o warning de `_start` nem erros de símbolos de runtime, gerando ELF em `target/thumbv7em-none-eabihf/debug/nrf52840-firmware`. Isso cobre somente compilação/link; probe-rs, USB/clocks em placa e validação física permanecem abertos.
- ✅ **Integração com driver USB real via `usb-device` para RP2350 (`rp2350-usb`)** — Backend concreto de `UsbHidDevice` sobre `usb-device::bus::UsbBusAllocator` (módulo `transport::embedded::usb_hid_backend`: `CtapHidClass` com report descriptor FIDO `0xF1D0` + `UsbHidBackend`), integrado ao `rp2350-firmware`. Crate: `transport`. ⬅️ depende de `examples/rp2350-firmware`. Critério: envio e recebimento de pacotes CTAPHID de 64 bytes em hardware (verificado em host via `MockUsbBus`).
- ✅ **Identidade USB configurável no `rp2350-firmware`** — Padrão: pid.codes do projeto (`0x1209:0x0001`) em todos os builds distribuídos. Opt-in `--features yubikey5-identity`: identidade Yubico YubiKey 5 (`0x1050:0x0407`) para reconhecimento automático por ykman/Yubico Authenticator — **NÃO PARA DISTRIBUIÇÃO** (VID/PID de terceiro, uso privado apenas). Ambos os flavors compilam; UF2 canônica mantém a identidade padrão. Runbook documenta as duas enumerações esperadas. Critério: `cargo build --features yubikey5-identity` e default passando.
- ✅ **Perfil de board Waveshare RP2350-Zero + runbook de validação física** — Novo perfil `RP2350_ZERO` em `firmware/board-generic/src/profiles.rs`: nome `rp2350-zero`, AAGUID ASCII "RP2350" + sufixo sequencial `0x06`, USB-HID+CCID por paridade com o perfil RP2350, presença via BOOTSEL, WS2812B em GPIO16 via PIO (driver pendente, pino registrado), sem botão GPIO (sentinela `u8::MAX`; BOOT=download, RUN=reset). Integração completa: `DeviceProfileBuilder::from_board(&RP2350_ZERO)` e `EmbeddedAuthenticator::new_with_board(&RP2350_ZERO)` cobertos por testes (`tests/src/lib.rs`); `firmware/board-generic` agora é `#![no_std]` (sem uso de std em nenhum módulo); o binário `examples/rp2350-firmware` consome o perfil (asserção de compilação `led_pin == 16`; status LED movido de GPIO25 para GPIO16). Runbook físico em `docs/hardware/rp2350-zero-validation.md` (build, UF2/probe-rs/picotool 2.3.0 local, picotool info para medir a flash real — discrepância W25Q16JV 2MB vs wiki 4MB, enumeração USB, GetInfo sem opção `uv`). Critério: `test_board_profiles_derive_correct_product_name_and_transports`, `test_embedded_authenticator_with_rp2350_zero_profile`, ELF compila, UF2 regenerada; validação física continua 🚧.

#### Conformance Testing & Raw CBOR Tooling

- ✅ **Criar ADR-0012: Suporte a Conformance Testing FIDO2 e Interface Raw CBOR** — Documentar modo `--raw-cbor` no simulador e suíte de testes de conformidade. Crate: N/A. Critério: `docs/adr/ADR-0012-fido-conformance-e-raw-cbor-interface.md` criado.
- ✅ **Implementar modo `--raw-cbor` no `fido2-simulator`** — Suporte a framing binário length-prefixed no stdin/stdout para despacho direto de comandos CTAP2 sem parsing JSON. Crate: `simulator`. Critério: `cargo build -p fido2-simulator` compila e executa.
- ✅ **Criar transporte `SimulatorClient` em Python (`tests/python/conformance/ctap2_transport.py`)** — Ponte binária Python para comunicação bidirecional com o simulador em modo `--raw-cbor`. Crate: `tests`. Critério: módulo funcional.
- ✅ **Implementar suíte de testes de conformidade CTAP 2.1 (`tests/python/conformance/`)** — 12 testes automatizados cobrindo GetInfo, MakeCredential, GetAssertion, ClientPIN, CredentialManagement, LargeBlobs e Reset. Crate: `tests`. Critério: `pytest tests/python/conformance/ -v` passando com 100% de sucesso.
- ✅ **Implementar Virtual CTAPHID Bridge (`tools/ctaphid_bridge.py`)** — Ponte USB-HID virtual (UHID no Linux) conectando o simulador `--raw-cbor` ao OS para uso direto com ferramentas oficiais da FIDO Alliance. Framing CTAPHID + wrapping CBOR testados em host (`tests/python/test_ctaphid_bridge.py`, 14 testes). Crate: `tools`. ⬅️ depende de `fido2-simulator --raw-cbor`. Critério: detecção do dispositivo virtual pelo browser e pelo FIDO Conformance Tool (requer Linux/UHID).

---

## Convenções

- Cada incremento deve ter testes associados (Rust + Python quando aplicável)
- Mudanças em API pública exigem atualização do README.md
- Decisões de design relevantes → ADR em `docs/adr/`
- Ao completar um item, mova de ❌ para ✅ com PR reference quando aplicável
- Itens marcados com ⬅️ depende de X devem ser implementados após X
- Quick wins podem ser iniciados imediatamente sem dependências

## Verificação de Segurança e Release (2026-08-14)

- ✅ `AttestationCertificate.private_key` usa `zeroize` no drop em `protocol/ctap2/src/attestation.rs`.
- ✅ API genérica de criptografia com nonce aleatório e teste de unicidade/round trip em `protocol/crypto/src/crypto.rs`.
- ✅ Alvos buildáveis `ctap2_dispatch` e `ctaphid_framing` adicionados ao fuzzing; `cargo-fuzz` instalado.
- 🚧 Execução do fuzzing no Windows bloqueada: ASan não suporta o alvo GNU e o alvo MSVC exige `link.exe` (Visual C++ Build Tools).
- ✅ `CHANGELOG.md` criado; o workspace está em `0.1.1`, sem release publicado durante esta preparação.
- ✅ Workflow de release publica `SHA256SUMS`; nenhuma chave ou assinatura foi criada.
- ✅ **ClientPIN CTAP2.1 interoperável** — Handler substituído (array/mapa CBOR com chaves inteiras, subcomandos da spec, P-256 ECDH + AES-256-CBC + HKDF/HMAC, erros CTAP2), validado por E2E com `fido2.ctap2.pin.ClientPin` (python-fido2 2.2.1) nos protocolos 1 e 2. Detalhes e desvios em `docs/adr/ADR-0017-clientpin-ctap2-wire-format.md`.
- ✅ `FlashStorageBackend` simulado implementa semântica testável de erase/program e recuperação. Isso não prova atomicidade de energia da flash real; ver `docs/adr/ADR-0016-flash-simulada-e-gates-de-release.md`.
- 🚧 Assinatura criptográfica de artefatos está configurada no workflow, mas permanece bloqueada neste ambiente até secrets protegidos serem fornecidos; checksums não são assinatura.
- 🚧 Probe-rs, validação física em RP2350/nRF52840/STM32L4 e execução do FIDO Conformance Tool dependem de ferramentas/placas externas e não foram alegados como executados.
- 🚧 A página oficial da FIDO confirma que o FIDO2 Conformance Test Tool requer registro/acesso de participante; nenhuma ferramenta oficial local foi encontrada ou executada.

## Ciclo de Endurecimento Crítico→Worker (2026-08-21)

Loop auditor (crítico) → correção (worker) → verificação, em 4 iterações + rodada final.
Estado: 316 testes Rust e 220 Python passando; `clippy -D warnings` e `fmt --check` limpos.

### Correções de protocolo
- ✅ **GetNextAssertion assina `authData || clientDataHash`** — hash antes descartado (`#[allow(dead_code)]`); contador global persistido (`sys:global_sign_count`) com incrementos estritamente crescentes; flags UP/UV espelhadas da asserção inicial. Critério: `test_get_next_assertion_signature_counters_and_flags`.
- ✅ **hmac-secret reescrito conforme CTAP 2.1 §12.5** — novo módulo `protocol/ctap2/src/hmac_secret.rs`: keyAgreement inline (protocolos 1 e 2 via `pin_protocol`), `saltAuth` verificado, `CredRandomWithUV/WithoutUV` de 32B por credencial persistidos, IV fresco via `SystemRandom`; removidos os caminhos inseguros de nonce zero + chave mestra. E2E: `tests/python/conformance/test_hmac_secret.py` (12 testes).
- ✅ **Extensões decodificáveis do wire** — `credProtect` (inteiro CBOR) e `credBlob` (byte string via `serde_bytes_opt`) falhavam `decode_cbor` com InvalidCbor; corrigidos com testes de round-trip wire.
- ✅ **GetAssertionRequest com defaults serde** — `allowList`, `options.up` (default true) e `options.uv` omitíveis conforme spec; request mínima não é mais InvalidCbor.

### Correções de segurança
- ✅ **Bloqueio de PIN volátil** — 3 falhas bloqueiam na sessão (`PinAuthBlocked`) mas power cycle recupera; contador persistente de retries mantido. Critério: `test_pin_auth_blocked_clears_on_power_cycle`.
- ✅ **pinHashEnc comparado sem strip de zeros** — PIN cujo `SHA-256[:16]` termina em `0x00` (~1/256) era rejeitado; novo `PinUvProtocol::decrypt_exact(16)`. Critério: `test_trailing_zero_hash_pin_accepted_protocol_{1,2}`.
- ✅ **Token mc/ga exige permissionsRPID** — subcomando 0x09 sem rpId retorna `MissingParameter`; token sem binding não autoriza RP arbitrário.
- ✅ **Reset exige presença física** — sem UP retorna `OperationDenied`; após wipe invalida pinUvAuthToken, pinAgreementKey, segredo compartilhado e contador volátil de falhas.
- ✅ **Credential Management autenticado** — todos os subcomandos exigem token válido mesmo sem PIN configurado (antes: metadados/deleção abertos em dispositivo sem PIN).
- ✅ **Flag UV verdadeira** — bit 0x04 só quando há autenticação real; `CredRandomWithUV` só é divulgado a requests autenticados (antes: bastava pedir `options.uv` sem verificador).
- ✅ **LargeBlobs com bounds** — offset/length validados contra `MAX_LARGE_BLOBS_SIZE` antes de alocação (DoS de ~4 GiB eliminado); leitura com `saturating_add`.
- ✅ **Debug redigido** — `StorageEngine`/`Credential` não imprimem mais kv_store, hash do PIN nem chaves privadas/CredRandoms.
- ✅ **credProtect persistido e aplicado** — política por credencial (`Option<u8>` backward-compatible); nível 3 exige UV em GA/GNA/enumeração; nível 2 exige allowList nomeante ou UV. Critérios: `test_cred_protect_*`, `test_cred_protect_level2_discovery_rules`.

### Dívidas residuais conhecidas
- ✅ **hmac-secret encadeado no GetNextAssertion** — sessão de transação volátil (`HmacSecretSession`: segredo compartilhado + salts decifrados em `Zeroizing`), estabelecida na asserção inicial e limpa em toda fronteira (comando ≠ GetNextAssertion, fim da cadeia, asserção única, Reset); cada asserção encadeada emite `HMAC(CredRandom_da_credencial, salt)` sob o mesmo segredo com IV fresco. Habilitou correção de decodificação de mapas de extensão parciais em `ExtensionOutputs` (`#[serde(default)]`). Crate: `ctap2`. ADR: `docs/adr/ADR-0022-hmac-secret-encadeado-sessao-de-transacao.md`. Critério: `test_hmac_secret_chained_get_next_assertion_protocol_{1,2}`, `test_hmac_secret_chain_cleared_by_other_command`, `test_hmac_secret_session_cleared_on_reset`, `test_hmac_secret_single_assertion_keeps_no_session` e E2E `test_hmac_secret_chained_get_next_assertion` passando.
- ✅ **Gate explícito do storage de host inseguro** — chave-mestra derivada de `SHA-256(caminho)` agora só é acessível via marcador `InsecureHostStorage`; `new_with_storage_path` removido em favor de `new_with_insecure_host_storage` (risco visível em todo call site; produto real exige secure element). Crate: `authenticator`. ADR: `docs/adr/ADR-0023-gate-storage-host-inseguro.md`. Critério: `test_insecure_host_storage_persists_across_restart`, E2E `tests/python/test_persistence.py` e `tests/python/conformance/test_persistence_restart.py` passando.
- 🚧 Built-in UV continua pendente (hardware); sem ele `uv` verdadeiro depende exclusivamente de PIN+token.
- 🚧 `GetNextAssertion` omite `user` entity por asserção encadeada; membro extra `next` em GetAssertionResponse (inofensivo).

## Injeção de Falhas com Atribuição de Camada (2026-08-22)

- ✅ **Fluxo real de diagnóstico (`tests/python/diagnostics/`)** — Ciclo executar → injetar → capturar exceção → atribuir camada responsável → corrigir só o escopo dela → regressão automática. `catalog.py`: 23 falhas deliberadas declarativas (framing, despacho, codec, validação, estado) com controles positivos internos; `runner.py` (`just diagnose`): executa contra simulador recém-iniciado, captura status/sentinela/traceback, compara com golden master e aponta arquivos/símbolos donos da correção; `wire_baseline.json` travado via `--lock`; `test_wire_regression.py` reexecuta o catálogo inteiro em todo pytest — qualquer retorno de erro antigo quebra o CI (verificado: baseline corrompido para 0x05 foi capturado). Guarda `--check-scope LAYER` confere se o diff git respeita os arquivos da camada. Modelo compartilhado em `diagnostics/model.py` (camadas, nomes de erro, escopo por camada); `test_fault_injection.py` refatorado para consumi-lo. Crate: `tests`. Critério: `just diagnose` 23/23 PASS; `pytest tests/python` (271 testes) passando.
- ✅ **Correção de códigos de erro no fio colidindo com a tabela CTAP1** — Identificado por sonda Python comparando o fio contra `CtapError.ERR` do python-fido2: `Ctap2Error::InvalidState` emitia `0x05` (`CTAP1_ERR_TIMEOUT` para hosts reais) em GetNextAssertion/EnumerateRPsNext sem transação; agora retorna `0x30` (`CTAP2_ERR_NOT_ALLOWED`, CTAP 2.1 §6.5.4). Variante `Ctap2Error::InvalidData` (`0x04`, lido como `CTAP1_ERR_INVALID_SEQ`) removida; 52 call sites de falha interna migrados para `Unknown = 0x7F` ("unspecified failure" da spec). Fallback genérico do simulador (`0x05`) e handlers JSON de enumeração (`0x04`) alinhados. Crate: `ctap2`, `simulator`. Critério: sonda não observa mais 0x04/0x05 como erro de estado; `cargo test --workspace`, clippy/fmt e `pytest tests/python` passando; regressões E2E `test_wire_never_leaks_ctap1_transport_codes_for_state_errors` e `test_state_*_is_not_allowed` em `tests/python/test_fault_injection.py`.
- ✅ **Testes E2E Python: `tests/python/test_fault_injection.py`** — Injeção deliberada de falhas com atribuição exata da camada que rejeitou, em vez de busca por padrões no código: FRAMING/TRANSPORTE (frame vazio descartado; frame truncado → EOF sem status), DESPACHO CTAP2 (`0x01` em opcodes desconhecidos, precedência sobre o codec), CODEC CBOR (`0x12`: payload vazio, break token, CBOR truncado, tipo top-level errado, campo obrigatório ausente na desserialização), VALIDAÇÃO DE REQUEST (`0x26` algoritmo não suportado após decodificar; `0x19` colisão em excludeList) e ESTADO DO AUTENTICADOR (`0x30` GetNextAssertion/EnumerateRPsNext sem transação, `0x2E` RP fantasma/storage vazio com recuperação comprovada por controle positivo, PIN via JSON: `0x35` PinNotSet e `0x31` PinInvalid com decremento exato de retries). Cada teste roda controle positivo antes da injeção; divergências apontam a camada real na mensagem. Helpers `send_frame`/`close_stdin`/`wait_exited` e constantes `0x3B/0x3C/NOT_ALLOWED` adicionados a `tests/python/conformance/ctap2_transport.py`. Crate: `tests`. Critério: `pytest tests/python/test_fault_injection.py -v` passando (25 testes).


## Suporte Nativo Yubico — Fase A2+B (2026-08-22)

- ✅ **Roteador ISO 7816-4 puro (`transport::iso7816`)** — Parsing de APDU em forma curta (casos 1/2S/3S/4S; `Le=00`→256; forma estendida rejeitada com `6700` — limitação registrada), Status Words como constantes (`9000`, `6A82`, `6D00`, `6B00`, `6700`, `6985`, `6982`; `61XX` via helper), trait `Applet` (`aid`/`select`/`process`) e `CardRouter`: SELECT por AID exato ou prefixo (vence o mais longo), seleção persistente até o próximo SELECT, comando sem seleção → `6D00`, AID desconhecido → `6A82` preservando a seleção anterior, encadeamento de resposta `61 XX` + GET RESPONSE (INS `0xC0`) como máquina de estados do roteador; comando que não seja GET RESPONSE descarta cadeia pendente; GET RESPONSE fora de sequência → `6985`. 17 testes unitários. Tipos legados `ApduCommand`/`ApduResponse` mantidos para os usuários existentes (`FramedCcidTransport`). Crate: `transport`. Critério: `cargo test -p transport` passando (49 testes).
- ✅ **Dispositivo USB composto HID+CCID no `rp2350-firmware`** — Um único `UsbDevice` sobre o `UsbBusAllocator` compartilhado: interface 0 CTAPHID/HID (`CtapHidClass`) + interface 1 CCID T=0 (`CcidClass`), à maneira de um YubiKey composto (`src/composite.rs`). Acessores públicos `recv_report`/`send_report` adicionados a `CtapHidClass` (backend existente intacto). Loop principal não bloqueante alimenta as duas classes num único ciclo de polling; CCID responde stub `6D 00` até a fase de applets. Identidade padrão `0x1209:0x0001` e opt-in `yubikey5-identity` alimentam o builder único (valem para ambas as interfaces). Critério: `cargo build` e `cargo build --features yubikey5-identity` (thumbv8m.main-none-eabihf) sem erros/warnings.

## Suporte Nativo Yubico — Fase C: Aplicação OATH (2026-08-22)

- ✅ **Applet Yubico OATH (YKOATH) em ISO 7816-4 (`authenticator::yubico_oath`)** — Comandos completos: PUT (0x01), DELETE (0x02), SET CODE (0x03, incl. remoção via key TLV vazia), RESET (0x04 com P1=0xDE/P2=0xAD), RENAME (0x05, extensão ≥5.3.1, duas TLVs de nome), LIST (0xA1), CALCULATE (0xA2, P2 full/truncado), VALIDATE (0xA3 mútuo), CALCULATE ALL (0xA4 com tags 0x75/0x76/0x77/0x7C) e SEND REMAINING (0xA5). AID `A0000005272101`; SELECT devolve versão/salt/desafio/algoritmo via novo hook `Applet::select_response`. Crate: `authenticator`, `transport`, `crypto`. Critério: 27 testes `cargo test -p authenticator` passando.
- ✅ **Código de acesso com PBKDF2-HMAC-SHA1 e validação mútua** — Chave de acesso derivada pelo host (`PBKDF2-HMAC-SHA1(senha, salt=ID, 1000 iters)[:16]`, formato do python-yubikit); confirmação no SET CODE; VALIDATE compara HMAC do desafio pendente em tempo constante (`constant_time_eq`) e adota desafio novo; cada SELECT emite desafio fresco persistido; comandos bloqueados com `6982` até validar. SHA-1 confinado a funções nomeadas `*_ykoath_compat` na `crypto` (documentação registra por quê). Critério: `test_locked_device_blocks_commands_until_validate`, `test_unset_code_removes_authentication`.
- ✅ **Estado OATH cifrado em repouso sob chave reservada `sys:oath`** — Serialização binária versionada + ChaCha20-Poly1305 com nonce aleatório (`SystemRandom`); salt/ID regenerado no RESET; blob ilegível volta a estado de fábrica com log. Segredos zeroizados no drop; Debug redigido em applet/estado/credenciais; nenhum segredo ou nome em logs. Critério: `test_state_blob_is_encrypted_at_rest`, `test_reset_persists_across_restart`.
- ✅ **Contador HOTP monotônico persistido antes da resposta** — CALCULATE vazio usa contador interno e grava avanço antes de expor bytes (rollback em memória se persistência falhar); modo absoluto exige contador ≥ interno (monotonicidade incondicional); IMF define contador inicial; CALCULATE ALL não avança contadores (tags `0x77`/`0x7C` sem resposta). Critério: `test_hotp_counter_monotonic_across_restart`, `test_calculate_all_tags_totp_hotp_and_touch`.
- ✅ **Encadeamento duplo de respostas longas** — Respostas > Le fracionadas pelo roteador (GET RESPONSE) e espelhadas no applet a partir do offset já entregue inline; SEND REMAINING serve janelas ≤255B com `61 XX`/`9000` — compatível com python-yubikit (que continua cadeias com INS `0xA5`) e com hosts ISO clássicos (`0xC0`). Critério: `test_large_list_drains_via_send_remaining_like_yubikit`, `test_large_list_drains_via_get_response`.
- ✅ **Vetores dourados RFC 6238 ponta a ponta** — PUT+CALCULATE truncado reproduz `94287082`/`46119246`/`90693936` (SHA1/SHA256/SHA512, T=59); resposta completa confere contra HMAC independente; HMAC-SHA512/HMAC-SHA1/PBKDF2-SHA1 validados por RFC 4231/2202/6070 na `crypto`. Critério: `test_totp_rfc6238_golden_vectors_through_applet`, `test_hmac_sha512_rfc4231_case*`, `test_pbkdf2_sha1_ykoath_compat_vectors`.
- ✅ **Forma estendida ISO 7816-4 no roteador (`transport::iso7816`)** — Parsing dos casos 2E/3E/4E (byte 5 = `00` com Lc/Le de 2 bytes; `Le=0000` → 65536; frame de 7 bytes com byte 5 nulo interpretado como 2E puro `00 LeHi LeLo`, layout exato do `ExtendedApduFormatter` do python-yubikit para comando sem dados com Le>0; variante legado com Lc explícito `0000` também aceita); truncamento/excesso continuam `6700` e `ApduParseError::ExtendedLengthUnsupported` foi removido. Entrega inline respeita Le grande (sem `61XX` enquanto o payload couber em Le) e preserva encadeamento `61 XX`/GET RESPONSE para Le menor — comportamento da forma curta intocado. python-yubikit passa a operar em modo estendido sobre CCID (versão do Management ≥4.1 reportada como `5.4.0`) e RENAME fica alcançável pelas ferramentas Yubico. Critério: `test_parse_extended_*`, `test_extended_select_and_large_le_delivers_inline_without_chaining` e `test_mixed_short_and_extended_forms_on_same_session` (`cargo test -p transport`); `test_rename_reachable_via_extended_length_frames_through_router` (`cargo test -p authenticator`).
- ✅ **Wiring do applet no `CardRouter` do firmware RP2350** — Bloqueio anterior resolvido pelo porte `no_std` do stack (ring vendido + getrandom custom + features `std`): `main.rs` constrói `StorageEngine`/`CryptoEngine` após a semente de entropia, instancia `OathApplet` + `ManagementApplet` sobre o MESMO storage (`&RefCell<StorageEngine>` — identidade única: serial e estado OATH no mesmo kv) e registra ambos via `register_yubico_applets`. O stub `6D00` do CCID foi substituído por `take_pending_request → router.process → ResponseData::to_bytes → send_response`; CTAPHID intocado. Critério: `cargo check -p authenticator --no-default-features --target thumbv8m.main-none-eabihf`, `cargo build --release` e UF2 regenerada passando.
- ✅ **Feature-gate RS256/rsa (desbloqueio parcial do target bare-metal)** — `rsa`/`rand`/`num-bigint-dig` agora são opcionais na `crypto` atrás da feature default-on `rs256`; passthrough em `ctap2`, `webauthn` e `authenticator` (`default = ["rs256"]`). Com a feature off: negociação de algoritmos trata -257/-37 como não suportados, GetInfo lista só [-7,-8,-35], MC com RSA → `UnsupportedAlgorithm` (4 testes de regressão off-config em `protocol/ctap2/src/ctap2.rs:6450-6562`). Host inalterado com defaults. Critério: `cargo test -p ctap2 --no-default-features` (132) e `--workspace` (381, rs256 on) passando.
- 🚧 **Porte no_std do stack authenticator (pré-requisito do wiring)** — Bloqueios residuais após o gate da RSA, ambos externos/estruturais: (1) `ring 0.17.14` não compila para `thumbv8m.main-none-eabihf` — dependência `getrandom` INCONDICIONAL (compile_error no alvo; sem versão mais nova disponível) + `build.rs` exige toolchain C (contornável: `gcc-arm-none-eabi` 10.3 já instalado pelo pico-setup-windows e pré-configurado via `[env] CC_thumbv8m_main_none_eabihf/AR/CXX` em `examples/rp2350-firmware/.cargo/config.toml`); (2) crates `authenticator`/applets usam `Box<dyn std::error::Error>` em APIs públicas — porte para `core::error::Error`/thiserror no_std é refactor próprio; (3) entropia bare-metal exige fonte contínua (ROM `BootRandom` u128 por boot serve de semente via feature `custom` do getrandom, mas nonces ECDSA exigem TRNG stream real antes de produção). Caminho registrado: ADR de estratégia cripto-embedded (ring patchado vs backend RustCrypto) + série de PRs no_std.

## Suporte Nativo Yubico — Fase D: Aplicação Management (2026-08-22)

- ✅ **Applet YubiKey Management em ISO 7816-4 (`authenticator::yubico_management`)** — Subconjunto de leitura exigido pelo `ManagementSession` smartcard do python-yubikit: SELECT AID (`A000000527471117`) devolve a versão como string ASCII (`"5.4.0"`, extraída por regex pelo host) e READ CONFIG (INS `0x1D`, P1=página) devolve `[len][TLVs…]` com USB supported (`0x01`, obrigatório ao parser), serial (`0x02`), USB enabled (`0x03`), form factor (`0x04`) e firmware version (`0x05`). SET MODE (`0x16`), WRITE CONFIG (`0x1C`) e DEVICE RESET (`0x1F`) não implementados → `6D00`; CLA ≠ 0 → `6E00`; P1 > 0 → `6B00`. Crate: `authenticator`. Critério: 10 testes novos em `cargo test -p authenticator` (37 no total) passando.
- ✅ **Versão reportada `(5,4,0)` no Management** — Desvio consciente do `(3,4,0)` do OATH, imposto pela fonte: `read_device_info` exige ≥ `(4,1,0)` (`require_version`), major == 3 dispara workarounds de NEO e < `(5,0,0)` faz o ykman ignorar `TAG_USB_ENABLED`; `(5,4,0)` evita faixas preview e touch-workaround `4.2.x`. Todos os comandos implementados chegam sem dados (casos 1/2S), então a limitação de forma estendida do roteador não afeta `ykman info`.
- ✅ **Identidade estável com placeholder de hardware** — Serial u32 não nulo gerado via `SystemRandom` no primeiro uso e persistido cifrado (ChaCha20-Poly1305, nonce aleatório) sob a chave reservada `sys:mgmt`; sobrevive a reinícios (`test_serial_is_stable_across_restart`); blob ilegível regenera identidade com log. Form factor `USB_A_KEYCHAIN` (0x01) e capacidades `0x0624` (OATH|FIDO2|mgmt-CCID|CCID geral) documentados como placeholders até wiring de chip ID/produto. Critério: `test_unreadable_state_regenerates_serial`, `test_device_info_fields_parse_like_python_yubikit`.
- ✅ **Helper `register_yubico_applets`** — Registra Management + OATH num mesmo `CardRouter` para reuso quando o wiring bare-metal CCID acontecer; coexistência e roteamento cobertos por testes de roteador nos formatos short (`00 1D 00 00 00`) e extended (`00 1D 00 00` + GET RESPONSE). Critério: `test_router_extended_style_read_config_drains_via_get_response`, `test_router_short_form_read_config_inline_and_oath_coexistence`.
- 🚧 **`ykman list --serials` sobre PCSC** — A resposta do applet já fornece o serial, mas a enumeração host depende de driver CCID concreto de board (Fase E) e do nome do reader contendo "yubico yubikey" para derivação de PID no ykman; fora do escopo desta fase.
- ✅ **APDUs estendidas ponta a ponta (requisito Yubico Authenticator)** — Roteador ISO 7816 aceita formas estendidas (casos 2E/3E/4E, Lc/Le de 16 bits, Le=0→65536) além das curtas; descritor CCID declara bit 17 "short and extended APDU level exchange" e XfrBlock aceita wLevelParameter∈{0,1} (off-by-one do header corrigido: wLevelParameter em [8..10], bRFU em [7]). Yubico Authenticator/ykman podem operar na forma estendida que escolhem quando versão ≥4.1. Critério: `test_xfr_block_extended_level_parameter_accepted`, `test_xfr_block_unknown_level_parameter_rejected`, testes de forma estendida do roteador; UF2 regenerada.
