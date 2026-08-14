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
- ✅ Sign counter persistence
- ✅ Private key nunca armazenado em plaintext

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
- ✅ **Implementar trait `ClientPin` em `protocol/ctap2/src/client_pin.rs`** — Definir trait com métodos: `get_pin_retries()`, `get_pin_token()`, `set_pin()`, `change_pin()`, `get_pin_hash_enc()`. Crate: `ctap2`. Critério: trait definida e compilável.
- ✅ **Implementar `getPINRetries` (subCommand 0x03)** — Retornar contador de tentativas atuais (iniciar em 8). Crate: `ctap2`, `storage`. Critério: teste unitário `test_get_pin_retries` passando.
- ✅ **Implementar `setPIN` (subCommand 0x01)** — Validar comprimento mínimo (4 bytes), criptografar PIN com SHA-256, armazenar hash no storage. Crate: `ctap2`, `storage`, `crypto`. Critério: teste unitário `test_set_pin` passando, rejeitar PIN < 4 chars.
- ✅ **Implementar `changePIN` (subCommand 0x02)** — Verificar PIN atual via hash, validar novo PIN, atualizar hash. Crate: `ctap2`, `storage`, `crypto`. Critério: teste unitário `test_change_pin` passando, rejeitar PIN atual errado.
- ✅ **Implementar `getPINToken` (subCommand 0x05)** — Derivar token via HMAC-SHA256(key=platformKey, data=pinHash), criptografar token com ChaCha20-Poly1305. Crate: `ctap2`, `crypto`. ⬅️ depende de `setPIN`. Critério: teste unitário `test_get_pin_token` passando.
- ✅ **Implementar `getPINHashEnc` (subCommand 0x06)** — Retornar hash do PIN criptografado com keyAgreement. Crate: `ctap2`, `crypto`. ⬅️ depende de `setPIN`. Critério: teste unitário `test_get_pin_hash_enc` passando.
- ✅ **Adicionar `pinUvAuthProtocol` negotiation** — Suportar protocolos 1 e 2, retornar versão no response. Crate: `ctap2`. Critério: teste unitário `test_pin_protocol_negotiation` passando.
- ✅ **Implementar PIN retry counter decrement/increment** — Decrementar em tentativa falha, reset em sucesso, bloquear após 3 falhas consecutivas (powerCycleState=true). Crate: `ctap2`, `storage`. ⬅️ depende de `getPINRetries`. Critério: teste unitário `test_pin_retry_counter` passando.
- ✅ **Adicionar handler `ClientPIN` no `process_command`** — Mapear subCommands para métodos do trait. Crate: `ctap2`. ⬅️ depende de todos os subitens acima. Critério: `cargo test -p ctap2 -- client_pin` passando.
- ✅ **Testes E2E Python: `tests/python/test_client_pin.py`** — Testar fluxo completo: setPIN → getPINRetries → getPINToken → changePIN. Crate: `tests`. ⬅️ depende do handler. Critério: `pytest tests/python/test_client_pin.py -v` passando.

#### Extensões WebAuthn

- ✅ **Implementar `credProtect` em `protocol/ctap2/src/ctap2.rs`** — Adicionar campo `credProtect` no `MakeCredentialRequest`, aplicar política na criação. Crate: `ctap2`. Critério: teste unitário `test_cred_protect` passando.
- ✅ **Adicionar `credProtect` no `GetInfoResponse`** — Incluir `"credProtect"` na lista de extensions quando suportado. Crate: `ctap2`. Critério: `GetInfo` retorna `credProtect` em extensions.
- ✅ **Implementar `credBlob` get em `protocol/ctap2/src/ctap2.rs`** — Adicionar campo `credBlob` (máx 32 bytes) no `Credential`, recuperar via GetAssertion. Crate: `ctap2`, `storage`. Critério: teste unitário `test_cred_blob_get` passando.
- ✅ **Implementar `credBlob` set em `protocol/ctap2/src/ctap2.rs`** — Validar tamanho máximo (32 bytes), armazenar no credential. Crate: `ctap2`, `storage`. Critério: teste unitário `test_cred_blob_set` passando, rejeitar > 32 bytes.
- ✅ **Implementar `minPinLength` discovery em `protocol/ctap2/src/ctap2.rs`** — Adicionar campo `minPinLength` no `MakeCredentialRequest`, retornar comprimento mínimo configurado. Crate: `ctap2`. Critério: teste unitário `test_min_pin_length` passando.
- ✅ **Adicionar `minPinLength` no `GetInfoResponse`** — Incluir `"minPinLength"` na lista de extensions. Crate: `ctap2`. Critério: `GetInfo` retorna `minPinLength` em extensions.
- ✅ **Implementar `hmac-secret` creation em `protocol/ctap2/src/ctap2.rs`** — Gerar segredo compartilhado via HMAC-SHA256(salt=random, key=credential_private_key), retornar encrypted secret. Crate: `ctap2`, `crypto`. Critério: teste unitário `test_hmac_secret_creation` passando.
- ✅ **Implementar `hmac-secret` get em `protocol/ctap2/src/ctap2.rs`** — Recuperar segredo via GetAssertion com extension `hmac-secret`. Crate: `ctap2`, `crypto`. ⬅️ depende de `hmac-secret` creation. Critério: teste unitário `test_hmac_secret_get` passando.
- ✅ **Testes E2E Python: `tests/python/test_extensions.py`** — Testar credProtect, credBlob, minPinLength, hmac-secret. Crate: `tests`. ⬅️ depende de todas as extensões. Critério: `pytest tests/python/test_extensions.py -v` passando.

#### Persistência Real

- ✅ **Adicionar trait `StorageBackend` em `firmware/storage/src/storage.rs`** — Definir trait com métodos: `read(key) -> Vec<u8>`, `write(key, value) -> Result`, `delete(key) -> Result`. Crate: `storage`. Critério: trait definida e compilável.
- ✅ **Implementar `FileStorageBackend` em `firmware/storage/src/storage.rs`** — Backend usando arquivo JSON local para desenvolvimento. Crate: `storage`. Critério: teste unitário `test_file_storage` passando.
- ✅ **Adicionar `StorageEngine::with_backend(backend: Box<dyn StorageBackend>)`** — Permitir injeção de backend customizado. Crate: `storage`. ⬅️ depende de `StorageBackend`. Critério: `StorageEngine` aceita backend customizado.
- ✅ **Implementar `FlashStorageBackend` stub em `firmware/storage/src/storage.rs`** — Backend placeholder para flash embedded (no_std compatível). Crate: `storage`. Critério: compila com `no_std`.
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
- ✅ **Implementar `UsbHidTransport` stub em `firmware/transport/src/usb_hid.rs`** — Placeholder para implementação USB-HID com `usb-device` crate. Crate: `transport`. Critério: compila, retorna `Unimplemented`.
- ✅ **Implementar `UsbCcidTransport` stub em `firmware/transport/src/usb_ccid.rs`** — Placeholder para implementação CCID. Crate: `transport`. Critério: compila, retorna `Unimplemented`.
- ✅ **Implementar `NfcTransport` stub em `firmware/transport/src/nfc.rs`** — Placeholder para implementação NFC ISO 14443. Crate: `transport`. Critério: compila, retorna `Unimplemented`.
- ✅ **Implementar `BleGattTransport` stub em `firmware/transport/src/ble_gatt.rs`** — Placeholder para implementação BLE GATT server. Crate: `transport`. Critério: compila, retorna `Unimplemented`.
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
- ❌ **Aplicação bare-metal de boot para RP2350 (`examples/rp2350-firmware`)** — Projeto de firmware executável com inicialização de clock, heap allocator (`embedded-alloc`), vetor de interrupção e loop de despacho CTAPHID. Crate: novo `examples/rp2350-firmware`. ⬅️ depende de `transport no_std`. Critério: compilação de binário `.elf` para `thumbv8m.main-none-eabihf`.
- ❌ **Aplicação bare-metal de boot para nRF52840 (`examples/nrf52840-firmware`)** — Firmware executável para Nordic nRF52840 com suporte a USBD e NFC Tag Type 4. Crate: novo `examples/nrf52840-firmware`. ⬅️ depende de `transport no_std`. Critério: compilação de binário `.elf` para `thumbv7em-none-eabihf`.
- ❌ **Integração com driver USB real via `usb-device` para RP2350 (`rp2350-usb`)** — Implementar backend concreto de `UsbHidDevice` sobre `usb-device::bus::UsbBusAllocator`. Crate: `transport`. ⬅️ depende de `examples/rp2350-firmware`. Critério: envio e recebimento de pacotes CTAPHID de 64 bytes em hardware.

#### Conformance Testing & Raw CBOR Tooling

- ✅ **Criar ADR-0012: Suporte a Conformance Testing FIDO2 e Interface Raw CBOR** — Documentar modo `--raw-cbor` no simulador e suíte de testes de conformidade. Crate: N/A. Critério: `docs/adr/ADR-0012-fido-conformance-e-raw-cbor-interface.md` criado.
- ✅ **Implementar modo `--raw-cbor` no `fido2-simulator`** — Suporte a framing binário length-prefixed no stdin/stdout para despacho direto de comandos CTAP2 sem parsing JSON. Crate: `simulator`. Critério: `cargo build -p fido2-simulator` compila e executa.
- ✅ **Criar transporte `SimulatorClient` em Python (`tests/python/conformance/ctap2_transport.py`)** — Ponte binária Python para comunicação bidirecional com o simulador em modo `--raw-cbor`. Crate: `tests`. Critério: módulo funcional.
- ✅ **Implementar suíte de testes de conformidade CTAP 2.1 (`tests/python/conformance/`)** — 11 testes automatizados cobrindo GetInfo, MakeCredential, GetAssertion, ClientPIN, CredentialManagement, LargeBlobs e Reset. Crate: `tests`. Critério: `pytest tests/python/conformance/ -v` passando com 100% de sucesso.
- ❌ **Implementar Virtual CTAPHID Bridge (`tools/ctaphid_bridge.py`)** — Ponte USB-HID virtual (UHID no Linux / virtual authenticator) conectando o simulador ao OS para uso direto com ferramentas oficiais da FIDO Alliance. Crate: `tools`. ⬅️ depende de `fido2-simulator --raw-cbor`. Critério: detecção do dispositivo virtual pelo browser e pelo FIDO Conformance Tool.

---

## Convenções

- Cada incremento deve ter testes associados (Rust + Python quando aplicável)
- Mudanças em API pública exigem atualização do README.md
- Decisões de design relevantes → ADR em `docs/adr/`
- Ao completar um item, mova de ❌ para ✅ com PR reference quando aplicável
- Itens marcados com ⬅️ depende de X devem ser implementados após X
- Quick wins podem ser iniciados imediatamente sem dependências

