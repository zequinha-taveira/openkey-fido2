# ADR-0017: ClientPIN CTAP2 Wire Format — Implementação Interoperável

Status: accepted / implemented
Data: 2026-08-15 (decisão de formato: 2026-08-14)

## Contexto

O handler original de `authenticatorClientPIN` (0x06) usava subcomandos
renumerados, chaves CBOR de string, ChaCha20-Poly1305 com nonce zero e um
segredo compartilhado persistido em storage — formato host-only, não
interoperável. A migração foi registrada como bloqueada em
`ADR-0014-clientpin-wire-format-compatibilidade.md` e neste ADR.

## Decisão

O handler foi substituído por uma implementação CTAP 2.1 (§6.5) com o
cliente de referência `fido2.ctap2.pin.ClientPin` (python-fido2 2.2.1):

1. **Wire format** — Request aceita três formas:
   - array CBOR posicional (o que python-fido2/Chromium enviam), com
     parâmetros opcionais compactados **sem lacunas** e atribuídos na ordem
     definida pela spec para cada subcomando (`setPIN`:
     keyAgreement, pinUvAuthParam, newPinEnc; `changePIN`: + pinHashEnc;
     `getPinToken`: keyAgreement, pinHashEnc; subcomandos 0x06/0x09:
     keyAgreement, (pinHashEnc,) permissions, rpId);
   - mapa com chaves inteiras (CTAP 2.1 §6.5.5: `0x01` pinUvAuthProtocol,
     `0x02` subCommand, `0x03` keyAgreement, `0x04` pinUvAuthParam,
     `0x05` newPinEnc, `0x06` pinHashEnc, `0x09` permissions, `0x0A` rpId);
   - mapa com chaves string (CTAP 2.0), por compatibilidade.
   - Response: mapa CBOR canônico com chaves inteiras `0x01..0x05`
     (keyAgreement, pinUvAuthToken, retries, powerCycleState, uvRetries).
     O `root_ctap_keys` do ctap2.rs não é usado pelo ClientPIN — o codec é
     dedicado em `protocol/ctap2/src/client_pin.rs`.

2. **Subcomandos (numeração da spec)**: getPINRetries=0x01,
   getKeyAgreement=0x02, setPIN=0x03, changePIN=0x04, getPinToken=0x05,
   getPinUvAuthTokenUsingUvWithPermissions=0x06, getUVRetries=0x07,
   getPinUvAuthTokenUsingPinWithPermissions=0x09.

3. **Criptografia** (`protocol/crypto/src/pin_protocol.rs`):
   - Acordo P-256 ECDH via `ring::agreement::ECDH_P256`; a chave privada
     anunciada em getKeyAgreement é mantida na sessão e usada no subcomando
     seguinte (`decapsulate`); uma nova chave é gerada a cada transação.
   - Protocolo 1: `kdf(Z) = SHA-256(Z)`; AES-256-CBC com IV zero;
     `authenticate` = HMAC-SHA-256 truncado a 16 bytes.
   - Protocolo 2: `kdf(Z) = HKDF("CTAP2 HMAC key") || HKDF("CTAP2 AES key")`
     (salt 32×0); AES-256-CBC com IV aleatório prefixado; HMAC-SHA-256
     completo; pinUvAuthToken de 32 bytes.
   - `AES-256-CBC` via crates RustCrypto `aes`/`cbc` (ring não oferece CBC).
   - `newPinEnc`: PIN zero-padded a 64 bytes antes da cifra.

4. **Retries**: 8 máximos; decremento antes da verificação do PIN; reset em
   sucesso; após 3 falhas consecutivas → `CTAP2_ERR_PIN_AUTH_BLOCKED`
   (powerCycleState=true); contador persistido no storage. `pinAuth` é
   verificado **antes** de consumir tentativas; comparação em tempo
   constante (`crypto::constant_time_eq`).

5. **Erros**: `PIN_INVALID 0x31`, `PIN_BLOCKED 0x32`, `PIN_AUTH_INVALID 0x33`,
   `PIN_AUTH_BLOCKED 0x34`, `PIN_NOT_SET 0x35`, `PIN_REQUIRED 0x36`,
   `PIN_POLICY_VIOLATION 0x37`, `PIN_TOKEN_EXPIRED 0x38`, `UV_BLOCKED 0x3C`,
   `UNAUTHORIZED_PERMISSION 0x40` e `MISSING_PARAMETER 0x14` no `Ctap2Error`.

6. **GetInfo**: `pinUvAuthProtocols` = [1, 2]; options com `clientPin` e
   `pinUvAuthToken`; `uv` ausente (falso). `clientPin` é anunciado como
   *suporte* da feature (python-fido2 exige a option para enviar `setPIN`).

7. **Segurança**: segredos/PINs/tokens em `Zeroizing`; `Debug` redigido para
   chave de acordo e token; nenhum log de material sensível; hash
   `LEFT(SHA-256(pin), 16)` persistido — nunca o PIN em claro.

## Desvios registrados do pedido original

- `UNAUTHORIZED_PERMISSION` implementado como `0x40` (CTAP 2.1 §8.2 e
  python-fido2), e não `0x3A` (que é `CTAP2_ERR_ACTION_TIMEOUT`).
- Numeração dos subcomandos segue a spec (§6.5.5), e não a numeração
  legada do handler anterior.
- No protocolo 2, o ciphertext usa IV aleatório prefixado e a chave AES
  derivada por HKDF ("CTAP2 AES key") — exigido pela spec §6.5.7 e pelo
  `PinProtocolV2.decrypt` do python-fido2. O IV zero restringe-se ao
  protocolo 1.
- O pinUvAuthToken do protocolo 2 é um valor aleatório de 32 bytes
  (spec §6.5.7 `resetPinUvAuthToken`); o HKDF deriva as chaves do
  protocolo, não o token em si.

## Consequências

- Interoperabilidade com python-fido2 2.2.1 validada por E2E
  (`tests/python/conformance/test_client_pin.py`, 15 testes, protocolos 1
  e 2, set_pin/get_pin_token/change_pin/get_pin_token+permissions).
- `firmwareVersion` do GetInfo permanece string (CTAP 2.0 style); o
  python-fido2 exige inteiro (CTAP 2.1 §6.4). Lacuna pré-existente fora do
  escopo do ClientPIN; contornada no adaptador de teste e registrada no
  relatório.
- Sessão de pinUvAuthToken: estado em memória no `Ctap2Authenticator` com
  `verify_pin_uv_auth_param()` público. MakeCredential/GetAssertion validam
  MAC, permissão e binding de RP; Credential Management valida
  `subCommand || subCommandParams`.
- Sem validação física de hardware (ver ADR-0011/ADR-0016).
