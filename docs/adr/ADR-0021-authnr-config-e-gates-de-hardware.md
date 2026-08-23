# ADR-0021: authenticatorConfig (0x0D) e Gates de Hardware

Status: accepted / implemented
Data: 2026-08-16

## Contexto

O CTAP 2.1 §6.11 define `authenticatorConfig` (0x0D) para políticas que exigem
`pinUvAuthParam` com permissão `acfg` (0x20) e MAC sobre `0x0D || subCommand || subCommandParams`.
Faltavam `alwaysUv`, `setMinPINLength` com `forceChangePin`, `makeCredUvNotRqd`,
`enterpriseAttestation` one-shot e `setMinPINLengthRPIDs`. O `ClientPIN` já expunha
`pinUvAuthToken` e o `StorageEngine` já suportava backend persistente, mas
`authenticatorConfig` não existia e `consume_ep_pending` não era chamado.
Há ainda gates de hardware pendentes (UV embutido, drivers CCID concretos, NFC/BLE).

## Decisão

Implementado `protocol/ctap2/src/authnr_config.rs` com `handle_authnr_config` registrado
em `Ctap2Authenticator::process_command` para `Ctap2Command::AuthenticatorConfig = 0x0D`:

1. **Wire format** — mapa com chaves inteiras (0x01 subCommand, 0x02 subCommandParams,
   0x03 pinUvAuthProtocol, 0x04 pinUvAuthParam) e fallback de chaves string CTAP 2.0;
   bytes residuais após o item CBOR rejeitados; `subCommandParams` re-codificado para
   `authnr_config_auth_message = 0x0D || subCommand || paramsCBOR`.

2. **Autenticação** — `MissingParameter` se `pinUvAuthProtocol`/`pinUvAuthParam` ausentes;
   `verify_pin_uv_auth_for_operation` com `PERMISSION_ACFG` e checagem de `acfg` em
   `PERMISSION_ACFG` validada via `client_pin::validate_permissions`. Subcomandos de
   política exigem PIN já configurado (`PinNotSet`).

3. **Subcomandos** — `0x01 enableEnterpriseAttestation` grava `sys:cfg_ep_pending=1`
   (one-shot, consumido no próximo `MakeCredential` como `packed` mesmo quando o formato
   padrão é `none`); `0x02 toggleAlwaysUv` e `0x04 makeCredUvNotRqd` alternam flags em
   storage; `0x03 setMinPINLength` valida `newMinPINLength` em `[4,63]`, exige
   `currentPIN` quando `forceChangePin=true`, decifra `currentPIN` com o segredo
   compartilhado da sessão `pin_shared_secret` (consumido, zeroizado), verifica
   `LEFT(SHA-256(pin),16)` em tempo constante, persiste `sys:cfg_min_pin_length`,
   `sys:cfg_min_pin_length_rpids` (JSON) e `sys:cfg_force_change_pin`; `0x05
   setMinPINLengthRPIDs` persiste lista de até 32 RP IDs.

4. **Segredo compartilhado** — `Ctap2Authenticator::pin_shared_secret: Option<(Zeroizing<Vec<u8>>,u8)>`
   retido em `issue_pin_uv_auth_token` e consumido em `verify_current_pin`; `Zeroizing`
   agora implementa `Debug` redigido (`protocol/crypto/src/pin_protocol.rs:66`).

5. **Enforcement** — `is_always_uv` checado em `MakeCredential` e `GetAssertion` antes de
   `up`: se `alwaysUv` ativo e `options.uv==false` → `PinRequired`; `is_force_change_pin`
   bloqueia emissão de novos tokens em `handle_get_pin_token_common` → `PinPolicyViolation`;
   `get_min_pin_length` exposto em `ExtensionOutputs.min_pin_length`.

6. **Storage** — adicionado `StorageEngine::delete(&str)` genérico (`firmware/storage/src/storage.rs:621`)
   para remover flags; `consume_ep_pending` remove a chave ao consumir.

7. **Erro** — `PinPolicyViolation` para `newMinPINLength` fora do intervalo ou `forceChangePin`
   sem `currentPIN`; `PinAuthInvalid` para `currentPIN` decifrado inválido; `InvalidParameter`
   para RPIDs >32.

## Consequências

- `authenticatorConfig` interoperável com `pinUvAuthToken` de protocolos 1/2; 13 testes em
  `authnr_config::tests` cobrem toggle, enforcement de `alwaysUv` em MC/GA, `setMinPINLength`
  com/ sem `forceChangePin`, permissão `acfg`, MAC inválido e `enterpriseAttestation` one-shot.
- `StorageEngine` ganha `delete` genérico além de `delete_credential`; flags de config
  sobrevivem a reinícios via backend.
- `Ctap2Authenticator` passa a ter `pin_shared_secret` com `Debug` redigido; não altera
  `CryptoEngine` nem `DeviceProfile`.
- Gates de hardware permanecem: UV embutido (`getUVRetries` 0x07 ainda `UnsupportedOption`),
  driver CCID concreto por board, stacks NFC/BLE e validação física com `probe-rs`.
