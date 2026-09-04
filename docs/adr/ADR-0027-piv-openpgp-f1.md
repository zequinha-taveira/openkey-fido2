# ADR-0027: PIV/OpenPGP Fase F1 (PIN stateful + leitura, sem chaves)

Status: accepted
Data: 2026-09-03

## Contexto

A Fase E (ADR-0024) registrou PIV (`A000000308000010000100`) e OpenPGP
(`D27600012401`) como stubs somente-SELECT (`9000` no SELECT, `6D00` em todo o
resto). Hosts reais vão além da detecção: `ykman piv info` emite `GET DATA` e
`VERIFY`, e `gpg --card-status` emite `SELECT` + `GET DATA` + `VERIFY`. Com
stubs, qualquer comando após o SELECT morre em `6D00`, sem estado de PIN.

A F1 precisa de applets minimamente stateful — PIN com tentativas persistentes
e objetos de leitura — sem ainda tocar em geração/gerência de chaves (fases
futuras). Restrições herdadas: `no_std` compatível, sem `unsafe`, sem redesenho
de `transport::iso7816`, mesma assinatura de `register_multiprotocol_applets`,
`Debug` redigido e `zeroize` em segredos (regras do repo e ADR-0006).

Alternativas consideradas:
1. Manter stubs e documentar `6D00` como resposta — rejeitada: hosts PIV/OpenPGP
   não progridem além do SELECT, e tentativas de PIN não são testáveis.
2. PIN volátil (só em RAM) — rejeitada: contador de tentativas precisa sobreviver
   a reinícios, como o `sys:global_sign_count` e o estado OATH já fazem.
3. Implementação completa com chaves (GENERATE/PSO/PUT DATA) nesta fase —
   rejeitada: amplia a superfície criptográfica e de storage antes de validar o
   ciclo PIN + roteamento; PSO sem chaves responderia de qualquer forma.

## Decisão

**PIV (`firmware/authenticator/src/yubico_piv.rs`), AID completo de 11 bytes:**

- `GET DATA` (`0xCB`, P1=`0x3F` P2=`0xFF`): tags `0x7E` (descoberta, AID dentro)
  e `0x5FC102` (CHUID, rótulo fixo) como placeholders determinísticos;
  qualquer outra tag → `6A82`.
- `VERIFY` (`0x20`, P1=`0x00` P2=`0x80`, PIN `0xFF`-padded de 8B): vazio consulta
  tentativas (`63Cx`); correto → `9000` e restaura 3 tentativas; errado →
  decrementa e persiste (`63Cx`, `6982` ao esgotar; bloqueado rejeita até o
  correto). Comparação via `crypto::constant_time_eq` após remover o padding.
- `CHANGE REFERENCE DATA` (`0x24`): `PIN_atual(8B) || PIN_novo(8B)`; PIN novo
  fora de 6..=8 → `6A80` sem consumir tentativa; PIN atual errado consome
  (`63Cx`/`6982`); sucesso troca o PIN e restaura tentativas (`9000`).
- Padrão de fábrica: PIN `"123456"`, 3 tentativas (igual aos YubiKeys físicos).

**OpenPGP (`firmware/authenticator/src/yubico_openpgp.rs`), prefixo `D27600012401`:**

- AID **estendido de 16 bytes** registrado (`AID_OPENPGP_FULL` = prefixo +
  versão `03 00` + placeholders): o `CardRouter` casa `aid.starts_with(requested)`,
  logo o SELECT curto (6B, por prefixo) e o SELECT completo (16B, exato) ambos
  selecionam — sem nenhuma mudança no roteador.
- `SELECT` devolve dados de aplicação `0x6F` (AID `0x4F` + bytes históricos),
  o que `gpg --card-status` espera.
- `GET DATA` (`0xCA`, tag em P1P2): `004F` (AID), `5F52` (bytes históricos),
  `007A` (atributos de algoritmo placeholder); demais tags → `6A82`.
- `VERIFY` (`0x20`): seletor em P1 (ou P2, formato da spec) `81`/`82` (PW1) e
  `83` (PW3); mesma máquina `63Cx`/`9000`/`6982` do PIV, contadores
  independentes por senha. Padrões: PW1 `"123456"`, PW3 `"12345678"`.
- `PSO` (`0x2A`) → `6982` (sem chaves residentes na F1); `0x47` e demais INS →
  `6D00`.

**Persistência e segurança (ambos, padrão OATH em `yubico_oath.rs`):**

- Estado binário versionado cifrado com ChaCha20-Poly1305 (nonce aleatório via
  `SystemRandom`) sob chaves reservadas `sys:piv` / `sys:openpgp`; decremento de
  tentativa persiste antes/depois da resposta (sem janela de reutilização);
  blob ilegível volta à fábrica com `warn!`, como OATH/Management.
- `Debug` redigido (só contagens), `Drop` com `zeroize` nas senhas/PINs, CLA ≠
  `0x00` → `6E00`, P1/P2 inválidos → `6B00`.
- `register_multiprotocol_applets` mantém os 4 parâmetros (só ganha lifetimes
  `'s` dos novos estados com storage); `examples/rp2350-firmware/src/main.rs`
  constrói os 4 applets sobre o mesmo `RefCell<StorageEngine>`.

Referências: `firmware/authenticator/src/yubico_piv.rs`,
`firmware/authenticator/src/yubico_openpgp.rs`,
`firmware/authenticator/src/multiprotocol.rs`,
`firmware/transport/src/iso7816.rs` (roteamento por prefixo), ADR-0024, ADR-0006.

## Consequências

- `ykman piv` / `gpg` progridem até VERIFY/GET DATA com semântica real de
  tentativas; `cargo test -p authenticator` cobre ciclo de PIN, persistência de
  retries entre reinícios, tags/INS desconhecidos e coexistência dos 4 AIDs.
- Capacidades Management seguem `0x0624` (sem prometer PIV/OpenPGP ao host até
  existirem chaves — mesma decisão da ADR-0024).
- Fases futuras (F2+): `GENERATE ASYMMETRIC KEY PAIR`/`PUT DATA`/PSO real,
  `CHANGE` de PW1/PW3 no OpenPGP, objetos PIV adicionais e anúncio de
  capabilities `0x062E` — cada um em ADR próprio, sem mudar roteamento nem
  formato dos blobs F1 (versão `STATE_FORMAT_VERSION = 1` permite migração).
- Sem `unsafe` novo; ambos os applets verificados `no_std` (`cargo check -p
  authenticator --no-default-features`).
