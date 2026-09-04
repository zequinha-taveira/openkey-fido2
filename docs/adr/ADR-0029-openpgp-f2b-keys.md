# ADR-0029: OpenPGP Fase F2b (chave SIG Ed25519/P-256, DECIPHER deferido)

Status: accepted
Data: 2026-09-03

## Contexto

A Fase F2a (ADR-0028) entregou chaves PIV (slots `9A`/`9C`/`9D`/`9E`,
algoritmos Ed25519 e P-256 via `crypto::CryptoEngine`), mas o OpenPGP
permaneceu `6982` em PSO/keygen: `GENERATE ASYMMETRIC KEY PAIR` (`0x47`) caía
em `6D00` e qualquer PSO respondia `6982`. Com isso, não há chave de
assinatura residente nem nada para assinar via `PSO SIGN` (`9E9A`) — o ciclo
PW1 da F1 (ADR-0027) não é observável por hosts OpenPGP reais.

A F2b implementa **somente chaves OpenPGP do slot SIG** (Ed25519 e P-256 via
`crypto::CryptoEngine`). Slots DEC/AUT, `PUT DATA`, mudanças em PIV, E2E
Python, redesenho de `transport::iso7816` e mudanças de hardware estão fora
de escopo. Restrições herdadas: `no_std` compatível, sem `unsafe`, mesma
assinatura de `register_multiprotocol_applets`, `Debug` redigido e `zeroize`
em segredos (regras do repo e ADR-0006).

Alternativas consideradas:
1. Reutilizar o formato de blob F1 (`versão 1`) com a chave em registro
   `sys:openpgp-sig` separado — rejeitada: espalha o estado cifrado em várias
   chaves do kv e complica atomicidade; um único blob versionado segue o
   padrão OATH/Management/PIV-F2a.
2. Exigir `VERIFY` também para `GENERATE` — rejeitada: amplia a máquina de
   sessão antes de validar o caminho básico; o gate mínimo real (PSO SIGN
   exige PW1 verificado) já cobre a operação sensível, e a política exacta
   fica para fase futura.
3. Impressão digital em SHA-1 sobre pacote de chave (formato da spec
   OpenPGP) — rejeitada nesta fase: exigiria confinar SHA-1 novo à `crypto`
   só para um identificador; `SHA-256(pubkey)` bruta é estável e suficiente
   como material de `GET DATA`, com o desvio documentado.

## Decisão

**OpenPGP (`firmware/authenticator/src/yubico_openpgp.rs`), F2b:**

- `GENERATE ASYMMETRIC KEY PAIR` (`0x47`, `P1∈{0x00,0x80,0x81}`,
  `P2=0x00`): dados = byte único `<alg>` ou CRT `B6 03 80 01 <alg>`, com
  `<alg>` ∈ {`0x11` P-256, `0xE0` Ed25519} (mesmos IDs da F2a). Gera via
  `CryptoEngine` (`generate_p256_key_pair` / `generate_key_pair`), persiste
  cifrado e devolve o objeto `7F49` = `7F49 <len> [80 01 <alg>][86 <len>
  <pubkey>]`. Regeneração sobrescreve (privada antiga zeroizada); falha de
  persistência faz rollback em memória. CRT `B8`/`A4` (DEC/AUT, fora de
  escopo) → `6A82`; algoritmo inválido → `6A80`; `P1/P2` fora do mapa →
  `6B00`.
- `PSO SIGN` (`0x2A`, `P1=0x9E`, `P2=0x9A`): dados brutos a assinar
  (1..=512B); assina com a chave SIG residente (`sign` / `sign_p256`) e
  devolve a assinatura bruta (Ed25519 64B, P-256 DER). Sem sessão PW1
  verificada ou sem chave → `6982`; dados vazios/grandes → `6A80`.
- `PSO DECIPHER` (`0x2A`, `P1=0x80`, `P2=0x86`) → sempre `6982` (sem slot
  DEC nesta fase); demais `P1/P2` no PSO → `6B00`.
- `GET DATA` (`0xCA`): além de `004F`/`5F52` (F1), `007A` reflete a chave
  residente (IDs EdDSA/ECDSA, placeholder RSA-2048 quando vazio); `B600`
  devolve o objeto `7F49` quando há chave; `00C5` devolve `SHA-256(pubkey)`
  (32B) quando há chave; `B600`/`00C5` sem chave → `6982`; tag fora do mapa
  → `6A82`.
- Sessão PW1 volátil (`pw1_verified: bool`, não persistida): `VERIFY`
  correto de PW1 (`81`/`82`) ativa — `VERIFY` de PW3 não ativa;
  esgotamento de retries do PW1 derruba; reinício exige novo `VERIFY`.
  `SELECT` não altera a sessão (desvio documentado, como no PIV).
- Persistência: blob único `sys:openpgp` (ChaCha20-Poly1305, nonce
  aleatório) em `STATE_FORMAT_VERSION = 2` com migração do blob F1
  (`versão 1` → slot vazio, PINs/retries preservados, regravado em `2` na
  carga).

**Segurança e compatibilidade:** `CLA ≠ 0x00` → `6E00`; `Debug` redigido
(só contagens e presença de chave); `Drop` zeroiza senhas e privada; cópia
transitória da privada no PSO SIGN é zeroizada após o uso; sem `unsafe`;
`multiprotocol.rs` e `examples/rp2350-firmware/src/main.rs` intocados
(construtores inalterados).

Referências: `firmware/authenticator/src/yubico_openpgp.rs`,
`protocol/crypto/src/crypto.rs` (`generate_key_pair`, `generate_p256_key_pair`,
`sign`, `sign_p256`, `sha256`), `firmware/transport/src/iso7816.rs`,
ADR-0027, ADR-0028, ADR-0006.

## Consequências

- `cargo test -p authenticator` cobre roundtrip generate→get-data→pso-sign
  nos dois algoritmos (verificação independente), persistência entre
  reinícios (com re-`VERIFY` PW1), gate PW1 (PW3 não libera), `6A82` em
  CRT DEC/AUT, `6982` em slot vazio/sem sessão, `6A80` em algoritmo/dados
  inválidos, `6B00` em `P1/P2` fora do mapa e migração F1→F2b;
  `cargo test -p transport` intocado.
- Capacidades Management seguem `0x0624` (sem prometer OpenPGP com chaves
  ao host até decisão de anúncio — mesma linha das ADRs anteriores).
- Fases futuras: slots DEC/AUT + `PSO DECIPHER` real, `PUT DATA`,
  impressão SHA-1 de spec, política PIN exacta e anúncio de capabilities
  `0x062E` — cada um em ADR próprio, sem mudar roteamento.
- Sem `unsafe` novo; applet verificado `no_std`
  (`cargo check -p authenticator --no-default-features`).
