# ADR-0028: PIV Fase F2a (chaves Ed25519/P-256, OpenPGP deferido)

Status: accepted
Data: 2026-09-03

## Contexto

A Fase F1 (ADR-0027) entregou PIV/OpenPGP stateful com PIN persistente, mas
sem chaves: `GENERATE ASYMMETRIC KEY PAIR` (`0x47`) caía em `6D00` e qualquer
PSO/autenticação respondia `6982`. Com isso, `ykman piv generate-key` não
produz material e não há nada para assinar — o ciclo PIN da F1 não é
observável por hosts reais.

A F2a implementa **somente chaves PIV** (slots `9A`/`9C`/`9D`/`9E`,
algoritmos Ed25519 e P-256 via `crypto::CryptoEngine`). OpenPGP permanece
`6982` em PSO/keygen (deferido para F2b). Restrições herdadas: `no_std`
compatível, sem `unsafe`, sem redesenho de `transport::iso7816`, mesma
assinatura de `register_multiprotocol_applets`, `Debug` redigido e `zeroize`
em segredos (regras do repo e ADR-0006).

Alternativas consideradas:
1. Reutilizar o formato de blob F1 (`versão 1`) com chaves em registros
   `sys:piv:*` separados — rejeitada: espalha o estado cifrado em várias
   chaves do kv e complica atomicidade; um único blob versionado segue o
   padrão OATH/Management.
2. Exigir `VERIFY` para todos os slots no AUTHENTICATE — rejeitada: amplia a
   máquina de sessão antes de validar o caminho básico de assinatura; o gate
   mínimo real (slot `9A`, PIV Authentication) já cobre o caso sensível, e a
   política exacta por slot fica para fase futura.
3. Resposta AUTHENTICATE no invólucro completo `7C/82` do SP 800-73 —
   rejeitada nesta fase: assinatura bruta (Ed25519 64B, P-256 DER) é
   verificável diretamente com `CryptoEngine::verify`/`verify_p256`; o
   invólucro fica para fase futura sem quebrar o contrato atual.

## Decisão

**PIV (`firmware/authenticator/src/yubico_piv.rs`), F2a:**

- `GENERATE ASYMMETRIC KEY PAIR` (`0x47`, `P1=0x00`, `P2=slot`): dados
  `AC 03 80 01 <alg>` (byte único `<alg>` também aceito); `alg` ∈ {`0x11`
  P-256, `0xE0` Ed25519}. Gera via `CryptoEngine` (`generate_p256_key_pair`
  / `generate_key_pair`), persiste cifrado e devolve o objeto `7F49` =
  `7F49 <len> [80 01 <alg>][86 <len> <pubkey>]`. Regeneração sobrescreve o
  slot (privada antiga zeroizada); falha de persistência faz rollback em
  memória. Slot desconhecido → `6A82`; algoritmo inválido → `6A80`.
- `GENERAL AUTHENTICATE` (`0x87`, `P1=<alg|0x00>`, `P2=slot`): desafio bruto
  ou `7C <len> 81 <len> <desafio>` (≤512B); assina com a chave residente
  (`sign` / `sign_p256`) e devolve a assinatura bruta. Slot `9A` sem sessão
  verificada → `6982`; slot desconhecido → `6A82`; sem chave → `6982`;
  `P1` divergente do algoritmo residente ou desafio vazio → `6A80`.
- `GET DATA` (`0xCB`, `3F/FF`): além de `7E`/`5FC102` (F1), tags de chave
  `9A→5FC105`, `9C→5FC10A`, `9D→5FC10B`, `9E→5FC10C` devolvem o objeto
  `7F49` quando há chave; sem chave → `6982`; tag fora do mapa → `6A82`.
- Sessão verificada volátil (`verified: bool`, não persistida): `VERIFY`
  correto e `CHANGE` bem-sucedido ativam; esgotamento de retries derruba;
  reinício exige novo `VERIFY` para o slot `9A`. `SELECT` não altera a
  sessão (desvio documentado).
- Persistência: blob único `sys:piv` (ChaCha20-Poly1305, nonce aleatório)
  em `STATE_FORMAT_VERSION = 2` com migração do blob F1 (`versão 1` → chaves
  vazias, PIN/retries preservados, regravado em `2` na carga).

**Segurança e compatibilidade:** `CLA ≠ 0x00` → `6E00`; `P1/P2` inválidos →
`6B00`; `Debug` redigido (só contagens e slots); `Drop` zeroiza PIN e
privadas; cópia transitória da privada no AUTHENTICATE é zeroizada após o
uso; sem `unsafe`; `multiprotocol.rs` e `examples/rp2350-firmware/src/main.rs`
intocados (construtores inalterados).

Referências: `firmware/authenticator/src/yubico_piv.rs`,
`protocol/crypto/src/crypto.rs` (`generate_key_pair`, `generate_p256_key_pair`,
`sign`, `sign_p256`), `firmware/transport/src/iso7816.rs`, ADR-0027, ADR-0006.

## Consequências

- `cargo test -p authenticator` cobre roundtrip generate→get-data→
  authenticate nos dois algoritmos (verificação independente), persistência
  entre reinícios (com re-`VERIFY` para `9A`), isolamento entre slots, `9A`
  não-autenticado negado (`6982`), `6A82` em slot desconhecido, `6982` em
  slot vazio e migração F1→F2; `cargo test -p transport` intocado.
- Capacidades Management seguem `0x0624` (sem prometer PIV com chaves ao
  host até decisão de anúncio — mesma linha da ADR-0027).
- Fases futuras (F2b+): keygen/PSO OpenPGP, `PUT DATA`, invólucro `7C/82`
  completo, política PIN exacta por slot, certificados X.509 e anúncio de
  capabilities `0x062E` — cada um em ADR próprio, sem mudar roteamento.
- Sem `unsafe` novo; applet verificado `no_std`
  (`cargo check -p authenticator --no-default-features`).
