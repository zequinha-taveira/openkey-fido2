# ADR-0030: PIV Fase F2d (PUT DATA com armazenamento de certificado)

Status: accepted
Data: 2026-09-03

## Contexto

A F2a (ADR-0028) entrega GENERATE/AUTHENTICATE e as capacidades estão em
`0x062E`, mas hosts reais (`ykman piv import-certificate`) importam um
certificado X.509 por slot — sem `PUT DATA` (`0xDB`) não há o que ler de
volta no `GET DATA`. Escopo estrito desta fase: só certificados PIV, sem
OpenPGP, sem DEC/AUT, sem redesenho de transporte, mesma assinatura
multiprotocolo. Restrições herdadas: `no_std`, sem `unsafe`, `Debug`
redigido, `zeroize` (regras do repo e ADR-0006).

Alternativas consideradas:
1. Reutilizar as tags `5FC105/0A/0B/0C` só para chaves e criar tags novas
   para certificados — rejeitada: no SP 800-73 essas tags SÃO os objetos de
   certificado; o host endereça o mesmo objeto na escrita e na leitura.
2. Rejeitar certificado acima do teto com `6700` — rejeitada: `6700`
   significa Lc errado no nível da APDU (já tratado no roteador); framing
   válido com dado inaceitável é `6A80`, mesma escolha do GENERATE para
   algoritmo inválido.
3. Exigir `VERIFY` para `PUT DATA` em todos os slots — rejeitada nesta
   fase: segue a política F2a já aceita (só `9A` com gate, demais abertos);
   a política PIN exacta por slot continua futura.

## Decisão

**PIV (`firmware/authenticator/src/yubico_piv.rs`), F2d:**

- `PUT DATA` (`0xDB`, `P1=0x3F`, `P2=0xFF`): dados =
  `<tag-cert 3B> <len-BER> <bytes>` (tags do mapa F2a; `len` curto,
  `81 len` ou `82 lenHi lenLo`; consumo exato). Bytes guardados verbatim
  (em geral o objeto `70` do SP 800-73, DER cru também aceito; roundtrip
  byte-idêntico). Teto `MAX_CERT_LEN = 2048` (DERs de RSA-2048 com folga
  para o invólucro, sem crescimento ilimitado do blob `sys:piv`).
  Tag fora do mapa → `6A82`; TLV malformado, valor vazio ou acima do teto
  → `6A80`; `9A` sem sessão verificada → `6982`. Não exige chave residente.
- `GET DATA`: com certificado devolve os bytes armazenados (vence o objeto
  `7F49`); senão, com chave, o `7F49` (F2a); sem nenhum → `6982`
  (convenção F2a preservada, não `6A82`).
- `GENERATE` num slot apaga o certificado dele (vinculava a chave
  anterior; bytes zeroizados).
- Persistência: `STATE_FORMAT_VERSION = 3` (sufixo
  `[num_certs][slot][cert_len u16BE][cert]…`), migração `v1`/`v2` →
  PIN/retries/chaves preservados, certs vazios, regravado em `3`.

Referências: `firmware/authenticator/src/yubico_piv.rs`
(`INS_PUT_DATA`, `parse_put_data`, `cmd_put_data`), ADR-0028, ADR-0006.

## Consequências

- `cargo test -p authenticator` cobre put→get (cru e `70`), teto exato e
  estouro (`6A80`), persistência entre reinícios (com re-`VERIFY` para `9A`),
  isolamento entre slots, gate `9A`, limpeza na regeneração e migração
  F2a→F3; `cargo test -p transport` e `multiprotocol.rs` intocados.
- Sem validação do certificado contra a chave do slot (parse X.509 fica
  para fase futura); sem `unsafe` novo; applet segue `no_std`.
