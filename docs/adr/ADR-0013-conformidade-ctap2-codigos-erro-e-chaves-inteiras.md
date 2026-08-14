# ADR-0013: Conformidade CTAP 2.1 — Códigos de Erro e Chaves CBOR Inteiras

Status: proposed
Data: 2026-08-14

## Contexto

Uma revisão independente do código (Rust + suíte Python) identificou que o
firmware e os testes **não estão em conformidade com o wire format CTAP 2.1** em
dois pontos estruturais:

1. **Códigos de erro fora da spec** — `Ctap2Error` em
   `protocol/ctap2/src/ctap2.rs` usa um esquema de numeração próprio
   (`CredentialExists=0x0A`, `UnsupportedAlgorithm=0x0C`, `OperationDenied=0x13`,
   `NoCredentials=0x0E`, faixa PIN custom `0x31-0x38`, `RequestTooLarge=0x40`,
   etc.).
2. **Chaves CBOR em string** — os structs de request/response usam
   `#[serde(rename = "clientDataHash")]`, `"rpId"`, `"allowList"`, etc. (chaves
   texto), enquanto a spec exige **chaves inteiras** (`0x01`, `0x02`, …).

Consequência crítica: a suíte `tests/python/conformance/` (introduzida no
ADR-0012) espelha os **mesmos valores errados** do firmware — ela valida a
consistência interna, não a spec. Um autenticador não-conforme **passaria**, e
um cliente real (navegador / FIDO Conformance Tool), que usa chaves inteiras e
os códigos oficiais, **falharia**. Isso contradiz diretamente a promessa do
ADR-0012 ("códigos de erro de especificação", "wire format idêntico ao de
produção").

### Especificação alvo

Este projeto mira **CTAP 2.1** (ADR-0012, suíte `conformance/`, docstrings). A
CTAP 2.1 reformulou a tabela de erros em relação à CTAP 2.0 (ex.: `0x27` passou
de `PIN_REQUIRED` para `OPERATION_DENIED`; `0x31-0x3C` virou a faixa
PIN/UV/operacional). A referência autoritativa adotada é a tabela de
`CtapError.ERR` da biblioteca **`fido2`** (Yubico), que é a mesma biblioteca
importada pelos testes Python.

## Decisão

### 1. Adotar a tabela de códigos de erro CTAP 2.1 (referência `fido2`)

Reescrever `Ctap2Error` para usar os valores e nomes oficiais da CTAP 2.1:

| Código | Nome CTAP 2.1 |
|--------|---------------|
| 0x00 | `Success` |
| 0x01 | `InvalidCommand` |
| 0x02 | `InvalidParameter` |
| 0x03 | `InvalidLength` |
| 0x04 | `InvalidSequence` |
| 0x11 | `CborUnexpectedType` |
| 0x12 | `InvalidCbor` |
| 0x14 | `MissingParameter` |
| 0x15 | `LimitExceeded` |
| 0x18 | `LargeBlobStorageFull` |
| 0x19 | `CredentialExcluded` |
| 0x21 | `Processing` |
| 0x22 | `InvalidCredential` |
| 0x23 | `UserActionPending` |
| 0x24 | `OperationPending` |
| 0x25 | `NoOperations` |
| 0x26 | `UnsupportedAlgorithm` |
| 0x27 | `OperationDenied` |
| 0x28 | `KeyStoreFull` |
| 0x2B | `UnsupportedOption` |
| 0x2C | `InvalidOption` |
| 0x2E | `NoCredentials` |
| 0x2F | `UserActionTimeout` |
| 0x31 | `PinInvalid` |
| 0x32 | `PinBlocked` |
| 0x33 | `PinAuthInvalid` |
| 0x34 | `PinAuthBlocked` |
| 0x35 | `PinNotSet` |
| 0x36 | `PuatRequired` |
| 0x37 | `PinPolicyViolation` |
| 0x38 | `PinTokenExpired` |
| 0x39 | `RequestTooLarge` |
| 0x3A | `ActionTimeout` |
| 0x7F | `Other` |

Mapeamento do enum atual → spec (os casos sem 1:1 exigem análise por call site):

| Atual (valor) | CTAP 2.1 (valor) |
|---------------|------------------|
| `CredentialExists` (0x0A) | `CredentialExcluded` (0x19) |
| `UnsupportedAlgorithm` (0x0C) | `UnsupportedAlgorithm` (0x26) |
| `OperationDenied` (0x13) | `OperationDenied` (0x27) |
| `NoCredentials` (0x0E) | `NoCredentials` (0x2E) |
| `RequestTooLarge` (0x40) | `RequestTooLarge` (0x39) |
| `LargeBlobStorageFull` (0x41) | `LargeBlobStorageFull` (0x18) |
| `UnsupportedOption` (0x0D) | `UnsupportedOption` (0x2B) |
| `InvalidOption` (0x06) | `InvalidOption` (0x2C) |
| `Processing` (0x0B) | `Processing` (0x21) |
| `InvalidKey` (0x11) | `InvalidCredential` (0x22) |
| `PinInvalid` (0x31) | `PinInvalid` (0x31) — mantém |
| `PinInvalidRetries` (0x32) | `PinBlocked` (0x32) |
| `PinPolicyViolation` (0x34) | `PinPolicyViolation` (0x37) |
| `PinTokenExpired` (0x36) | `PinTokenExpired` (0x38) |
| `Unknown` (0x7F) | `Other` (0x7F) — mantém |
| `InvalidData` (0x04) | `InvalidCbor` (0x12) na decodificação; `Other` (0x7F) p/ erro interno — **analisar por call site** |
| `InvalidState` (0x05) | sem equivalente 1:1 — **analisar** (provável `InvalidOption`/`Other`) |
| `Timeout` (0x08) | `ActionTimeout` (0x3A) ou `UserActionTimeout` (0x2F) — **analisar** |
| `PinRequired` (0x33) | `PinNotSet` (0x35) quando PIN não definido; `PuatRequired` (0x36) quando token necessário — **analisar** |
| `PinTokenRequired/Pending/Failure` (0x35/0x37/0x38) | conceitos inventados → mapear para `PuatRequired`/`UserActionPending`/`Other` — **analisar** |

Regras:
- Decodificação CBOR que falha → `InvalidCbor` (0x12) ou `MissingParameter` (0x14) conforme o caso.
- Erro interno de storage/crypto → `Other` (0x7F), nunca vazando detalhes sensíveis.

### 2. Chaves CBOR inteiras

Converter todos os structs de request/response CTAP2 para chaves inteiras
conforme a spec. Chaves principais (CTAP 2.1):

- **makeCredential (0x01)**: `0x01` clientDataHash · `0x02` rp · `0x03` user ·
  `0x04` pubKeyCredParams · `0x05` excludeList · `0x06` extensions ·
  `0x07` options · `0x08` pinUvAuthParam · `0x09` pinUvAuthProtocol ·
  `0x0A` enterpriseAttestation.
- **getAssertion (0x02)**: `0x01` rpId · `0x02` clientDataHash · `0x03` allowList ·
  `0x04` extensions · `0x05` options · `0x06` pinUvAuthParam ·
  `0x07` pinUvAuthProtocol.
- **getInfo (0x04)**: `0x01` versions · `0x02` extensions · `0x03` aaguid ·
  `0x04` options · `0x05` maxMsgSize · `0x06` pinUvAuthProtocols · `0x0A` algorithms.
- Mapas aninhados também: `rp {0x01: id, 0x02: name}`, `user {0x01: id, 0x02: name,
  0x03: displayName}`, `options {0x01: rk, 0x02: uv, ...}`, descriptors
  `{0x01: type, 0x02: id}`.
- **Exceção**: mapas de *extensions* (identificadores de extensão) permanecem
  com chaves string — são strings na spec.

**Abordagem de implementação (recomendada)**: manter `ciborium` e escrever um
codec próprio com chaves inteiras (a `attestation.rs` já usa `ciborium::Value` +
`ciborium::value::Integer` para chaves COSE inteiras, estabelecendo o padrão do
repo). Alternativa considerada e descartada por ora: migrar para `minicbor`
(`#[n(N)]`), mais limpo a longo prazo mas com custo de troca de dependência e de
todos os call sites de `encode_cbor`/`decode_cbor`.

### 3. Semântica de `NoCredentials`

`NoCredentials` **existe** na CTAP 2.1 (0x2E). `getAssertion`/`getNextAssertion`
com `allowList` sem match e `enumerateRPs`/`enumerateCredentials` sem dados
devem retornar `NoCredentials` (0x2E) — não "success vazio". Mantém-se o erro,
apenas corrige-se o valor.

### 4. Plano de execução em fases

- **Fase 1** — Códigos de erro (Rust + Python + `tests/src/lib.rs` + `simulator` +
  `webauthn` + `authenticator`), incluindo análise por call site dos casos
  ambíguos da tabela.
- **Fase 2** — Chaves CBOR inteiras (Rust + `virtualauthenticator.py` +
  `conformance/`), com `test_get_info.py` corrigindo `maxMsgSize` (0x05).
- **Fase 3** — Robustez Python (`ctap2_transport.py` teardown/`close()`,
  `test_persistence.py` `try/finally`, `test_algorithms.py` `returncode`/`OSError`,
  `_b64(None)`, edge cases `board/cbor.py`, deduplicação de fixture).

Critério de aceite: `cargo test --workspace` e `pytest tests/python -v` verdes, e
a suíte `conformance/` validando contra a tabela CTAP 2.1 (sem "hedge" de chaves
string/inteiras).

## Consequências

### Positivas
- Conformidade real com CTAP 2.1: navegadores e o FIDO Conformance Tool
  passarão a interoperar com o firmware.
- A suíte `conformance/` passa a dar garantia verdadeira (valida contra a spec,
  não contra o próprio firmware).
- Consistência com a `fido2` lib (referência adotada) elimina ambiguidade nos
  testes.

### Negativas / Tradeoffs
- **Mudança quebra o wire format**: qualquer cliente/ferramenta que já fale o
  formato string-key atual deixará de funcionar até ser atualizado.
- Trabalho amplo e transversal (~130 call sites de `Ctap2Error` em 4 crates +
  structs CBOR + Python), com risco de regressão em comandos menos exercitados.
- ADR-0012 precisa de nota de correção (a "conformidade" prometida lá não era
  real antes desta mudança).
