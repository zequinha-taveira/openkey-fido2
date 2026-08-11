# ADR-0006: Side-Channel Mitigation para Código Criptográfico

Status: accepted
Data: 2026-08-09

## Contexto

Implementações criptográficas podem vazar informações sensíveis (chaves privadas,
tokens PIN, segredos de credencial) através de canais laterais como:

- **Timing attacks**: tempo de execução varia baseado nos dados de entrada
- **Memory dumps**: material sensível permanece em memória após uso
- **Cache attacks**: padrões de acesso à memória revelam informações

O `openkey-fido2` lida com chaves privadas, PINs e tokens que precisam ser protegidos
contra essas ameaças, especialmente em dispositivos embarcados onde o controle sobre
o ambiente de execução é limitado.

## Decisão

Aplicar as seguintes mitigações de side-channel no código criptográfico:

1. **Constant-time comparison**: Usar `constant_time_eq()` para comparar hashes de PINs,
   tokens e outros segredos. A função executa em tempo independente do conteúdo dos
   dados, realizando XOR byte-a-byte e acumulando o resultado.

2. **Zeroização de memória**: Derivar `Zeroize` com `#[zeroize(drop)]` nas structs que
   contêm material sensível (`Credential`, `StoredCredential`). Isso garante que chaves
   privadas, `cred_blob` e outros dados sejam sobrescom zeros ao serem desalocados.

3. **Rotação de PIN hash**: Armazenar apenas hash do PIN (SHA-256), nunca o PIN em plaintext.
   O hash é zerado junto com a struct no drop.

4. **Limitação de PIN attempts**: Bloquear após 3 tentativas consecutivas falhas para
   mitigar ataques de força bruta que poderiam explorar timing differences.

## Consequências

Positivas:
- Chaves privadas e PINs não permanecem em memória após uso
- Comparações de segredos não vazam informação via timing
- Conformidade com boas práticas de segurança FIDO2/CTAP2
- Custo computacional mínimo (XOR + write zeros)

Negativas:
- Zeroização não protege contra ataques que ocorrem **durante** a vida do dado
  (ex: cold boot attack antes do drop)
- `zeroize` crate adiciona uma dependência ao workspace
- Não há proteção contra ataques de power analysis ou EM leakage
  (fora do escopo deste projeto)

Referências:
- `protocol/crypto/src/crypto.rs:300` — `constant_time_eq()`
- `firmware/storage/src/storage.rs:184` — `#[zeroize(drop)]` em `Credential`
- `protocol/ctap2/src/client_pin.rs` — rate limiting e PIN hash rotation
- Crate `zeroize`: https://crates.io/crates/zeroize
