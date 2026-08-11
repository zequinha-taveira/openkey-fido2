# Fuzzing — openkey-fido2

Harness de fuzzing para o parsing CBOR do CTAP2, baseado em
[`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) + `libfuzzer-sys`.

Esta crate fica **fora do workspace principal** (`[workspace]` vazio no
`Cargo.toml`), pois `cargo-fuzz` usa perfil, sanitizers e `RUSTFLAGS`
próprios que não devem afetar `cargo build --workspace`.

## Pré-requisitos

`libFuzzer` exige toolchain nightly e um alvo Unix (Linux/macOS). No Windows,
use WSL ou o CI.

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Rodar

A partir da raiz do workspace:

```bash
# Lista os alvos disponíveis
cargo +nightly fuzz list --fuzz-dir fuzz

# Executa o alvo de CBOR (Ctrl-C para parar)
cargo +nightly fuzz run decode_cbor --fuzz-dir fuzz

# Execução limitada por tempo (útil em CI)
cargo +nightly fuzz run decode_cbor --fuzz-dir fuzz -- -max_total_time=60
```

Ou, a partir de `fuzz/`, sem `--fuzz-dir`:

```bash
cd fuzz && cargo +nightly fuzz run decode_cbor
```

## Alvos

| Alvo | O que exercita |
|------|----------------|
| `decode_cbor` | `ctap2::decode_cbor` para `MakeCredentialRequest`, `GetAssertionRequest`, `ClientPinRequest`, `BioEnrollRequest` e `ciborium::value::Value` (inclui roundtrip encode/decode). |

O alvo verifica duas propriedades:

1. **Sem pânico/abort** ao decodificar bytes arbitrários — entradas inválidas
   devem virar `Ctap2Error::InvalidData`, nunca `unwrap` em erro ou estouro.
2. **Roundtrip estável** — todo `Value` decodificado deve reencodar e decodificar
   para um valor igual.

## Artefatos

Crashes e inputs interessantes ficam em:

- `fuzz/artifacts/decode_cbor/` — reproduções de falhas
- `fuzz/corpus/decode_cbor/` — corpus acumulado

Ambos são ignorados pelo git. Para reproduzir uma falha:

```bash
cargo +nightly fuzz run decode_cbor --fuzz-dir fuzz fuzz/artifacts/decode_cbor/crash-<hash>
```

## Adicionar um novo alvo

1. Crie `fuzz/fuzz_targets/<nome>.rs` com `#![no_main]` e a macro `fuzz_target!`
2. Adicione a seção `[[bin]]` correspondente em `fuzz/Cargo.toml`
3. Documente o alvo na tabela acima
