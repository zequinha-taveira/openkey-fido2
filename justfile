# openkey-fido2 - Comandos unificados
# Uso: just <comando>
# Requisito: https://github.com/casey/just

# Comando padrao: lista todos os comandos disponiveis
default:
    @just --list

# Compilar todo o workspace
build:
    cargo build --workspace

# Compilar em modo release
build-release:
    cargo build --workspace --release

# Rodar testes unitarios e de integracao Rust
test:
    cargo test --workspace

# Rodar testes end-to-end (compila o simulador primeiro, depois roda pytest)
test-e2e: build-simulator
    python -m pytest tests/python -v

# Apenas rodar pytest (assumindo que o simulador ja esta compilado)
test-python:
    python -m pytest tests/python -v

# Verificar formatacao
fmt-check:
    cargo fmt --all -- --check

# Aplicar formatacao
fmt:
    cargo fmt --all

# Verificar linter (trata warnings como erros)
clippy:
    cargo clippy --workspace -- -D warnings

# Build + fmt + clippy + test (verificacao completa)
check: build fmt-check clippy test

# Compilar o simulador
build-simulator:
    cargo build -p fido2-simulator

# Rodar o simulador interativamente (stdin/stdout)
sim: build-simulator
    cargo run -p fido2-simulator

# Rodar exemplo basic
example-basic:
    cargo run -p basic-example

# Rodar exemplo ccid
example-ccid:
    cargo run -p ccid-example

# Gerar relatorio de cobertura (Xml + Html em coverage/)
# Requisito: cargo install cargo-tarpaulin
coverage:
    cargo tarpaulin --workspace --out Xml --out Html --output-dir coverage --timeout 300

# Rodar o fuzzer de CBOR (requer nightly + cargo install cargo-fuzz)
fuzz target="decode_cbor" time="60":
    cargo +nightly fuzz run {{target}} --fuzz-dir fuzz -- -max_total_time={{time}}

# Listar alvos de fuzzing disponiveis
fuzz-list:
    cargo +nightly fuzz list --fuzz-dir fuzz

# Gerar documentacao
doc:
    cargo doc --workspace --no-deps

# Gerar documentacao e abrir no browser
doc-open:
    cargo doc --workspace --no-deps --open

# Limpar artefatos de build
clean:
    cargo clean --workspace

# Verificar se tudo esta OK (build + testes + lint)
ci: build test clippy fmt-check
