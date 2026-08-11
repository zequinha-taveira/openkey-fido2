# Contribuindo para o openkey-fido2

Obrigado por considerar contribuir! Este documento descreve os padrões e práticas adotadas no projeto.

## Visão Geral do Projeto

O **openkey-fido2** é um autenticador FIDO2/WebAuthn escrito em Rust, projetado para rodar em dispositivos embarcados (no_std) mas desenvolvido e testado em hosts (std).

**Documentação essencial:**
- [`README.md`](README.md) — visão geral e como compilar
- [`AGENTS.md`](AGENTS.md) — guia do agente (fonte de verdade para fluxo de trabalho)
- [`TODO.md`](TODO.md) — estado do projeto e incrementos planejados
- [`docs/adr/`](docs/adr/) — decisões de arquitetura (ADRs)

## Configuração do Ambiente

### Pré-requisitos

- Rust 1.70+ (MSRV definido em `Cargo.toml:30`)
- `just` (command runner) — opcional, mas recomendado
- Python 3.11+ (para testes E2E)

### Compilação Inicial

```bash
cargo build --workspace
```

### Comandos via `just`

```bash
just build      # Compila todo o workspace
just test       # Testes unitários e de integração Rust
just test-e2e   # Testes end-to-end Python (requer simulador compilado)
just fmt        # Verifica formatação (cargo fmt --check)
just clippy     # Linting (cargo clippy)
just sim        # Roda o simulador interativamente
just doc        # Gera documentação
```

## Arquitetura

```
authenticator
    ├── webauthn
    │   └── ctap2
    │       ├── crypto
    │       └── storage
    │           └── crypto
    ├── board-generic
    └── device-profile
        └── board-generic
```

**Regra de dependência:** setas apontam de quem depende para quem é dependido. Nunca crie dependências circulares. Veja [`AGENTS.md`](AGENTS.md) para detalhes completos.

## Padrões de Código

### Estilo e Formatação

- Seguir as convenções padrão do Rust (`rustfmt`)
- Nomes em inglês para código (structs, funções, variáveis)
- Mensagens de commit e documentação em pt-BR

### Estrutura de Erros

- Usar `thiserror` para erros de crate
- Mapear erros internos para `Ctap2Error` nas fronteiras do protocolo
- Erros de validação de input → `Ctap2Error::InvalidParameter`
- Erros de estado → `Ctap2Error::InvalidState`
- Recurso não encontrado → `Ctap2Error::NoCredentials` / `Ctap2Error::InvalidKey`

### Segurança Criptográfica

1. **Nunca** introduza `unsafe` sem justificativa registrada em ADR
2. **Nunca** faça log de chaves privadas, seeds ou material sensível
3. Use `ring` para operações criptográficas — não implemente primitivas próprias
4. Nonces devem ser gerados via `SystemRandom` — nunca use RNG previsível
5. Chaves privadas em memória devem ser zeradas após uso (`Zeroize`)
6. Mudanças em `crypto/` exigem revisão cuidadosa e testes de regressão

## Testes

### Tipos de Teste

| Tipo | Local | Quando Usar |
|------|-------|-------------|
| Unitário | `protocol/crypto/src/*.rs` | Lógica isolada (crypto, parsing, validação) |
| Integração | `tests/src/lib.rs` | Fluxos completos (MakeCredential, GetAssertion) |
| E2E Python | `tests/python/test_*.py` | Validação via simulador |

### Convenções

- Cada incremento deve ter testes associados (Rust + Python quando aplicável)
- Testes unitários no mesmo arquivo do código (`#[cfg(test)] mod tests`)
- Testes de integração em `tests/src/lib.rs`
- Testes E2E em `tests/python/test_*.py` via simulador

### Exemplo de Teste Unitário

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_my_feature_basic_case() {
        let result = my_function(valid_input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_my_feature_rejects_invalid_input() {
        let result = my_function(invalid_input);
        assert!(result.is_err());
    }
}
```

### Rodando os Testes

```bash
# Todos os testes
cargo test --workspace

# Apenas um crate
cargo test -p crypto

# Testes E2E (requer simulador compilado)
cargo build -p fido2-simulator
python -m pytest tests/python -v
```

## Processo de Contribuição

1. **Verifique o [`TODO.md`](TODO.md)** para ver o que já está mapeado
2. **Consulte as ADRs** em `docs/adr/` para entender decisões existentes
3. **Planeje antes de implementar** — divida tarefas grandes em etapas pequenas
4. **Uma mudança lógica = uma PR/commit**
5. **Testes são obrigatórios** para código novo ou modificado
6. **Rode `just fmt` e `just clippy`** antes de abrir PR

### Mensagens de Commit

- Estilo do repositório (conciso, imperativo)
- Referencie ADR quando relevante: `adr: ADR-0006 — ...`
- Referencie issues quando aplicável: `fixes #123`

### Pull Requests

- Descrição clara do que muda e por quê
- Referencie o item do TODO.md sendo resolvido
- Inclua critério de aceitação (como verificar que funciona)
- Atualize TODO.md marcando itens como ✅

## Criando um ADR

Quando tomar uma decisão de design relevante:

1. Copie `docs/adr/ADR-0000-template.md`
2. Renomeie para `ADR-NNNN-titulo-curto.md`
3. Preencha: Contexto, Decisão, Consequências
4. Referencie no commit message: `adr: ADR-NNNN — ...`
5. Não edite ADRs antigos — crie novos para registrar mudanças de direção

## Licença

Ao contribuir, você concorda que suas contribuições serão licenciadas sob **MIT OR Apache-2.0** (dual-license do projeto).
