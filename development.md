# Desenvolvimento do openkey-fido2

## Fluxo de Trabalho Obrigatório

### 1. Planejar antes de implementar

Antes de escrever código para qualquer funcionalidade não-trivial:

1. Leia este `AGENTS.md` e o `README.md` para entender a arquitetura
2. Consulte `TODO.md` para verificar se a tarefa já está mapeada
3. Identifique quais crates serão afetadas (veja "Mapeamento de Crates")
4. Escreva um plano com etapas pequenas e verificáveis
5. Apresente o plano antes de implementar

**Exemplo de plano bom:**
```
- [ ] Adicionar `ClientPIN` trait ao `protocol/crypto`
- [ ] Implementar `getPINToken` no `Ctap2Authenticator`
- [ ] Adicionar testes em `tests/src/lib.rs`
- [ ] Adicionar caso em `tests/python/test_firmware_sim.py`
- [ ] Atualizar `TODO.md`
```

### 2. Dividir tarefas grandes

- Uma PR = uma mudança lógica
- Testes são obrigatórios para código novo
- Mudanças em API pública exigem atualização da documentação

### 3. Manter histórico estruturado

- Decisões de design → `docs/adr/ADR-NNNN-titulo.md`
- Mudanças significativas → registrar no ADR relevante ou criar novo
- Progresso → atualizar `TODO.md`

### 4. Documentação como fonte de verdade

- `README.md` — visão geral e como compilar
- `AGENTS.md` (este arquivo) — guia do agente
- `TODO.md` — estado do projeto
- `docs/adr/` — decisões de arquitetura
- `CONTRIBUTING.md` — padrões de código e testes

Não repita instruções de conversa em código ou docs. Referencie estes arquivos.

### 5. Documentação como Roteador de Contexto (ADR-0005)

A documentação deste repositório funciona como **roteador de contexto** para
agentes de IA. O fluxo é:

```
AGENTS.md (guia) → TODO.md (tarefas) → carrega apenas o contexto necessário
```

**Princípios:**
- **Fonte única da verdade** — informação vive em um arquivo, não em instruções
  de conversa passadas
- **Divulgação progressiva** — agente lê o guia, consulta o manifesto, carrega
  apenas o contexto necessário para a tarefa atual
- **Sem duplicação** — não copie conteúdo entre arquivos; referencie com paths
  (`arquivo:linha`)

**Para subagents:**
- Forneça apenas task description, minimum context, output criteria e explicit
  restrictions
- Não despeje TODO.md/AGENTS.md completos quando apenas uma seção é relevante
- Estado compartilhado existe apenas em arquivos do repositório

---

## Padrões de Código

### Conventions Gerais

- Cada incremento deve ter testes associados (Rust + Python quando aplicável)
- Mudanças em API pública exigem atualização do README.md
- Decisões de design relevantes → ADR em `docs/adr/`
- Ao completar um item, mova de ❌ para ✅ com PR reference quando aplicável
- Itens marcados com ⬅️ depende de X devem ser implementados após X
- Quick wins podem ser iniciados imediatamente sem dependências

### Padrões de Código

- Todas as funções públicas devem ter doc comments `///`
- Use `thiserror` para criar erros do crate
- Não use `unsafe` sem uma ADR documentada
- Use `ring` para operações criptográficas
- Nunca faça log de chaves privadas, seeds ou material sensível
- Chaves privadas em memória devem ser zeradas após uso quando possível

---

## Fluxo de Trabalho de desenvolvimento

### 1. Fork e branch

1. Faça um fork do repositório
2. Crie uma branch com uma mensagem descritiva:
   ```
   feat: Adicionar suporte a ClientPIN
   ```

### 2. Testes

- **Testes unitários Rust**: `cargo test -p <crate>`
- **Testes E2E Python**: `python -m pytest tests/python -v` (requer simulador compilado)
- **Testes de integração**: `cargo test -p test-suite`
- **Testes para todas as crates**: `cargo test --workspace`

### 3. Build

```bash
# Compilar todo o workspace
cargo build --workspace

# Compilar apenas uma crate
cargo build -p <crate>
```

### 4. Testes

```bash
# Testes unitários e de integração Rust
cargo test --workspace

# Testes end-to-end (requer simulador compilado)
cargo build -p fido2-simulator
python -m pytest tests/python -v
```

### 5. Formatação e Lint

```bash
# Verificar formatação e linter
cargo fmt --check --workspace
cargo clippy --workspace -- -D warnings
```

### 6. Preparação de PR

1. Execute `cargo fmt --check --workspace` antes de enviar
2. Execute `cargo test -p ctap2 -- client_pin` para verificar os testes
3. Execute `cargo test --workspace` para executar todos os testes

### 7. Enviar um PR

1. Faça um fork do repositório
2. Crie uma branch com uma mensagem descritiva
3. Execute `cargo test -p ctap2 -- client_pin` para verificar os testes
4. Envie o PR para a branch `main`

### 8. ADRs (Decisões de Arquitetura)

Documentações de decisões de design (ADR) são em `docs/adr/`. Cada ADR deve ter:

1. **Contexto**: Por que a decisão foi tomada
2. **Decisão**: Qual foi a decisão
3. **Consequências**: Impactos positivos e negativos

### 9. Justifications

- Cada PR deve ter um teste que passa
- Todo commit deve ter um ADR referenciado (se aplicável)
- Toda mudança em API pública deve ser documentada no README.md

### 10. Ciclo de Feedback

1. Após criar a branch, execute `cargo test --workspace` para validar
2. Faça uma pull request com uma descrição clara
3. Revise o PR e execute `cargo clippy --workspace -- -D warnings`
4. Aplique apenas o diff correto nos arquivos

---

## Comandos Essenciais

```bash
# Compilar todo o workspace
cargo build --workspace

# Testes unitários e de integração Rust
cargo test --workspace

# Testes end-to-end (requer simulador compilado)
cargo build -p fido2-simulator
python -m pytest tests/python -v

# Verificar formatação e linter
cargo fmt --check --workspace
cargo clippy --workspace -- -D warnings

# Rodar o simulador interativamente
cargo run -p fido2-simulator

# Rodar exemplos
cargo run -p basic-example
cargo run -p ccid-example
```

Os mesmos comandos estão disponíveis via [`just`](https://github.com/casey/just):
`just build`, `just test`, `just test-e2e`, `just check`, `just coverage`,
`just fuzz`. Veja `just --list`.

---

## Estrutura do Projeto

```
openkey-fido2/
├── Cargo.toml           # Workspace + crate dependencies
├── README.md            # Documentação e badge do projeto
├── AGENTS.md            # Guia do agente (este arquivo)
├── TODO.md              # Estado do projeto e incrementos
├── docs/
│   └── adr/             # Decisões de arquitetura (ADR)
│       ├── ADR-0000-template.md
│       └── ADR-NNNN-*.md
├── firmware/
│   ├── authenticator/   # Coordenação das camadas
│   ├── board-generic/   # Profiles de boards
│   ├── device-profile/  # Configuração de produto
│   ├── ctap2/           # CTAP2 protocolo
│   ├── crypto/          # Operações criptográficas
│   ├── storage/         # Armazenamento de credenciais
│   └── transport/       # Abstração de transportes
├── protocol/
│   ├── ctap2/           # CTAP2 protocolo
│   ├── webauthn/         # WebAuthn protocolo
│   ├── crypto/           # Operações criptográficas (público)
│   └── storage/          # Armazenamento de credenciais (público)
├── simulator/           # Simulador JSON line protocolo
├── examples/            # Exemplos mínimos de uso
├── tests/               # Testes de integração e Python E2E
└── fuzz/                 # Fuzzing para decode_cbor
```
