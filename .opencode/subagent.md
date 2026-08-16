# openkey-fido2 - Subagent Configuration

## Workspace Overview

This workspace implements a FIDO2 authenticator for embedded devices using Rust.
It is organized as a Cargo workspace with separate crates for each protocol layer.

## Project Name

**openkey-fido2** - FIDO2 Embedded Authenticator

## Documentation Hierarchy

| File | Purpose |
|------|---------|
| `README.md` | Project overview and how to build |
| `AGENTS.md` | Agent workflow guide (mandatory reading) |
| `TODO.md` | Increment tracking and future work |
| `CONTRIBUTING.md` | Code standards and contribution guide |
| `docs/adr/` | Architecture Decision Records (see ADR list below) |
| `docs/architecture.md` | Module contracts and request flows |
| `.opencode/subagent.md` | This file (subagent config) |
| `.opencode/skills/` | Task-specific operational context |

## Workspace Structure

```
openkey-fido2/
├── Cargo.toml                    # Workspace root
├── AGENTS.md                     # Agent workflow guide
├── TODO.md                       # Increment tracker
├── CONTRIBUTING.md               # Contribution guide
├── justfile                      # Unified commands (requires `just`)
├── docs/
│   ├── adr/                      # Architecture Decision Records
│   │   ├── ADR-0000-template.md
│   │   └── ADR-*.md                # Decisions affecting implementation
│   └── architecture.md           # Module contracts & flows
├── firmware/
│   ├── authenticator/            # Core authenticator logic (API final)
│   ├── board-generic/            # Hardware abstraction layer
│   ├── device-profile/           # Device profile & capability discovery
│   └── storage/                  # Persistent credential storage
├── protocol/
│   ├── ctap2/                    # CTAP2 protocol implementation
│   ├── webauthn/                 # WebAuthn protocol implementation
│   └── crypto/                   # Cryptographic operations (ring-based)
├── examples/
│   ├── basic/                    # Basic authenticator example
│   └── ccid/                     # CCID interface example
├── simulator/                    # JSON line protocol simulator
├── tests/
│   ├── src/lib.rs                # Rust integration tests
│   └── python/                   # Python end-to-end tests
└── tools/                        # Development tools
```

## Crate Dependencies

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

**Rule:** Arrows point from dependent to dependency. Never create circular dependencies.

## Key Design Decisions

1. **ring for crypto** (ADR-0001): All cryptography via `ring` crate, never custom primitives
2. **JSON line protocol** (ADR-0002): Simulator exposes firmware via stdin/stdout JSON
3. **Layered architecture** (ADR-0003): Unidirectional dependencies, each layer testable in isolation
4. **std/no_std stratification** (ADR-0004): Core uses `alloc` only, simulator/tests use `std`
5. **context isolation** (ADR-0005): Subagents receive only task-relevant context, no shared memory state
6. **progressive context routing** (ADR-0018): Load issue, specification, ADR, source, and skill context in order

## Context Isolation (ADR-0005)

> Princípio: cada subagent recebe apenas o contexto estritamente necessário
> para sua tarefa. Estado compartilhado existe apenas em arquivos do
> repositório (TODO.md, AGENTS.md, ADRs).

### Ao criar um subagent, fornecer:

| Campo | Descrição |
|-------|-----------|
| **Task description** | Objetivo claro e delimitado |
| **Minimum context** | Apenas arquivos/regras diretamente relevantes |
| **Output criteria** | O que retornar ao agente principal |
| **Explicit restrictions** | O que NÃO fazer (ex: "não commitar") |

### Não fazer:

- Despejar TODO.md, AGENTS.md completos quando apenas uma seção é relevante
- Incluir dependências de crate que o subagent não vai tocar
- Compartilhar estado em memória entre subagents

### Estado compartilhado permitido:

- Arquivos do repositório (`TODO.md`, `AGENTS.md`, ADRs) como fonte de verdade
- Mensagens estruturadas de retorno como contratos entre agentes

## Context Routing (ADR-0018)

Follow the canonical route in `AGENTS.md`:

```text
Issue → AGENTS.md → relevant specification → relevant ADR →
relevant source files → relevant skill
```

Load only the sections and files relevant to the current task. This file
defines subagent configuration and does not replace the canonical workflow.

## Subagent Responsibilities

- Implement CTAP2 protocol state machine
- Implement WebAuthn credential management
- Implement cryptographic key derivation and signing
- Implement persistent credential storage with encryption
- Provide board-specific HAL implementations
- Write integration tests for protocol layers
- Maintain architecture documentation in sync with code

### Specialized Agents

- `real-code-quality` — audit-only review of bugs, security risks, regressions,
  and missing tests; it does not modify files.
- `defect-cycle` (ADR-0019) — execute the complete detection → reproduction →
  correction → validation cycle for a confirmed defect or conformance failure.

## Workflow Rules

1. Read `AGENTS.md` before starting any non-trivial task
2. Identify the Issue and consult only the related `TODO.md` section
3. Load relevant specification, ADR, source files, and skill in the `AGENTS.md` order
4. Plan with small, verifiable steps before implementing
5. Update `TODO.md` when completing increments
6. Create ADRs for significant design decisions
7. Run `just ci` (or equivalent) before considering work done
8. Apply context isolation per ADR-0005 when delegating to subagents
