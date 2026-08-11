# openkey-fido2 — Guia do Agente

Este arquivo define como agentes de desenvolvimento devem trabalhar neste repositório.
Ele é a **fonte de verdade para o fluxo de trabalho**, não instruções passageiras.

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
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — padrões de código, testes e processo de contribuição

Não repita instruções de conversa em código ou docs. Referencie estes arquivos.

### Documentação como Roteador de Contexto (ADR-0005)

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

## Mapeamento de Crates

| Crate | Caminho | Responsabilidade |
|-------|---------|------------------|
| `authenticator` | `firmware/authenticator/` | Coordenação de todas as camadas. `EmbeddedAuthenticator` é a API final. |
| `webauthn` | `protocol/webauthn/` | Validação de requests WebAuthn, delega ao CTAP2. |
| `ctap2` | `protocol/ctap2/` | Implementação do estado CTAP2 (MakeCredential, GetAssertion, GetInfo, etc.). |
| `crypto` | `protocol/crypto/` | Operações criptográficas (Ed25519, HMAC-SHA256, ChaCha20-Poly1305, SHA-256). |
| `storage` | `firmware/storage/` | Armazenamento de credenciais com encryption at rest. |
| `board-generic` | `firmware/board-generic/` | HAL e profiles pré-definidos de boards (NRF52840, STM32L4, RP2350, etc.). |
| `device-profile` | `firmware/device-profile/` | Configuração de produto e capability discovery. |
| `fido2-simulator` | `simulator/` | Binário host que expõe o firmware via JSON line protocol para testes. |
| `basic-example` | `examples/basic/` | Exemplo mínimo de uso do `EmbeddedAuthenticator`. |
| `ccid-example` | `examples/ccid/` | Exemplo com transport CCID. |
| `test-suite` | `tests/` | Testes de integração Rust. |

### Dependências entre Crates

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

**Regra:** setas apontam de quem depende para quem é dependido. Nunca crie dependências circulares.

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

---

## Regras de Segurança para Código Criptográfico

1. **Nunca** introduza `unsafe` sem justificativa registrada em ADR
2. **Nunca** faça log de chaves privadas, seeds ou material sensível
3. Use `ring` para operações criptográficas — não implemente primitivas próprias
4. Nonces devem ser gerados via `SystemRandom` — nunca use RNG previsível
5. Chaves privadas em memória devem ser zeradas após uso quando possível
6. Mudanças em `crypto/` exigem revisão cuidadosa e testes de regressão

---

## Padrões de Erro

- Use `thiserror` para erros de crate (ex.: `WebAuthnError`)
- Mapeie erros internos para `Ctap2Error` nas fronteiras do protocolo
- Erros de validação de input → `Ctap2Error::InvalidParameter`
- Erros de estado → `Ctap2Error::InvalidState`
- Recurso não encontrado → `Ctap2Error::NoCredentials` / `Ctap2Error::InvalidKey`

---

## Como Criar um ADR

1. Copie `docs/adr/ADR-0000-template.md`
2. Renomeie para `ADR-NNNN-titulo-curto.md`
3. Preencha: Contexto, Decisão, Consequências
4. Referencie no commit message: `adr: ADR-0004 — ...`
5. Não edite ADRs antigos — crie novos para registrar mudanças de direção
