# ADR-0007: Arquitetura de Execução de Subagents

Status: accepted
Data: 2026-08-09

## Contexto

O projeto openkey-fido2 utiliza subagents de IA para granularizar e executar
tarefas do `TODO.md`. Atualmente não existe um documento que descreva como
orquestrar esses agentes — quando usar cada tipo, como carregar contexto,
quais padrões de paralelismo aplicar, e como os outputs são consumidos.

O ADR-0005 definiu princípios de isolamento de contexto, mas não detalhou a
execução: tipos de agentes, critério de escolha, formato de prompts, ou
tratamento de falhas.

## Decisão

Adotar uma arquitetura de subagents com dois tipos primários, estratégia de
contexto progressivo, e contratos de saída explícitos.

### 1. Tipos de Agentes Disponíveis

#### 1.1 `explore` — Exploração de Codebase

**Propósito:** Buscar arquivos, mapear estrutura, localizar definições,
entender dependências sem modificar código.

**Quando usar:**
- Localizar onde uma função/trait/struct é definida
- Mapear dependências entre crates
- Entender como um módulo específico funciona
- Encontrar testes relacionados a uma feature

**Contexto fornecido:**
- Paths relevantes do `AGENTS.md` (Mapeamento de Crates)
- A pergunta específica (ex: "Onde X é implementado?")

**NÃO fornecer:**
- TODO.md completo
- ADRs inteiros (referencie paths)

**Critério de saída:** Paths com linha (`arquivo:linha`) + resumo conciso

#### 1.2 `general` — Execução Multietapa

**Propósito:** Implementar features, refactoring, escrever testes — tarefas
que exigem múltiplas etapas com dependências sequenciais.

**Quando usar:**
- Implementar um incremento do TODO.md
- Adicionar novos módulos ou funções
- Escrever testes unitários/integração
- Refatorar código existente

**Contexto fornecido:**
- Seção relevante do TODO.md (não o arquivo completo)
- Paths dos arquivos a modificar
- Convenções do projeto (da AGENTS.md: padrões de erro, regras de segurança)
- Dependências do incremento (se houver)

**Critério de saída:** Código implementado + testes passando + resumo do que foi feito

### 2. Estratégia de Contexto Progressivo

O agente principal carrega contexto em camadas:

```
Camada 1: AGENTS.md          ← sempre (guia de workflow)
Camada 2: Seção TODO.md       ← apenas itens relevantes à tarefa
Camada 3: Código específico   ← paths identificados via explore ou TODO.md
Camada 4: ADRs relevantes     ← quando decisão de design afeta a implementação
```

Regra: nunca carregue uma camada se a anterior já contém o necessário.

### 3. Padrões de Orquestração

#### 3.1 Sequencial (Pipeline)

Usado quando cada etapa depende da saída da anterior.

```
tarefa A → output A → tarefa B (usa output A) → output B → ...
```

Exemplo: explorar código → implementar → escrever testes → validar

#### 3.2 Paralelo (Fan-out)

Usado quando tarefas não têm dependências entre si.

```
          ┌─ subagent A (crate X) ─┐
tarefa ── ├─ subagent B (crate Y) ─┤─► merge outputs
          └─ subagent C (tests) ───┘
```

Exemplo: implementar features independentes em crates diferentes.

#### 3.3 Plan-then-Execute

Usado para tarefas complexas com múltiplos incrementos.

```
1. Planejar: listar etapas com dependências
2. Validar: apresentar plano ao usuário
3. Executar: subagents por etapa (sequencial ou paralelo)
4. Verificar: validar outputs de cada etapa
```

### 4. Contrato de Prompt para Subagents

Todo subagent deve receber:

```
1. TASK DESCRIPTION    — o que fazer (objetivo claro)
2. MINIMUM CONTEXT     — arquivos/paths/regras estritamente necessários
3. OUTPUT CRITERIA     — formato esperado do retorno
4. EXPLICIT RESTRICTIONS — o que NÃO fazer (ex: "não commitar", "não modificar X")
```

Exemplo de prompt bem estruturado:

```
TASK: Implementar `getPINRetries` no módulo client_pin

CONTEXT:
- `protocol/ctap2/src/client_pin.rs` — trait ClientPin já definida
- `firmware/storage/src/storage.rs` — StorageEngine com método get/set
- Critério de aceitação: teste `test_get_pin_retries` deve passar

OUTPUT: Código implementado + confirmação de `cargo test` passando

RESTRICTIONS:
- Não modificar o trait ClientPIN (apenas implementar)
- Não commitar mudanças
- Não alterar arquivos fora de `protocol/ctap2/src/client_pin.rs`
```

### 5. Tratamento de Saída

#### 5.1 Output do tipo `explore`

Formato esperado:
```
Resumo: [1-3 frases]
Achados:
- path/arquivo.rs:42 — definição de X
- path/outro.rs:108 — uso de Y em contexto Z
```

#### 5.2 Output do tipo `general`

Formato esperado:
```
Resumo: [o que foi feito]
Arquivos modificados:
- path/arquivo.rs — [mudança específica]
Testes: [comando executado] [resultado]
Observações: [resalvas ou decisões tomadas]
```

### 6. Tratamento de Falhas

Quando um subagent falha:

1. **Identificar a causa** — contexto insuficiente? tarefa ambígua? dependência faltando?
2. **Re-prompt com correção** — ajustar contexto, dividir tarefa, ou remover dependência
3. **Escalar para o usuário** — quando 2 re-prompts falham, apresentar diagnóstico

### 7. Relação com Documentação Existente

| Documento | Papel |
|-----------|-------|
| `AGENTS.md` | Roteador de contexto inicial |
| `TODO.md` | Fonte de tarefas com dependências |
| `ADR-0005` | Princípios de isolamento de contexto |
| `ADR-0007` (este) | Arquitetura de execução de subagents |
| `docs/adr/` | Decisões de design que afetam implementação |

## Consequências

Positivas:
- Subagents executam com contexto mínimo → menos tokens, menos erros
- Contratos explícitos facilitam validação de outputs
- Padrões de orquestração documentados permitem replicabilidade
- Separação entre explore e general evita tool misuse

Negativas:
- Requer disciplina para seguir o contrato de prompt
- Overhead de planejamento para tarefas simples (use julgamento)
- Estado em arquivos pode ficar desatualizado (mitigação: TODO.md como fonte de verdade)

## Referências

- `AGENTS.md:49-70` — Documentação como Roteador de Contexto (ADR-0005)
- `TODO.md` — Incrementos granulares com dependências
- `docs/adr/ADR-0005-isolamento-contexto-agentes.md` — Princípios de isolamento
