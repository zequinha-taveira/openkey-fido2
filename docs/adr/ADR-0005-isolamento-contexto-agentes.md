# ADR-0005: Isolamento de Contexto entre Agentes e Estado Compartilhado Controlado

Status: accepted
Data: 2026-08-05

## Contexto

Sistemas multiagentes exigem gestão deliberada de contexto para evitar acoplamento
e redundância. Quando múltiplos agentes carregam o mesmo conjunto completo de
informações, surgem problemas:

- **Desperdício de tokens/context window** — cada agente paga o custo de carregar
  informações irrelevantes para sua tarefa
- **Risco de inconsistência** — agentes com visões desatualizadas do estado podem
  tomar decisões conflitantes
- **Acoplamento implícito** — agentes que compartilham muito contexto tornam-se
  difíceis de modificar ou substituir independentemente

No projeto openkey-fido2, subagents são usados para tarefas específicas
(granularizar TODO.md, implementar features, escrever testes). Cada subagent
deve receber apenas o contexto estritamente necessário para sua tarefa.

## Decisão

Adotar dois princípios complementares:

### 1. Isolamento de contexto por subagent

Cada subagent recebe:
- **Descrição da tarefa** — objetivo claro e delimitado
- **Contexto mínimo** — apenas arquivos/regras diretamente relevantes
- **Critérios de saída** — o que retornar ao agente principal
- **Restrições explícitas** — o que NÃO deve fazer (ex: "não commitar")

O agente principal nunca despeja TODO.md, AGENTS.md, e TODO.md completos para
subagents quando apenas uma seção é relevante.

### 2. Estado compartilhado controlado

O estado compartilhado entre agentes existe apenas em:
- **Arquivos do repositório** — `TODO.md`, `AGENTS.md`, ADRs como fonte de verdade
- **Mensagens estruturadas** — output de subagents como contratos definidos

Não existe estado compartilhado em memória entre subagents. Toda comunicação
é via sistema de arquivos ou mensagens de retorno.

### 3. Granularidade de incrementos

Cada incremento no `TODO.md` deve ser:
- **Atômico** — implementável em 1-3 horas
- **Verificável** — com critério de aceitação objetivo
- **Independente** — com dependências explicitamente marcadas (`⬅️ depende de X`)
- **Específico** — indicando o crate/módulo afetado

## Consequências

Positivas:
- Subagents consomem menos tokens por tarefa
- Facilita paralelismo — agentes sem dependências podem rodar concorrentemente
- Reduz risco de conflitos de estado
- Incrementos granulares permitem revisão mais rápida
- Preserva consistência entre repositórios sem duplicar documentação — agentes
  leem AGENTS.md como roteador de contexto e carregam apenas o necessário

Negativas:
- Requer mais disciplina ao planejar prompts de subagents
- Estado em arquivos pode ficar desatualizado se não houver revisão
- Dependências entre itens exigem ordenamento (quick wins primeiro)
