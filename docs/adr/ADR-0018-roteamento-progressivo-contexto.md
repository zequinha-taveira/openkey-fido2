# ADR-0018: Roteamento Progressivo de Contexto por Tarefa

Status: accepted
Data: 2026-08-16

## Contexto

O ADR-0005 definiu isolamento de contexto e estado compartilhado controlado. O
ADR-0007 detalhou tipos de subagent, contratos de prompt e uma estratégia de
contexto progressivo, mas sua ordem de camadas não indicava explicitamente a
especificação relevante nem a skill aplicável à tarefa.

Sem uma ordem explícita, agentes podem carregar o repositório inteiro, ler o
código antes dos requisitos normativos ou usar uma skill desatualizada como
fonte de verdade. Isso aumenta o custo de contexto e o risco de decisões
incompatíveis com o protocolo ou com as decisões arquiteturais existentes.

## Decisão

Adotar a seguinte rota canônica para cada tarefa:

```text
Issue → AGENTS.md → especificação relevante → ADR relevante →
arquivos fonte relevantes → skill relevante
```

As etapas têm os seguintes contratos:

1. **Issue**: delimita objetivo, comportamento esperado e critério de
   aceitação. Pode ser um relato do usuário, uma issue do GitHub ou um item do
   `TODO.md`.
2. **`AGENTS.md`**: fornece as regras obrigatórias, o mapa de crates e o
   workflow. O `TODO.md` é consultado somente na seção relacionada ao Issue.
3. **Especificação relevante**: fornece os requisitos normativos aplicáveis,
   como seções de CTAP2, WebAuthn ou um requisito de produto. Somente as seções
   necessárias são carregadas.
4. **ADR relevante**: fornece decisões de arquitetura e restrições de design.
   ADRs aceitos não são editados para mudar decisões; uma nova direção exige
   um novo ADR.
5. **Arquivos fonte relevantes**: são localizados por busca e lidos somente
   depois que os requisitos e as decisões aplicáveis foram identificados.
6. **Skill relevante**: é carregada quando o gatilho da tarefa corresponde à
   skill. Ela fornece contexto operacional específico, mas não substitui a
   especificação, os ADRs ou o código.

As regras complementares são:

- `AGENTS.md` é a fonte operacional canônica da rota.
- `development.md` referencia a rota e não duplica seu conteúdo.
- Uma etapa sem aplicação deve ser marcada como não aplicável, com o motivo,
  em vez de carregar contexto irrelevante.
- Subagents recebem apenas task description, minimum context, output criteria e
  explicit restrictions, com paths e seções específicas.
- Estado compartilhado permanece em arquivos do repositório e em mensagens
  estruturadas de saída; não há estado implícito entre subagents.

Esta decisão refina o isolamento definido no ADR-0005 e substitui somente a
ordem de aquisição de contexto descrita no ADR-0007. Os tipos de agentes, os
contratos de saída e os padrões de orquestração do ADR-0007 permanecem válidos.

## Consequências

Positivas:

- Agentes carregam requisitos e decisões antes de interpretar o código.
- O contexto permanece delimitado ao Issue e às suas dependências reais.
- A escolha de skills fica explícita e evita usar contexto operacional não
  relacionado.
- A documentação tem uma fonte única para a ordem de carregamento.

Negativas:

- O agente precisa classificar a tarefa e identificar a especificação, ADR e
  skill aplicáveis.
- Skills e referências documentais precisam ser mantidas para não introduzir
  contexto desatualizado.
- Tarefas mal especificadas podem exigir uma etapa adicional de esclarecimento
  antes da leitura do código.
