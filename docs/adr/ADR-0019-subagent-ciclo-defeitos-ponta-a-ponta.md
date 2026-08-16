# ADR-0019: Subagent de Ciclo de Defeitos Ponta a Ponta

Status: accepted
Data: 2026-08-16

## Contexto

O ADR-0007 definiu os subagents `explore` e `general`, mas não separou a
auditoria de qualidade da execução completa de uma correção. O agente
`real-code-quality` é deliberadamente somente leitura e não pode corrigir um
defeito. Um agente `general` pode implementar mudanças, mas não tem um
contrato específico que exija evidência de detecção, reprodução antes da
correção e validação depois dela.

Defeitos de protocolo, segurança e regressões precisam de uma trilha de
evidência ponta a ponta. Sem essa trilha, um teste amplo que passa pode ocultar
uma falha não reproduzida ou uma correção especulativa.

## Decisão

Adicionar o subagent especializado `defect-cycle` em
`.opencode/agents/defect-cycle.md` para executar o ciclo:

```text
detecção → reprodução → correção → validação
```

O agente segue o roteamento progressivo do ADR-0018 e tem as seguintes regras:

1. **Detecção**: delimitar comportamento esperado e observado, localizar a
   fronteira afetada e reunir evidência da causa provável antes de editar.
2. **Reprodução**: executar o reproducer mais estreito e determinístico,
   registrando comando, entrada, resultado esperado e resultado observado.
3. **Correção**: aplicar a menor mudança que resolve a causa confirmada e
   adicionar ou preservar um teste de regressão.
4. **Validação**: repetir o reproducer, executar os checks relevantes, revisar
   o diff e distinguir falhas da mudança de limitações do ambiente.

O agente pode editar arquivos para corrigir o defeito, mas comandos shell
exigem aprovação. Ele não pode fazer commit, push, reset, checkout ou descartar
mudanças. Se a falha não for reproduzida, o agente deve retornar
`not_reproduced` ou `blocked` sem inventar uma correção.

O output obrigatório informa um dos status `fixed`, `not_reproduced`, `blocked`,
`no_fix_needed` ou `partially_fixed`, seguido de seções de Issue, Detection,
Reproduction, Correction, Validation e Residual risks. O status `fixed` exige
evidência de falha antes da correção e sucesso depois dela.

O `real-code-quality` permanece como agente de auditoria sem edição. O
`defect-cycle` é usado quando a tarefa exige modificar e validar o código.

## Consequências

Positivas:

- Reduz correções especulativas ao exigir reprodução antes da edição.
- Produz uma cadeia verificável entre defeito, teste, mudança e validação.
- Preserva a separação entre auditoria somente leitura e implementação.
- Mantém alterações reversíveis no worktree ao proibir operações destrutivas de
  Git.

Negativas:

- O ciclo exige mais tempo do que uma correção direta sem reproducer.
- Falhas dependentes de hardware ou ambiente podem terminar como `blocked`.
- O agente precisa manter o relatório preciso quando checks independentes
  falham ou quando o worktree já está sujo.
