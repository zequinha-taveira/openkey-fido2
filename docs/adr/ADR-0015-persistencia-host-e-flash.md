# ADR-0015: Persistência Crash-Safe no Host e Bloqueador de Flash

Status: accepted
Data: 2026-08-14

## Contexto

`FileStorageBackend` era implementado com `fs::write`, que pode deixar um
snapshot JSON parcialmente escrito durante uma queda. O repositório não possui
uma HAL de flash que defina erase, program, alinhamento, limites de setor,
wear leveling e comportamento de queda de energia.

## Decisão

No host, cada snapshot é escrito primeiro em um journal temporário e sincronizado
com `sync_all`. O snapshot também é escrito em um arquivo temporário
sincronizado e então substitui o arquivo principal. Na inicialização, um journal
presente tem prioridade, permitindo recuperar o último snapshot completo mesmo
se a substituição do arquivo principal foi interrompida.

`FlashStorageBackend` permanece um stub. Não será implementado um backend flash
genérico sem uma API concreta de hardware e testes de power-loss para a board.

## Consequências

- Quedas do processo no host não devem deixar o JSON sem um snapshot completo.
- A substituição em duas etapas no Windows continua dependente do journal para
  recuperação durante a pequena janela entre remoção e rename.
- Isso não é evidência de persistência ou atomicidade em flash real; validação
  física exige uma board e uma HAL específica.
