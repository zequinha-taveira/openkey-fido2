# ADR-0016: Flash Simulada e Gates de Release

Status: accepted
Data: 2026-08-14

## Contexto

O projeto não possui uma HAL comum de flash para RP2350, nRF52840 e STM32L4.
O backend anterior era apenas um stub, enquanto o host precisava de uma forma
determinística de testar erase, program e recuperação após queda de energia.
Também não era seguro que o workflow publicasse artefatos sem assinatura,
validação física e teste oficial de conformidade.

## Decisão

`FlashDevice` define a fronteira por board: leitura, erase de setor e program
com a regra NOR de transição somente de 1 para 0. `SimulatedFlash` implementa
essa fronteira no host e pode interromper uma operação de program para testes.
`FlashStorageBackend` grava snapshots JSON em dois setores alternados, com
magic, geração, tamanho e checksum. Um snapshot incompleto ou adulterado é
ignorado e o último slot válido é recuperado.

Isso valida o algoritmo e o contrato, não uma memória física específica. Cada
HAL de board deve fornecer seu próprio adaptador, alinhamento, tamanho de página,
erase e garantia de energia antes de qualquer alegação de atomicidade física.

O workflow de release exige `COSIGN_PRIVATE_KEY`, `COSIGN_PASSWORD` e
`COSIGN_PUBLIC_KEY`, assina e verifica cada artefato, e só permite criar uma
release manualmente quando os gates de hardware e do FIDO Conformance Tool
forem explicitamente marcados. Tags sozinhas não publicam releases.

## Consequências

- Há testes reproduzíveis de power-loss sem fingir validação em hardware.
- A publicação unsigned é bloqueada quando secrets estão ausentes.
- A validação física e o Conformance Tool continuam pré-requisitos externos.
