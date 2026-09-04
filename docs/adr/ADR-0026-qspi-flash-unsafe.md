# ADR-0026: Blocos `unsafe` no Driver QSPI Flash do RP2350

Status: accepted
Data: 2026-09-03

## Contexto

O `AGENTS.md` proíbe `unsafe` sem justificativa registrada em ADR.
O driver físico da flash QSPI (`examples/rp2350-firmware/src/qspi_flash.rs`,
`QspiFlashDevice`) é o único arquivo com `unsafe` em `firmware/*` e
`protocol/*` (`vendor/ring` é crate externa vendida, fora do controle do
projeto). A justificativa vivia apenas como comentário inline no módulo
(`TODO.md` — Persistência Física na Flash QSPI, item "ADR de unsafe").

Restrições técnicas:

- Escrita de flash no RP2350 exige as funções da Boot ROM (`IF`, `EX`, `RE`,
  `RP`, `FC`, datasheet §5.5), resolvidas via tabela ROM em runtime — não há
  símbolo linkável nem API segura do HAL que cubra erase/program janelado.
- Durante a chamada ROM o QMI entra em modo direto e **qualquer acesso XIP
  (inclusive busca de instrução) gera bus fault**. O corpo da janela precisa
  executar de SRAM (`.data.ram_func`) sem referenciar nada da flash, com IRQs
  mascaradas (PRIMASK).
- Semântica NOR: só transições 1→0, programação em páginas de 256 B, erase em
  setores de 4 KiB.

Alternativas consideradas:

- API de flash do HAL (`rp235x_hal`): não cobre o sequenciamento
  connect/exit-XIP/flush com o layout de seção exigido; rejeitada.
- Double-buffer em segundo core ou DMA: complexidade maior sem ganho de
  segurança; rejeitada.
- Chamada ROM direta com janela em SRAM e contratos `SAFETY` por call site:
  adotada — é o padrão do `pico-sdk` (`flash_range_erase/program`).

## Decisão

Os 6 usos de `unsafe` no módulo são aceitos, cada um com contrato explícito
no call site:

1. `resolve_ptrs` — `transmute` do endereço da tabela ROM para a assinatura
   documentada no datasheet §5.5. Endereço 0 (função ausente) é rejeitado
   antes do transmute.
2. `run_windowed` — chamada a `connect_internal_flash` **fora** da janela
   (QMI ainda em modo XIP, idempotente).
3. `window_exec` (`#[link_section = ".data.ram_func"]`) — único código que
   roda com XIP desligado; recebe apenas escalares e referências à SRAM
   (`FlashPtrs` por valor, `WindowOp` com `src` em SRAM); IRQs mascaradas pelo
   chamador via `cortex_m::interrupt::free`.
4. `QspiFlashDevice::open` — leitura do endereço do símbolo de linker
   `__flash_binary_end` (provido por `memory.x`/`link.x`) para sanidade
   região-vs-firmware.
5. `read` / `program` — `ptr::read_volatile` do XIP **fora** de janelas, com
   intervalo integralmente dentro da região validada (`xip_addr` + checks de
   bounds com `saturating_add`/`checked_mul`, sem truncamento em 32 bits).
6. `program` — `src.as_ptr()` do buffer de staging (`page_buf`, campo do
   struct, vivo durante a chamada) passado à `range_program`.

Regras permanentes: nenhum símbolo, `const` ou string da flash dentro de
`window_exec` (o compilador pode inlinear referências — todo input entra por
parâmetro); `&mut self` como única exclusão (sem `static` global, mantém
`Send`+`Sync`); bounds validados antes de qualquer cast para `u32`.

## Consequências

- O único `unsafe` próprio do projeto passa a ter justificativa rastreável;
  a referência canônica deixa de ser o comentário inline.
- Positivo: persistência física isolada à região de credenciais
  (`region_for` testável em host, `src/lib.rs`), sem global mutável.
- Negativo: UB silencioso se o contrato da janela for violado em refatoração
  futura (ex.: referenciar uma `const` da flash em `window_exec`) — qualquer
  toque no módulo exige re-revisão dos 6 contratos.
- Não alegado: atomicidade contra queda de energia da flash real nem
  validação física — seguem cobertos pela ADR-0016 e pelo runbook
  (`docs/hardware/rp2350-zero-validation.md`, seção 7, 🚧).

Referências: ADR-0011 (targets bare-metal), ADR-0016 (contrato
`FlashDevice` e gates de release), `examples/rp2350-firmware/src/qspi_flash.rs`,
`examples/rp2350-firmware/src/lib.rs` (`region_for`).
