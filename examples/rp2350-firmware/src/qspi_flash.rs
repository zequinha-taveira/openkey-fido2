//! Driver da flash QSPI física do RP2350 (`FlashDevice` para o storage).
//!
//! Expõe APENAS a região de credenciais (ver `qspi_geometry`) como um
//! dispositivo flash: o [`FlashStorageBackend`](storage::FlashStorageBackend)
//! enxerga offsets locais à região; a base absoluta é adicionada aqui.
//!
//! # Arquitetura de execução (crítico)
//!
//! Erase/program usam funções da Boot ROM via ponteiros resolvidos ANTES da
//! janela. Durante a chamada ROM, o QMI entra em modo direto e **acessos XIP
//! geram bus fault** — inclusive busca de instrução. Por isso o corpo que
//! invoca as funções ROM vive em `.data.ram_func` (copiado para SRAM pelo
//! runtime cortex-m-rt no boot) e recebe TUDO por valor/referência à SRAM —
//! nenhum símbolo, const ou string da flash é referenciado dentro da janela.
//! IRQs mascaradas (PRIMASK) ao redor da chamada.
//!
//! Programação em páginas de 256 B com read-modify-write lendo o conteúdo
//! atual via XIP antes de reprogramar (regra NOR: só 1→0; regravar o mesmo
//! valor é seguro; tail recebe 0xFF). O buffer de staging é campo do struct
//! (&mut self garante exclusão), mantendo Send+Sync sem static global.
//!
//! # Justificativa de `unsafe`
//!
//! AGENTS.md exige registro: os blocos `unsafe` são (1) transmutes dos
//! endereços da tabela ROM para as assinaturas documentadas no datasheet
//! RP2350 §5.5/bootrom, (2) leitura XIP mapeada em 0x10000000 validada contra
//! a capacidade da região, (3) uso do símbolo de linker `__flash_binary_end`.
//! Sem eles não existe escrita de flash; o porte bare-metal foi aprovado
//! explicitamente neste incremento (TODO.md — Suporte Nativo Yubico/Fase E).
//!
//! Nota: este é o único arquivo com `unsafe` em `firmware/*` e `protocol/*`;
//! `vendor/ring` (em `examples/rp2350-firmware/vendor/ring`) é crate externa
//! vendida e contém `unsafe` fora do controle do projeto — ver `README.md`
//! seção Segurança.

use rp2350_firmware::{region_for, SECTOR_SIZE, XIP_BASE};
use core::ptr;
use storage::{FlashDevice, StorageError};

/// Máscara de lookup da tabela ROM para funções ARM secure (espelha
/// `rt_flags::FUNC_ARM_SEC_RISCV` do HAL, que é módulo privado;
/// no alvo bare-metal resolve para FUNC_ARM_SEC = 0x0004).
const ROM_FUNC_ARM_SEC: u32 = 0x0004;

/// Tamanho de página de programação NOR (múltiplo exigido pela ROM).
const PAGE_SIZE: usize = 256;

/// Assinaturas das funções de flash da Boot ROM (todas ARM-S secure).
type ConnectFn = unsafe extern "C" fn();
type ExitXipFn = unsafe extern "C" fn();
type RangeEraseFn = unsafe extern "C" fn(addr: u32, count: usize, block_size: u32, block_cmd: u8);
type RangeProgramFn = unsafe extern "C" fn(addr: u32, data: *const u8, count: usize);
type FlushFn = unsafe extern "C" fn();

/// Ponteiros ROM resolvidos uma vez, FORA da janela XIP-off.
#[derive(Clone, Copy)]
struct FlashPtrs {
    connect_internal_flash: ConnectFn,
    exit_xip: ExitXipFn,
    range_erase: RangeEraseFn,
    range_program: RangeProgramFn,
    flush_cache: FlushFn,
}

fn resolve_ptrs() -> Result<FlashPtrs, StorageError> {
    use rp235x_hal::rom_data;

    // SAFETY (por lookup): transmute do endereço retornado pela tabela ROM
    // para a assinatura documentada no datasheet RP2350 §5.5. Endereço 0
    // (função ausente) é rejeitado antes do transmute.
    macro_rules! lookup {
        ($tag:expr, $ty:ty) => {{
            let addr = rom_data::rom_table_lookup($tag, ROM_FUNC_ARM_SEC);
            if addr == 0 {
                return Err(StorageError::BackendError(
                    "bootrom: função de flash ausente".into(),
                ));
            }
            unsafe { core::mem::transmute::<usize, $ty>(addr) }
        }};
    }

    Ok(FlashPtrs {
        connect_internal_flash: lookup!(*b"IF", ConnectFn),
        exit_xip: lookup!(*b"EX", ExitXipFn),
        range_erase: lookup!(*b"RE", RangeEraseFn),
        range_program: lookup!(*b"RP", RangeProgramFn),
        flush_cache: lookup!(*b"FC", FlushFn),
    })
}

/// Operação a executar dentro da janela XIP-off (apenas escalares + SRAM).
enum WindowOp<'a> {
    /// Erase setorial: `addr` absoluto (XIP), `count` múltiplo de 4 KiB.
    Erase { addr: u32, count: usize },
    /// Programação de UMA página de 256 B a partir de `src` (SRAM).
    ProgramPage { addr: u32, src: &'a [u8; PAGE_SIZE] },
}

/// Corpo executado DENTRO da janela XIP-off.
///
/// Garantias: função inteira em `.data.ram_func` (SRAM); nenhum acesso a
/// símbolo/const da flash; IRQs já mascaradas pelo chamador.
#[link_section = ".data.ram_func"]
unsafe fn window_exec(p: &FlashPtrs, op: &WindowOp<'_>) {
    (p.exit_xip)();
    match op {
        WindowOp::Erase { addr, count } => {
            // Setor-only: block_size=0/block_cmd=0 desativa block erase D8h
            // opcional, mantendo comportamento uniforme entre chips.
            (p.range_erase)(*addr, *count, 0, 0);
        }
        WindowOp::ProgramPage { addr, src } => {
            (p.range_program)(*addr, src.as_ptr(), PAGE_SIZE);
        }
    }
    (p.flush_cache)();
}

/// Mascara IRQs, conecta QMI, executa `op` na janela e restaura PRIMASK.
fn run_windowed(p: &FlashPtrs, op: &WindowOp<'_>) -> Result<(), StorageError> {
    // Conecta QMI aos pads internos (idempotente; padrão pico-sdk antes de
    // qualquer sequência de flash serial). SAFETY: chamada ROM fora da janela.
    unsafe { (p.connect_internal_flash)() };
    // Seção crítica (PRIMASK) — o closure é inlineado no chamador; apenas
    // window_exec (SRAM) roda com IRQs mascaradas.
    cortex_m::interrupt::free(|_| {
        // SAFETY: ver contrato de window_exec — ponteiros ROM resolvidos fora
        // da janela, código em SRAM (.data.ram_func), IRQs mascaradas.
        unsafe { window_exec(p, op) };
    });
    Ok(())
}

/// Driver concreto da flash QSPI interna, restrito à região de credenciais.
pub struct QspiFlashDevice {
    region_base: u32,
    capacity: usize,
    page_buf: [u8; PAGE_SIZE],
}

impl QspiFlashDevice {
    /// Probeia o tamanho real da flash (Boot ROM FLASH_DEVINFO) e abre a
    /// região de credenciais no fim da flash.
    pub fn open() -> Result<Self, StorageError> {
        use rp235x_hal::rom_data::sys_info_api::{flash_dev_info, FlashDevInfoSize};

        let info = flash_dev_info()
            .map_err(|_| StorageError::BackendError("ROM sysinfo indisponível".into()))?
            .ok_or_else(|| StorageError::BackendError("ROM sem FLASH_DEVINFO".into()))?;

        // Tamanho real do chip em CS0, reportado pela Boot ROM — resolve a
        // discrepância W25Q16 (2 MiB) × wiki (4 MiB) sem chute em compile-time.
        let total: u32 = match info.cs0_size() {
            FlashDevInfoSize::None => 0,
            FlashDevInfoSize::K8 => 8 * 1024,
            FlashDevInfoSize::K16 => 16 * 1024,
            FlashDevInfoSize::K32 => 32 * 1024,
            FlashDevInfoSize::K64 => 64 * 1024,
            FlashDevInfoSize::K128 => 128 * 1024,
            FlashDevInfoSize::K256 => 256 * 1024,
            FlashDevInfoSize::K512 => 512 * 1024,
            FlashDevInfoSize::M1 => 1024 * 1024,
            FlashDevInfoSize::M2 => 2 * 1024 * 1024,
            FlashDevInfoSize::M4 => 4 * 1024 * 1024,
            FlashDevInfoSize::M8 => 8 * 1024 * 1024,
            FlashDevInfoSize::M16 => 16 * 1024 * 1024,
            FlashDevInfoSize::Unknown => 0,
        };
        if total == 0 {
            return Err(StorageError::BackendError(
                "tamanho de flash desconhecido (FLASH_DEVINFO)".into(),
            ));
        }

        let (base, capacity) = region_for(total).ok_or_else(|| {
            StorageError::BackendError("flash pequena demais para a região".into())
        })?;

        // Sanidade: a região nunca pode começar antes do fim do firmware.
        extern "C" {
            static __flash_binary_end: u8;
        }
        // SAFETY: símbolo provido pelo link.x/memory.x; apenas lemos endereço.
        let fw_end = ptr::addr_of!(__flash_binary_end) as u32;
        if base <= fw_end.wrapping_sub(XIP_BASE) {
            return Err(StorageError::BackendError(
                "região de credenciais sobrepõe o firmware".into(),
            ));
        }

        Ok(Self {
            region_base: base,
            capacity,
            page_buf: [0xFF; PAGE_SIZE],
        })
    }

    /// Endereço absoluto (XIP) do offset local `offset` (valida início).
    fn xip_addr(&self, offset: usize) -> Result<u32, StorageError> {
        if offset >= self.capacity {
            return Err(StorageError::BackendError(
                "flash offset fora da região".into(),
            ));
        }
        Ok(XIP_BASE + self.region_base + offset as u32)
    }
}

impl FlashDevice for QspiFlashDevice {
    fn capacity(&self) -> usize {
        self.capacity
    }

    fn sector_size(&self) -> usize {
        SECTOR_SIZE as usize
    }

    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), StorageError> {
        if out.len() > self.capacity - offset.min(self.capacity) || offset >= self.capacity {
            return Err(StorageError::BackendError(
                "flash read out of bounds".into(),
            ));
        }
        let addr = self.xip_addr(offset)?;
        // SAFETY: intervalo [addr, addr+len) integralmente dentro da região
        // validada; XIP legível fora de janelas de erase/program.
        let src = addr as *const u8;
        for (i, b) in out.iter_mut().enumerate() {
            *b = unsafe { ptr::read_volatile(src.add(i)) };
        }
        Ok(())
    }

    fn erase_sector(&mut self, sector: usize) -> Result<(), StorageError> {
        let start = sector
            .checked_mul(SECTOR_SIZE as usize)
            .ok_or_else(|| StorageError::BackendError("flash sector overflow".into()))?;
        if start + SECTOR_SIZE as usize > self.capacity {
            return Err(StorageError::BackendError(
                "flash sector out of bounds".into(),
            ));
        }
        let addr = self.xip_addr(start)?;
        let p = resolve_ptrs()?;
        run_windowed(
            &p,
            &WindowOp::Erase {
                addr,
                count: SECTOR_SIZE as usize,
            },
        )
    }

    fn program(&mut self, offset: usize, data: &[u8]) -> Result<(), StorageError> {
        if offset.saturating_add(data.len()) > self.capacity {
            return Err(StorageError::BackendError(
                "flash program out of bounds".into(),
            ));
        }
        if data.is_empty() {
            return Ok(());
        }

        // Read-modify-write por página de 256 B: preserva vizinhos (NOR 1→0),
        // tail além de `data` recebe 0xFF. Página atual lida via XIP (fora da
        // janela) para o buffer de staging em SRAM; só a gravação é janelada.
        let mut page_start = offset - (offset % PAGE_SIZE);
        let mut written = 0usize;
        while written < data.len() {
            let page_end = page_start + PAGE_SIZE;
            let take = core::cmp::min(page_end - (offset + written), data.len() - written);

            let addr = self.xip_addr(page_start)?;
            // SAFETY: página integralmente dentro da região validada.
            let src = addr as *const u8;
            for i in 0..PAGE_SIZE {
                self.page_buf[i] = unsafe { ptr::read_volatile(src.add(i)) };
            }
            let dst_off = (offset + written) - page_start;
            self.page_buf[dst_off..dst_off + take].copy_from_slice(&data[written..written + take]);

            let p = resolve_ptrs()?;
            run_windowed(
                &p,
                &WindowOp::ProgramPage {
                    addr,
                    src: &self.page_buf,
                },
            )?;

            page_start += PAGE_SIZE;
            written += take;
        }
        Ok(())
    }
}
