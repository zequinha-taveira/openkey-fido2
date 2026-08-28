//! Geometria pura da região de credenciais na flash QSPI do RP2350.
//!
//! Módulo deliberadamente sem dependências de alvo (`core` apenas) para que
//! os testes de unidade rodem em host via `cargo test -p rp2350-firmware
//! --lib`, mesmo com o binário exigindo cross-compilation para thumbv8m.
//!
//! Consumida por `src/qspi_flash.rs` (driver concreto) e testada aqui.

#![no_std]

/// Tamanho de setor de erase da flash NOR (W25Q/WN25Q e compatíveis).
pub const SECTOR_SIZE: u32 = 4096;

/// Região reservada para credenciais: 128 KiB (32 setores). Folga larga para
/// OATH + serial de Management + blobs futuros; desperdício aceitável até em
/// uma flash de 2 MiB (W25Q16).
pub const REGION_LEN: usize = 128 * 1024;

/// Base XIP da flash no mapa de memória do RP2350.
pub const XIP_BASE: u32 = 0x1000_0000;

/// Calcula `(base_abs, capacity)` da região de credenciais a partir do
/// tamanho total probeado da flash.
///
/// - `capacity` = min(REGION_LEN, metade da flash) alinhado para baixo a setor;
///   nunca menor que 2 setores (mínimo do backend de dois slots).
/// - `base` = fim da flash − capacity (alinhado por construção quando o
///   tamanho total é potência de dois, como toda flash NOR comercial).
///
/// Retorna `None` se a flash for pequena demais para a região mínima.
pub fn region_for(total_flash: u32) -> Option<(u32, usize)> {
    if total_flash < 2 * SECTOR_SIZE {
        return None;
    }
    let half = (total_flash / 2) as usize;
    let cap = REGION_LEN.min(half);
    let cap_aligned = (cap / SECTOR_SIZE as usize) * SECTOR_SIZE as usize;
    if cap_aligned < 2 * SECTOR_SIZE as usize {
        return None;
    }
    let base = total_flash - cap_aligned as u32;
    Some((base, cap_aligned))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_mib_flash_gets_full_region_at_end() {
        // W25Q16 real (2 MiB): base = 0x200000-0x20000, 128 KiB, alinhado 4K.
        let (base, cap) = region_for(2 * 1024 * 1024).unwrap();
        assert_eq!(cap, REGION_LEN);
        assert_eq!(base, 2 * 1024 * 1024u32 - REGION_LEN as u32);
        assert_eq!(base % SECTOR_SIZE, 0);
    }

    #[test]
    fn four_mib_flash_gets_full_region_at_end() {
        let (base, cap) = region_for(4 * 1024 * 1024).unwrap();
        assert_eq!(cap, REGION_LEN);
        assert_eq!(base, 4 * 1024 * 1024u32 - REGION_LEN as u32);
    }

    #[test]
    fn small_flash_shrinks_capacity_to_half() {
        // Flash hipotética de 256 KiB: metade = 128 KiB → região cheia ainda.
        let (base, cap) = region_for(256 * 1024).unwrap();
        assert_eq!(cap, REGION_LEN);
        assert_eq!(base, 128 * 1024);
    }

    #[test]
    fn tiny_flash_floors_capacity_at_two_sectors() {
        // 32 KiB: metade = 16 KiB → capacidade reduzida para 16 KiB (4 setores),
        // ainda >= mínimo de 2 setores do backend.
        let (base, cap) = region_for(32 * 1024).unwrap();
        assert_eq!(cap, 16 * 1024);
        assert_eq!(base, 16 * 1024);
        assert_eq!(base % SECTOR_SIZE, 0);
    }

    #[test]
    fn flash_too_small_returns_none() {
        // 12 KiB: metade = 6 KiB → alinhado para baixo = 1 setor < mínimo de 2.
        assert!(region_for(3 * SECTOR_SIZE).is_none());
        assert!(region_for(SECTOR_SIZE).is_none());
        assert!(region_for(0).is_none());
    }
}
