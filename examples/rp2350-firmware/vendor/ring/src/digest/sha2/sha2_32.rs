// Copyright 2024 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use super::{BlockLen, CHAINING_WORDS};
use crate::{cpu, polyfill::slice::AsChunks};
use core::num::Wrapping;

pub(in super::super) const SHA256_BLOCK_LEN: BlockLen = BlockLen::_512;

pub type State32 = [Wrapping<u32>; CHAINING_WORDS];

pub(crate) fn block_data_order_32(
    state: &mut State32,
    data: AsChunks<u8, { SHA256_BLOCK_LEN.into() }>,
    cpu: cpu::Features,
) {
    // [patch openkey-fido2] Alvo thumbv8m.main-none-eabihf (Cortex-M33,
    // Thumb-2): os ramos FFI para arm/aarch64/x86_64 foram removidos porque
    // as fontes perlasm correspondentes sao excluidas em build.rs (nao
    // montam em Thumb-2) e o alvo nao tem extensao SHA-2 por instrucao.
    // Usa-se a implementacao Rust pura (`fallback`), o MESMO caminho que o
    // ring ja usa para alvos sem asm (ex.: wasm32). Nenhuma primitiva
    // criptografica foi alterada - apenas a selecao de implementacao.
    let _ = cpu; // Unneeded.
    *state = super::fallback::block_data_order(*state, data)
}
