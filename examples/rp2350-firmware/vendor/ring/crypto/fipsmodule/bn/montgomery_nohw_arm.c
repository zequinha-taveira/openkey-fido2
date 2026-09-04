/* [patch openkey-fido2] Fallback C de multiplicação de Montgomery para
 * ARM 32-bit sem NEON (Cortex-M33/Thumb-2, alvo thumbv8m.main-none-eabihf).
 *
 * Contexto: `sources_for_arch` em build.rs exclui
 * `crypto/fipsmodule/bn/asm/armv4-mont.pl` para `arch == "arm"` porque o asm
 * ARM-mode gerado não monta em Thumb-2. Esse .pl é, porém, a ÚNICA definição
 * de `bn_mul_mont_nohw` e `bn_mul8x_mont_neon` para OPENSSL_ARM (não há
 * fallback C no ring/BoringSSL) — sem este arquivo o link do firmware falha
 * com `undefined symbol` vindo de `gfp_p256.o`/`gfp_p384.o`.
 * Nenhum código criptográfico do ring foi alterado; este arquivo apenas
 * fornece as definições ausentes. Vendor local usado SOMENTE por
 * examples/rp2350-firmware via [patch.crates-io].
 *
 * Contrato (crypto/fipsmodule/bn/internal.h): escreve
 * |rp| = |ap| * |bp| * R^-1 mod |np| (R = 2^(num*32)), com n0 = -|np|^-1
 * mod 2^32 em n0[0]. "Se ao menos um de |ap|/|bp| estiver totalmente
 * reduzido, |rp| será totalmente reduzido" — chamadores (gfp_p256.c,
 * gfp_p384.c) operam em forma de Montgomery (valores < N). Esta
 * implementação SEMPRE retorna resultado totalmente reduzido (< N, via
 * subtração condicional em tempo constante), um superconjunto da garantia
 * do asm — seguro para todos os chamadores.
 *
 * Implementação: produto schoolbook (2*num limbs, exato) + redução de
 * Montgomery REDC (HAC 14.32, in-place) + 1 subtração condicional mascarada
 * (REDC garante T < 2N quando P < N*R; aqui P = a*b < N^2 <= N*R pois N < R).
 *
 * `bn_mul8x_mont_neon` nunca executa no M33 (sem NEON; `neon_available` é 0
 * e o dispatch em internal.h só o chama para num == 8 com NEON presente),
 * mas o linker exige o símbolo: implementado como wrapper do nohw, o que
 * é funcionalmente correto em qualquer caso (é a mesma operação).
 *
 * Tempo constante: laços limitados por |num| (tamanho público: 8 para
 * P-256, 12 para P-384), sem branches sobre dados secretos; seleção final
 * por máscara.
 */

#include "internal.h"

void bn_mul_mont_nohw(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,
                      const BN_ULONG *np, const BN_ULONG *n0, size_t num) {
  const BN_ULONG n0_ = n0[0];

  /* T temporário de 2*num+1 limbs (produto 2*num + 1 limb extra para o
   * carry final do REDC). VLA: num é 8/12 na prática (P-256/P-384). */
  BN_ULONG t[2 * num + 1];
  for (size_t k = 0; k < 2 * num + 1; k++) {
    t[k] = 0;
  }

  /* 1. Produto schoolbook exato P = a*b em t[0..2*num-1].
   * t[i+num] está intocado (zero) ao receber o carry da linha i: linhas
   * anteriores escreveram dados até t[i+num-2] e carry até t[i+num-1]. */
  for (size_t i = 0; i < num; i++) {
    BN_ULLONG carry = 0;
    for (size_t j = 0; j < num; j++) {
      carry += (BN_ULLONG)t[i + j] + (BN_ULLONG)ap[i] * (BN_ULLONG)bp[j];
      t[i + j] = (BN_ULONG)carry;
      carry >>= 32;
    }
    t[i + num] = (BN_ULONG)carry;
  }

  /* 2. REDC (HAC 14.32): dobra cada limb baixo com múltiplo de N e desloca.
   * Laço de propagação com limite fixo (sem `while carry`: tempo constante).
   * Ao final, t[0..num-1] == 0 e o resultado (< 2N) está em
   * t[num..2*num-1] mais o bit extra t[2*num]. */
  for (size_t i = 0; i < num; i++) {
    const BN_ULONG m = (BN_ULONG)((BN_ULLONG)t[i] * (BN_ULLONG)n0_);
    BN_ULLONG c = 0;
    for (size_t j = 0; j < num; j++) {
      c += (BN_ULLONG)t[i + j] + (BN_ULLONG)m * (BN_ULLONG)np[j];
      t[i + j] = (BN_ULONG)c;
      c >>= 32;
    }
    for (size_t k = i + num; k < 2 * num + 1; k++) {
      c += (BN_ULLONG)t[k];
      t[k] = (BN_ULONG)c;
      c >>= 32;
    }
  }

  /* 3. Subtrações condicionais em tempo constante até redução total.
   * REDC garante T < 4N^2/R + N (< 5N para entradas < 2N com N < R); cada
   * iteração subtrai N se V >= N (V em num+1 limbs, com o bit extra E).
   * 5 iterações cobrem V < 6N com folga. (Para entradas reduzidas, 1
   * bastaria; o laço fixo mantém tempo constante.) */
  for (int iter = 0; iter < 5; iter++) {
    BN_ULONG borrow = 0;
    BN_ULONG diff[num + 1];
    for (size_t j = 0; j < num; j++) {
      const BN_ULLONG sub =
          (BN_ULLONG)t[num + j] - (BN_ULLONG)np[j] - (BN_ULLONG)borrow;
      diff[j] = (BN_ULONG)sub;
      borrow = (BN_ULONG)((sub >> 32) & 1u);
    }
    /* Empresta o borrow baixo do limb extra E (sem branch: aritmética). */
    const BN_ULLONG top = (BN_ULLONG)t[2 * num] - (BN_ULLONG)borrow;
    diff[num] = (BN_ULONG)top;
    /* V >= N ⟺ sem borrow na saída do topo (aritmética, sem branch). */
    const uint32_t sel = (uint32_t)(((top >> 32) & 1u) ^ 1u);
    const uint32_t mask = 0u - sel;
    for (size_t j = 0; j < num + 1; j++) {
      t[num + j] = t[num + j] ^ (mask & (t[num + j] ^ diff[j]));
    }
  }
  for (size_t j = 0; j < num; j++) {
    rp[j] = t[num + j];
  }
}

void bn_mul8x_mont_neon(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,
                        const BN_ULONG *np, const BN_ULONG *n0, size_t num) {
  /* Sem NEON no Cortex-M33: equivale ao caminho nohw (também correto caso
   * o dispatch um dia o alcance — é a mesma operação de Montgomery). */
  bn_mul_mont_nohw(rp, ap, bp, np, n0, num);
}
