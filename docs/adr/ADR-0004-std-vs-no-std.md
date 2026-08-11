# ADR-0004: std vs no_std — Estratificação por Target

Status: accepted
Data: 2026-08-05

## Contexto

O firmware FIDO2 authenticator idealmente roda em microcontroladores sem
sistema operacional (no_std). Porem, o desenvolvimento e testes atuais rodam
em hosts com sistema operacional (Windows/Linux/macOS).

O crate `ring`, escolhido para criptografia (ADR-0001), requer `std`. Isso cria
tensao com o objetivo de compatibilidade embedded.

## Decisão

Estrategia de estratificacao:

- **protocol/crypto/**: usa `std` atualmente (via `ring`). Futuramente pode
  receber feature flag `embedded` para trocar para `rustcrypto`.
- **protocol/ctap2/**: usa `extern crate alloc` (alocador apenas, sem std
  completo). Compativel com `no_std` com alloc.
- **firmware/storage/**: usa `extern crate alloc`. Idem.
- **firmware/board-generic/**: usa `embedded-hal`, `cortex-m` — ja no_std.
- **simulator/**: usa `std` (host-only).
- **tests/**: usa `std` (host-only).
- **examples/**: usam `std` (host-only).

## Consequências

Positivas:
- Simulador e testes rodam em qualquer host
- Camadas inferiores (crypto, storage) ja estao quase no_std compativeis
- Transicao para embedded e incremental

Negativas:
- `ring` nao compila para no_std hoje
- Ha uma "divisao" logica no que e host-only vs. embarcado
