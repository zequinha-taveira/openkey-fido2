# Política de Versionamento — openkey-fido2

Este documento define como o projeto gerencia versões de releases, compatibilidade de API, MSRV e suporte a protocolo.

---

## Versão Atual

| Artefato | Versão |
|----------|--------|
| Workspace (`Cargo.toml`) | `0.1.1` |
| MSRV (Minimum Supported Rust Version) | `1.85` |
| Protocolo | CTAP2.1 / WebAuthn L2 |

---

## Esquema de Versionamento

O projeto adota **Semantic Versioning 2.0.0** ([semver.org](https://semver.org/)) para o workspace Cargo e para os artefatos de firmware distribuídos.

```
MAJOR.MINOR.PATCH
  │      │     └── Correções de bugs e segurança (retrocompatíveis)
  │      └──────── Funcionalidades novas (retrocompatíveis)
  └─────────────── Quebras de API pública ou protocolo
```

### Regras de incremento

| Situação | Componente bumped |
|----------|-------------------|
| Correção de bug ou segurança sem mudança de API | `PATCH` |
| Nova funcionalidade CTAP2/WebAuthn retrocompatível | `MINOR` |
| Mudança em API pública de crate (`authenticator`, `ctap2`, `webauthn`, `crypto`) | `MAJOR` |
| Mudança em wire format de protocolo CTAP2 | `MAJOR` |
| Mudança de MSRV | `MINOR` (no mínimo) |

> **Nota:** Enquanto `MAJOR = 0`, mudanças incompatíveis **podem** ocorrer em incrementos `MINOR`. A API pública ainda não é considerada estável.

---

## Workspace Cargo

Todas as crates do workspace compartilham a **mesma versão**, declarada em `[workspace.package]` no `Cargo.toml` raiz:

```toml
[workspace.package]
version = "0.1.1"
```

O bumping é feito **uma única vez** na raiz; as crates herdam via `version.workspace = true`. Não há versões independentes por crate enquanto o projeto estiver em `0.x`.

---

## MSRV (Minimum Supported Rust Version)

- MSRV atual: **Rust 1.85**
- Declarado em `Cargo.toml`: `rust-version = "1.85"`
- A CI valida o MSRV a cada PR

### Política de mudança de MSRV

- Aumentar o MSRV é tratado como mudança `MINOR` (no mínimo)
- A mudança deve ser justificada (ex.: nova feature de linguagem necessária, dependência que abandonou versão anterior)
- Deve ser anunciada no `CHANGELOG.md` antes de entrar em `main`

---

## Ciclo de Release

```
main (desenvolvimento contínuo)
    │
    ├─ feat/incremento-XYZ  ──► PR ──► squash merge ──► main
    │
    └─ tag vMAJOR.MINOR.PATCH  ──► release (artefatos + checksums + cosign)
```

### Passos para uma release

1. Atualizar `version` em `Cargo.toml` (workspace raiz)
2. Atualizar `## Unreleased` → `## MAJOR.MINOR.PATCH - YYYY-MM-DD` no [`CHANGELOG.md`](CHANGELOG.md)
3. Atualizar `SECURITY.md` se a tabela de versões suportadas mudar
4. Commit: `chore: bump version to vX.Y.Z`
5. Tag: `git tag -s vX.Y.Z -m "Release vX.Y.Z"`
6. Push da tag: a CI gera artefatos, `SHA256SUMS` e assinatura `cosign`

> Veja o gate de release em [`docs/adr/ADR-0016-flash-simulada-e-gates-de-release.md`](docs/adr/ADR-0016-flash-simulada-e-gates-de-release.md).

---

## Compatibilidade de Protocolo

O projeto implementa **CTAP2.1** e **WebAuthn Level 2**. A compatibilidade de protocolo segue regras independentes da versão SemVer do crate:

| Protocolo | Status |
|-----------|--------|
| CTAP2.0 (subconjunto) | ✅ Suportado |
| CTAP2.1 | ✅ Implementação em andamento (ver `TODO.md`) |
| WebAuthn L2 | ✅ Suportado |
| CTAP1/U2F | ❌ Fora do escopo |

### Versão de firmware reportada ao host

O campo `firmware_version` retornado em `GetInfo` segue o esquema CTAP2.1 de inteiro codificado:

```
firmware_version = MAJOR * 1_000_000 + MINOR * 1_000 + PATCH
```

Veja [`docs/adr/ADR-0020-firmware-version-ctap21-integer.md`](docs/adr/ADR-0020-firmware-version-ctap21-integer.md) para detalhes.

---

## Branches e Tags

| Ref | Propósito |
|-----|-----------|
| `main` | Desenvolvimento ativo; pode ser instável |
| `v*` (tags) | Releases imutáveis e assinadas |

Não há branches de manutenção (`0.1.x-maintenance`) enquanto o projeto estiver em fase inicial. Backports críticos de segurança são lançados como novo `PATCH` a partir de `main`.

---

## Compatibilidade de API de Crate

Enquanto `MAJOR = 0`:

- A API pública dos crates **não é estável** — mudanças incompatíveis podem ocorrer
- Mudanças que afetam `EmbeddedAuthenticator`, `Ctap2Authenticator`, `WebAuthnAuthenticator` ou qualquer trait pública de `crypto/` devem ser documentadas no `CHANGELOG.md`
- Mudanças em `[workspace.dependencies]` que alteram o comportamento de dependências transitivas devem ser anotadas

---

## Histórico de Versões

Consulte o [`CHANGELOG.md`](CHANGELOG.md) para o histórico completo.

| Versão | Data | Destaque |
|--------|------|----------|
| `0.1.1` | 2026-08-14 | Fuzzing, flash com journaling, gate cosign de release |
| `0.1.0` | — | Release inicial de desenvolvimento |

---

## Referências

- [SemVer 2.0.0](https://semver.org/)
- [`Cargo.toml`](Cargo.toml) — `[workspace.package]`
- [`CHANGELOG.md`](CHANGELOG.md) — histórico de mudanças
- [`SECURITY.md`](SECURITY.md) — versões suportadas para fins de segurança
- [`docs/adr/ADR-0016-flash-simulada-e-gates-de-release.md`](docs/adr/ADR-0016-flash-simulada-e-gates-de-release.md) — gate de release
- [`docs/adr/ADR-0020-firmware-version-ctap21-integer.md`](docs/adr/ADR-0020-firmware-version-ctap21-integer.md) — versão de firmware CTAP2.1
