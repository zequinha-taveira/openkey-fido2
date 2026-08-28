# Política de Segurança — openkey-fido2

> **English summary below** — please report vulnerabilities privately via GitHub Security Advisories. Do not open public issues for security bugs.

## Versões Suportadas

| Versão | Suportada | Notas |
|--------|-----------|-------|
| `main` | ✅ | Recebe correções de segurança assim que disponíveis |
| `0.1.x` | ✅ | Última release estável; backports críticos quando aplicável |
| `< 0.1.0` | ❌ | Sem suporte |

Recomendamos sempre usar a última revisão de `main` ou a última tag `v*` publicada.

## Como Reportar uma Vulnerabilidade

**Não abra issue pública para vulnerabilidades.**

1. Use **GitHub → Security → Report a vulnerability** (Private vulnerability reporting) em `https://github.com/zequinha-taveira/openkey-fido2/security/advisories/new`
2. Alternativa: abra um draft Security Advisory e descreva o problema com PoC mínimo, impacto e versão afetada
3. Se preferir e-mail, mencione `SECURITY` no assunto e inclua detalhes técnicos completos

### O que incluir

- Descrição do problema e impacto (ex.: bypass de PIN, vazamento de chave, DoS via CBOR)
- Versão/commit afetado, crate e arquivo (`crate:linha`, ex.: `protocol/ctap2/src/client_pin.rs:120`)
- PoC reprodutível (Rust `cargo test` ou `tests/python` + simulador)
- Se o problema envolve criptografia, hardware (`thumbv8m`/`thumbv7em`) ou transporte (CTAPHID/CCID)

### O que esperar

- **Confirmação em até 3 dias úteis**
- **Avaliação e plano em até 7 dias**
- Correção coordenada em branch privada, com testes de regressão e ADR quando houver decisão de design
- Divulgação coordenada após correção disponível; crédito ao reporter se desejado

Seguimos *coordinated disclosure* — por favor não divulgue publicamente antes do fix estar disponível.

## Escopo

Dentro do escopo:

- `protocol/crypto` — operações Ed25519/ES256/ES384/PS256/RS256, HMAC-SHA256, ChaCha20-Poly1305, HKDF, ECDH P-256/X25519, geração de nonces via `SystemRandom`
- `protocol/ctap2` e `protocol/webauthn` — validação de `MakeCredential`/`GetAssertion`, `ClientPIN` (protocolos 1/2), `hmac-secret`, `credProtect`/`credBlob`, `LargeBlobs`, `Credential Management`, `authenticatorConfig`
- `firmware/storage` — encryption at rest, `StorageBackend`, `FlashStorageBackend`, contadores, `largeBlobKey`
- `firmware/transport` — framing CTAPHID, `iso7816`/`Applet`, `FramedUsbHidTransport`/`FramedCcidTransport`
- `firmware/authenticator` e `simulator` — despacho CBOR e `fido2-simulator --raw-cbor`
- `examples/rp2350-firmware` e `examples/nrf52840-firmware` — boot `no_std`, composição USB

Fora do escopo: DoS que exige acesso físico já assumido como comprometido, engenharia social, e problemas apenas em dependências de terceiros sem PoC no projeto.

## Práticas de Segurança do Projeto

O projeto segue as regras de `AGENTS.md` e ADRs:

- **Sem `unsafe` em `protocol/*` e `firmware/*`** exceto `examples/rp2350-firmware/src/qspi_flash.rs` (justificado no header) e `vendor/ring` (vendored, fora do controle do projeto)
- **Nunca logar material sensível** — chaves privadas, seeds, `pinUvAuthToken`, `CredRandom` são `Zeroizing`/`zeroize(drop)` e `Debug` redigido
- **Criptografia via `ring`** — não implementamos primitivas próprias; nonces via `SystemRandom`
- **Constant-time** — `crypto::constant_time_eq` para PIN/token, decremento de `retries` antes de verificação
- **Rate limiting** — bloqueio após 3 falhas consecutivas de PIN (`PIN_AUTH_BLOCKED`), `powerCycleState`
- **Fuzzing** — alvos `decode_cbor`, `ctap2_dispatch`, `ctaphid_framing` (`cargo fuzz`, nightly)
- **CI** — `cargo fmt --check`, `cargo clippy -D warnings`, `CodeQL` (`rust`/`python`), `cargo test --workspace` e `pytest tests/python`

Mais detalhes em `README.md#segurança`, `docs/adr/ADR-0006-side-channel-mitigation.md`, `docs/adr/ADR-0008-sealed-box-ecies.md`, `docs/adr/ADR-0016-flash-simulada-e-gates-de-release.md` e `docs/adr/ADR-0023-gate-storage-host-inseguro.md`.

## Medidas para Usuários

- Mantenha o firmware atualizado; valide `SHA256SUMS` e, quando disponível, assinatura `cosign` dos artefatos de release
- Não compartilhe `OPENKEY_VAULT_*` ou segredos de teste em logs/CI públicos
- Em hardware real, habilite `secure_boot`/`debug_disable` quando suportado pelo board (ver `firmware/board-generic`)

## Agradecimentos

Agradecemos reportes responsáveis. Contribuidores que seguirem esta política serão creditados no `CHANGELOG.md` e no advisory, salvo pedido de anonimato.

---

## Security Policy (English)

Supported: `main` and latest `0.1.x`. Please report privately via **GitHub Security Advisories** (preferred) — do not file public issues for security bugs. Expect acknowledgment within 3 business days and assessment within 7 days. We follow coordinated disclosure. Scope and practices are as described above (pt-BR section is authoritative for this repository).
