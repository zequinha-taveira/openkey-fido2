# ADR-0008: Sealed Box Efêmero (ECIES) para Criptografia Híbrida

Status: accepted
Data: 2026-08-10

## Contexto

O autenticador FIDO2 precisa suportar criptografia híbrida para cenários como:
- Proteção de `credBlob` em trânsito entre plataforma e autenticador
- Comunicação segura entre módulos internos (ex.: ClientPIN token exchange)
- Extensões futuras que exigem encryption end-to-end

O requisito é um esquema **ECIES** (Elliptic Curve Integrated Encryption Scheme)
que combine criptografia assimétrica (ECDH) com simétrica (AEAD).

## Decisão

Implementar um **sealed box efêmero** sobre X25519 + ChaCha20-Poly1305:

1. **Geração de chave**: X25519 via `ring::agreement::EphemeralPrivateKey`
2. **Derivação**: HKDF-SHA256 com salt `ephemeral_pk || recipient_pk` (identico nos dois lados)
3. **Cifragem**: ChaCha20-Poly1305 com nonce aleatorio de 12 bytes
4. **AAD**: chave publica efêmera (proteção contra adulteração)

O ciphertext serializado tem formato:
```
| ephemeral_pk (32B) | nonce (12B) | ciphertext+tag (n+16B) |
```

### Limitação conhecida

`ring` 0.17 nao permite importar chaves privadas X25519 estaticas —
`EphemeralPrivateKey` so pode ser criada via `generate()`. Por isso:

- `hybrid_decrypt` recebe `EphemeralPrivateKey` **por valor** (consome)
- O par de chaves do destinatario precisa ser criado no processo e mantido vivo
- Restrito a cenarios dentro de um mesmo processo (sessoes em memoria)

## Consequencias

Positivas:
- Criptografia híbrida sem dependencias adicionais (usa `ring` existente)
- AAD vincula o ciphertext a chave efêmera (tampering detection)
- KDF deterministico garante mesma chave derivada nos dois lados
- Zeroizacao best-effort de material sensivel via wrapper `Zeroifying`

Negativas:
- Limitacao do `ring` impede persistencia de chaves X25519 em flash
- Wrapper `Zeroizing` manual (sem crate `zeroize`) e menos robusto
- Nao suporta cenarios de longo prazo onde chaves precisam sobreviver a reboots

Referencias:
- `protocol/crypto/src/hybrid.rs` — implementacao completa
- `protocol/crypto/src/hybrid.rs:46` — `Zeroizing<T>` wrapper
- `protocol/crypto/src/hybrid.rs:124` — `derive_symmetric_key()`
- `protocol/crypto/src/hybrid.rs:159` — `hybrid_encrypt()`
- `protocol/crypto/src/hybrid.rs:223` — `hybrid_decrypt()`
- ADR-0001: uso de `ring` para operacoes criptograficas
- ADR-0006: side-channel mitigation (zeroize, constant-time)
