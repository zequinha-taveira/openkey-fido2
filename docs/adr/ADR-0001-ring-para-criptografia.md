# ADR-0001: Uso de `ring` para Operações Criptográficas

Status: accepted
Data: 2026-08-05

## Contexto

O projeto FIDO2 authenticator requer primitivas criptográficas seguras: Ed25519 para assinaturas, HMAC-SHA256 para derivação de chaves, ChaCha20-Poly1305 para encryption at rest, e SHA-256 para hashing.

Alternativas consideradas:
- `ring` (AWS-LC baseado) — consolidado, auditado, usado por Rustls e Bunny
- `rustcrypto` puro (ed25519-dalek + hmac + sha2) — ecossistema Rust puro
- `openssl` — maduro, mas pesado e problemático para `no_std`/embedded

Restrições:
- Código deve ser adequado para embedded (`no_std`)
- Não podemos implementar primitivas próprias (regra de segurança do projeto)
- `SystemRandom` é requisito para nonces e seeds

## Decisão

Usar `ring` como provedor criptográfico único. Todas as operações criptográficas
são encapsuladas em `CryptoEngine` (`protocol/crypto/src/crypto.rs`), que expõe
uma API simplificada para o resto do projeto.

`CryptoEngine` não expõe `ring` diretamente — internamente usa:
- `ring::signature::Ed25519KeyPair` para sign/verify
- `ring::rand::SystemRandom` para geração de bytes aleatórios
- `ring::hmac` para HMAC-SHA256
- `ring::aead::CHACHA20_POLY1305` para encryption at rest
- `ring::digest::SHA256` para hashing

## Consequências

Positivas:
- Código criptográfico auditado pela comunidade
- `SystemRandom` garante nonces seguros sem esforço adicional
- API unificada simplifica o restante do codebase

Negativas:
- `ring` não é `no_std` puro (requer `std`) — mas nosso target host (simulador/testes) usa `std`
- Para target embedded real, precisaremos de adaptação (potencialmente feature flag ou crate alternativa)
- Dependência de um crate externo grande (~200KB compilado)

Tradeoffs aceitos:
- Simplicidade e segurança agora vs. portabilidade embedded futura
- Quando o target embedded for priorizado, podemos reintroduzir `rustcrypto` atrás de uma feature flag
