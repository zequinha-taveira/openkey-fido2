# ADR-0008: Sealed Box ECIES para Criptografia Híbrida (Efêmero e Estático)

Status: accepted (atualizado em 2026-08-14)
Data: 2026-08-10

## Contexto

O autenticador FIDO2 precisa suportar criptografia híbrida para cenários como:
- Proteção de `credBlob` em trânsito entre plataforma e autenticador
- Comunicação segura entre módulos internos (ex.: ClientPIN token exchange)
- Cifragem persistente em Flash que sobrevive a reinicializações (*reboots*) do dispositivo
- Extensões futuras que exigem encryption end-to-end

O requisito é um esquema **ECIES** (Elliptic Curve Integrated Encryption Scheme) que combine criptografia assimétrica (ECDH X25519) com simétrica (ChaCha20-Poly1305 + HKDF-SHA256).

## Decisão

Implementar suporte duplo para **sealed box ECIES**:

1. **Chaves Efêmeras (`ring`)**:
   - `hybrid_generate_keypair` / `hybrid_decrypt` usam `ring::agreement::EphemeralPrivateKey`.
   - Adequado para sessões em memória e handshakes efêmeros one-shot.

2. **Chaves Estáticas Persistíveis (`x25519-dalek`)**:
   - `hybrid_generate_static_keypair`, `hybrid_diffie_hellman` e `hybrid_decrypt_static` usam `x25519_dalek::StaticSecret` e `x25519_dalek::PublicKey`.
   - Permite que chaves privadas de 32 bytes sejam persistidas no `StorageEngine` e decifrem mensagens após reboots.

3. **Derivação de Chave Simétrica (Idêntica em ambos os modos)**:
   - HKDF-SHA256 com salt `ephemeral_pk || recipient_pk`.
   - Rótulo de domínio `openkey-ecies-v1`.

4. **Cifragem e Autenticação de Mensagem**:
   - ChaCha20-Poly1305 com nonce aleatório de 12 bytes.
   - AAD vinculado à chave pública efêmera (proteção estrita contra adulteração).

Formato do ciphertext serializado:
```
| ephemeral_pk (32B) | nonce (12B) | ciphertext+tag (n+16B) |
```

## Consequências

### Positivas
- Eliminação da limitação do `ring 0.17` quanto a chaves X25519 estáticas.
- Total interoperabilidade: payloads cifrados com a chave pública do destinatário podem ser decifrados tanto pelo handler estático quanto efêmero.
- Suporte a `no_std` e zeroização segura de memória via `zeroize`.
- Segurança preservada com AAD e KDF determinístico vinculado a ambos os lados.

### Neutras / Considerações
- Adiciona a dependência `x25519-dalek = { version = "2.0", default-features = false, features = ["static_secrets", "zeroize"] }` ao workspace.
