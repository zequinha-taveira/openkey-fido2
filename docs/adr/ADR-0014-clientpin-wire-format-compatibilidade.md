# ADR-0014: Compatibilidade do Wire Format do ClientPIN

Status: accepted
Data: 2026-08-14

## Contexto

O handler atual de `ClientPIN` usa mapas CBOR com chaves string, cifra campos
com ChaCha20-Poly1305 e nonce zero, e armazena um segredo local. Ele não
implementa o acordo de chaves nem a autenticação exigidos por
`pinUvAuthProtocol`.

Concretamente, `CryptoEngine::encrypt` retorna somente `plaintext || tag`
(16 bytes de tag); os 12 bytes do nonce zero usados pelo handler não são
transportados no payload. A mesma chave-mestra local é usada pelo
`CryptoEngine`, e o valor retornado como `keyAgreement` é o segredo persistido,
não uma chave pública COSE P-256.

Nos protocolos CTAP2 padronizados, o cliente envia os campos de `ClientPIN`
com chaves inteiras. O protocolo 1 usa acordo ECDH P-256, AES-256-CBC com IV
zero e HMAC-SHA-256; o protocolo 2 usa o esquema de derivação e autenticação
definido pela versão correspondente. Os campos cifrados não podem ser
substituídos por um nonce ChaCha arbitrário sem mudar o wire format e a
interoperabilidade.

## Decisão

Não mudar silenciosamente a implementação atual. A implementação existente é
explicitamente host-only/interna e permanece bloqueada para interoperabilidade
CTAP2 até que seja feita uma migração deliberada para o wire format padrão,
incluindo:

- codec CBOR com chaves inteiras para `ClientPIN`;
- key agreement P-256 compatível com o protocolo negociado;
- cifragem, HMAC e truncamento exatamente definidos por cada protocolo;
- vetores de teste contra um cliente CTAP2 independente.

Não há um mecanismo de nonce compatível que possa ser adicionado isoladamente:
o nonce zero atual é parte de uma construção ChaCha não padronizada, enquanto
o CTAP2 exige a construção AES/HMAC do protocolo. Portanto, nenhum nonce será
introduzido ou trocado nesta mudança.

## Consequências

- Clientes CTAP2 reais não devem ser considerados compatíveis com o handler
  atual.
- Os testes existentes verificam apenas o comportamento interno e não provam
  interoperabilidade.
- A implementação futura deve ser uma mudança de wire format explícita,
  acompanhada de testes de regressão e atualização do bloqueador em `TODO.md`.
