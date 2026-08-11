# ADR-0003: Arquitetura em Camadas

Status: accepted
Data: 2026-08-05

## Contexto

O projeto precisa isolar responsabilidades para permitir testes unitarios
independentes por camada, substituicao de implementacoes e evolucao
independente de cada modulo.

O FIDO2 authenticator naturalmente se divide em camadas com interfaces bem
definidas.

## Decisão

Arquitetura em camadas com dependencias unidirecionais:

```
EmbeddedAuthenticator
    |
    +-- WebAuthnAuthenticator
    |       |
    |       +-- Ctap2Authenticator
    |               |
    |               +-- CryptoEngine
    |               +-- StorageEngine
    |                       |
    |                       +-- CryptoEngine
    |
    +-- CapabilityDiscovery
            |
            +-- DeviceProfile
                    |
                    +-- BoardDefinition
```

Setas apontam de quem depende para quem e dependido. Nunca criar dependencias
circulares.

Cada camada expoe tipos publicos via `pub use` no `lib.rs` da crate.

## Consequências

Positivas:
- Cada crate pode ser testada isoladamente
- Substituir storage backend requer mudar apenas `firmware/storage/`
- Adicionar novos transports nao afeta a logica CTAP2

Negativas:
- Mais arquivos e modulos para navegar
- Overhead de serializacao nas fronteiras (CBOR)
