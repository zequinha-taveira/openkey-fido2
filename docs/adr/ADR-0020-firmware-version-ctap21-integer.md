# ADR-0020: `firmwareVersion` Inteiro no GetInfo CTAP 2.1

Status: accepted / implemented
Data: 2026-08-16

## Contexto

O CTAP 2.1 §6.4 define `firmwareVersion` (chave CBOR `0x0E`) como um inteiro
sem sinal. O projeto armazenava a versão do produto como string semver e
repassava essa string no `GetInfo`, fazendo o `python-fido2` rejeitar a
resposta. O ADR-0017 registrou essa lacuna como fora do escopo do ClientPIN.

O formato textual do `DeviceProfile` é útil para configuração e diagnóstico, e
o comando `GetVersion` já possui um contrato textual independente. A correção
deve, portanto, ficar na fronteira do `GetInfo` sem alterar esses contratos.

## Decisão

`GetInfoResponse.firmware_version` passa a ser `u32`. O núcleo numérico
`major.minor.patch` do semver do perfil é convertido com:

```
major * 1_000_000 + minor * 1_000 + patch
```

Cada componente deve estar no intervalo `0..=999`, preservando a ordem dos
componentes e evitando colisões nesse domínio. Sufixos de pré-lançamento e
build são ignorados, pois não têm representação no inteiro CTAP. Assim,
`0.1.0` torna-se `1000` e `3.1.0` torna-se `3001000`. Uma versão inválida ou
fora do domínio faz `GetInfo` falhar com `InvalidData`, em vez de emitir um
valor ambíguo.

`DeviceProfile.firmware_version`, `Capabilities.firmware_version` e
`Ctap2Capabilities.firmware_version` continuam strings semver como fonte da
conversão. O `firmwareVersion` serializado na chave `0x0E` é um inteiro CBOR
positivo. `GetVersion` permanece inalterado e continua retornando sua versão
textual.

## Consequências

- Clientes CTAP 2.1 e `python-fido2` podem consumir `GetInfo` sem adaptação.
- O wire format passa a cumprir o tipo exigido pela especificação.
- Consumidores Rust do campo público `GetInfoResponse.firmware_version` devem
  tratar `u32`, não `String`.
- O sufixo semver não é preservado no `GetInfo`; consumidores que precisam do
  texto devem usar o perfil ou `GetVersion`.
- A mudança não cobre validação de hardware, transports ou linkers.
