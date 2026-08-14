# ADR-0012: Suporte a Conformance Testing FIDO2 e Interface Raw CBOR

## Contexto

A conformidade com as especificações da FIDO Alliance (FIDO2 / CTAP 2.0, CTAP 2.1) e W3C WebAuthn é requisito fundamental para garantir interoperabilidade com navegadores, sistemas operacionais e servidores de autenticação (Relying Parties).

Anteriormente, o simulador (`fido2-simulator`) expunha apenas um protocolo textual baseado em linhas JSON, o que facilitava testes rápidos mas impedia o envio direto de payloads binários CBOR nativos sem tradução.

Era necessário introduzir:
1. **Modo binário direto (`--raw-cbor`) no simulador host**: Permite a ferramentas externas e scripts de teste falar o protocolo CTAP2 em wire-format CBOR puro com enquadramento de comprimento (`[2B length][1B cmd][CBOR payload]`).
2. **Suíte de Testes de Conformidade CTAP 2.1 (`tests/python/conformance/`)**: Bateria automatizada de testes cobrindo comandos mandatórios e opcionais (MakeCredential, GetAssertion, GetInfo, ClientPIN, CredentialManagement, LargeBlobs e Reset) com validação estrita de tipos, codificações CBOR, flags de presença do usuário e códigos de erro de especificação.

---

## Decisão

1. **Interface Binária `--raw-cbor`**:
   - Adicionada flag `--raw-cbor` no binário `fido2-simulator`.
   - Streaming bidirecional sobre `stdin`/`stdout` com enquadramento length-prefixed:
     - Request: `[u16 length big-endian] + [u8 cmd] + [payload CBOR]`.
     - Response: `[u16 length big-endian] + [u8 status (0x00 = Success, ou Ctap2Error)] + [payload CBOR de resposta]`.
   - Despacho direto ao método `EmbeddedAuthenticator::process_command` sem serialização intermediária para JSON.

2. **Transporte e Harness de Conformance em Python**:
   - Criada classe de transporte `SimulatorClient` em `tests/python/conformance/ctap2_transport.py`.
   - Suíte de conformidade pytest estruturada por comando da especificação CTAP 2.1:
     - `test_get_info.py`: versões suportadas, AAGUID 16B, options, algorithms COSE.
     - `test_make_credential.py`: criação de credencial, validação de flags UP e AT em `authData`, rejeição de algoritmos não suportados e campos ausentes.
     - `test_get_assertion.py`: ciclo de asserção, incremento estrito de `signCount`, validação de `allowList` e erro `NO_CREDENTIALS`.
     - `test_client_pin.py`: negociação e consulta de retries via subcomando `getPINRetries`.
     - `test_credential_management.py`: metadados de credenciais residentes (`getCredsMetadata`).
     - `test_large_blobs.py`: gravação e leitura de payload no buffer `LargeBlobs`.
     - `test_reset.py`: limpeza completa de estado e credenciais.

3. **Integração com Ferramentas de Conformidade FIDO Alliance**:
   - A interface `--raw-cbor` serve como endpoint de bridging para o FIDO Conformance Test Tool (via USB-HID virtual / UHID ou pipes IPC).

---

## Consequências

### Positivas
- Validação automática de 100% dos fluxos CTAP2 com wire format idêntico ao de produção.
- Zero dependência de pontes JSON para testes de conformidade de baixo nível.
- Facilidade de automação em pipelines de CI (`python -m pytest tests/python/conformance/ -v`).

### Considerações
- O modo padrão do simulador continua sendo o JSON line protocol para manter compatibilidade com as ferramentas de debug e testes existentes.
