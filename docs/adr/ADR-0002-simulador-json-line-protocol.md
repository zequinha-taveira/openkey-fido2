# ADR-0002: Simulador via JSON Line Protocol

Status: accepted
Data: 2026-08-05

## Contexto

O firmware FIDO2 precisa ser testado sem hardware físico. O simulador deve permitir:
- Execução em qualquer host (Windows, Linux, macOS)
- Testes automatizados via script
- Interação humana para debugging

Alternativas consideradas:
- JSON line protocol (stdin/stdout) — simples, legível, testável
- TCP socket — mais flexível, mas requer gerenciamento de conexão
- gRPC/protobuf — robusto, mas pesado para o escopo
- WASM embed — interessante, mas limita acesso ao hardware simulado

## Decisão

O simulador (`fido2-simulator`) expõe o firmware via JSON line protocol sobre
stdin/stdout. Cada linha é um request JSON; cada resposta é uma linha JSON.

O protocolo cobre:
- `get_info` — retorna CTAP2 GetInfo
- `make_credential` — cria credencial
- `get_assertion` — obtém assertion
- `verify_assertion` — verifica assinatura
- `process_command` — envia comando CBOR cru
- `reset` — reinicia o estado

Bytes são codificados em base64 dentro dos campos JSON.

## Consequências

Positivas:
- Qualquer linguagem pode interagir com o simulador (Python usado atualmente)
- Testes são fáceis de escrever e debugar
- Nenhuma dependência de rede ou porta

Negativas:
- JSON é verboso para payloads grandes
- Sem streaming — request/response síncrono
- Não simula timing real de hardware

Tradeoffs aceitos:
- Simplicidade de teste vs. fidelidade de simulação
- Quando necessário testar timing, criar modo de teste específico
