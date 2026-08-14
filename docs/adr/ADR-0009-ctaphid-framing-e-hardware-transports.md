# ADR-0009: CTAPHID Packet Framing, APDU CCID/NFC e Transports de Hardware Real

## Contexto

O protocolo FIDO2/CTAP2 opera sobre diferentes camadas físicas e de transporte:
1. **USB-HID (CTAPHID)**: Utiliza pacotes de tamanho fixo (64 bytes) com um cabeçalho de inicialização (`INIT`) e pacotes de continuação (`CONT`) para segmentar payloads de até 7609 bytes.
2. **USB-CCID**: Emula leitor de smartcard e troca APDUs ISO/IEC 7816-4.
3. **NFC (Contactless)**: Comunicação sem contato baseada em ISO/IEC 14443-4 T=CL.
4. **BLE GATT**: Serviços e características Bluetooth Low Energy.

Anteriormente, o repositório possuía apenas stubs genéricos e a trait `Transport`. Era necessário introduzir:
- Algoritmo de fragmentação e remontagem CTAPHID em conformidade com CTAP 2.1 §8.2.
- Gerenciador de canais (ChannelManager / CIDs).
- Contratos de hardware (`embedded`) e implementações de referência para os microcontroladores suportados (**RP2350**, **nRF52840**, **STM32L4**).
- Adaptadores de transporte (`FramedUsbHidTransport`, `FramedCcidTransport`) que implementam a trait object-safe `Transport`.

## Decisão

1. **Separação entre Hardware Abstraction e Framing**:
   - A camada `ctaphid` é 100% agnóstica de hardware e puramente computacional (opera sobre `[u8; 64]`), facilitando testes unitários, fuzzing e execução em ambientes `no_std`.
   - Traits de baixo nível (`UsbHidDevice`, `UsbCcidDevice`, `NfcDevice`, `BleGattDevice`) são definidas no módulo `embedded`, dependendo apenas de `embedded-hal 1.0`.
   - Adaptadores concretos (`FramedUsbHidTransport<D>`, `FramedCcidTransport<D>`) conectam os dispositivos à trait unificada `Transport` consumida pelo `EmbeddedAuthenticator`.

2. **CTAPHID Framing & Assembly**:
   - **INIT Packet (64B)**: `CID (4B) | CMD | BCNT (2B) | DATA (57B max)`.
   - **CONT Packet (64B)**: `CID (4B) | SEQ (0..127) | DATA (59B max)`.
   - Remontagem com checagem estrita de sequência, CID e cancelamento rápido (`CTAPHID_CANCEL`).
   - Alocação de CIDs no handshake `CTAPHID_INIT` descartando CIDs reservados (`0x00000000` e `0xFFFFFFFF`).

3. **Suporte a Alvos de Hardware**:
   - Fornecer reference implementations dos periféricos USB e rádio para **RP2350**, **nRF52840** e **STM32L4**.

## Consequências

### Positivas
- A arquitetura permite ligar qualquer microcontrolador suportado ao firmware FIDO2 com poucas linhas de código de bridging.
- 100% de conformidade com a especificação CTAPHID do FIDO2 / CTAP 2.1.
- Suporte a múltiplos canais, múltiplos pacotes e cancelamento de transações.

### Neutras / Considerações
- O módulo `embedded` e seus adaptadores de hardware exigem a feature `embedded` habilitada quando compilados para targets bare-metal.
