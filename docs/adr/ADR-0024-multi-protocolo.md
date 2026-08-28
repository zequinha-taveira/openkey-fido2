# ADR-0024: Multi-protocolo (FIDO2 + OATH + PIV/OpenPGP + Multi-transporte)

Status: accepted
Data: 2026-08-27

## Contexto

O dispositivo já é multi-interface no nível físico: `examples/rp2350-firmware/src/composite.rs` expõe HID (CTAPHID) + CCID sobre um único `UsbBusAllocator`, e `transport::iso7816::CardRouter` roteia APDUs para applets OATH (`A0000005272101`) e Management (`A000000527471117`). Falta, porém, uma camada **multi-protocolo** explícita:

- `device-profile::DeviceProfile` anuncia múltiplos `transports: Vec<Transport>` (do `BoardDefinition`), mas o transporte ativo é singular: `transport_config: Option<TransportConfig>` + `EmbeddedAuthenticator::transport: Option<Box<dyn Transport>>`. Não há como ligar HID+CCID+NFC+BLE simultaneamente via perfil, nem um dispatcher `MultiTransport`.
- No CCID, o CardRouter é genericamente multi-applet, mas o produto só registra 2 AIDs. Para emular um YubiKey multi-protocolo real (FIDO2, OATH, PIV, OpenPGP) é preciso demonstrar roteamento a ≥4 AIDs distintos com `ykman list --serials` / Yubico Authenticator reconhecendo todos.
- `Protocol` já contém `Ctap2/Ctap21/U2f/WebAuthn`, mas não há protocolo para o domínio CCID (Oath/Piv/OpenPgp). A capability `SUPPORTED_CAPABILITIES` do Management reporta `0x0624` (OATH|FIDO2|CCID), sem bits para PIV/OpenPGP futuros.

Alternativas consideradas:
1. Manter `transport_config` singular e documentar que composite é só do `rp2350-firmware` — rejeitada: integradores precisam configurar multi-transporte via `DeviceProfile` sem fork do firmware.
2. Substituir `transport_config: Option<_>` por `Vec<>` quebrando API — rejeitada: muitos testes e exemplos leem `profile.transport_config.unwrap()`.
3. Criar crate separada `multiprotocol` — rejeitada: dispersa lógica que pertence ao `device-profile`/`authenticator`/`transport`.

## Decisão

**Camada de transporte multi-protocolo:**

- `device-profile::DeviceProfile` ganha campo adicional `transport_configs: Vec<TransportConfig>` (lista de transportes ativos) mantendo `transport_config: Option<TransportConfig>` como view da primeira posição para compatibilidade. `DeviceProfileBuilder` ganha `transport_config(cfg)` (push/compat) + `transport_configs(vec)` + `add_transport(cfg)` idempotente. `DeviceProfile::active_transport_configs()` expõe a lista canônica (se `transport_configs` não vazio, usa-o; senão, usa `transport_config` isolado).
- `transport::MultiTransport` (`firmware/transport/src/multitransport.rs`): agregador `Vec<Box<dyn Transport>>` que implementa `Transport` com broadcast em `init`/`close` e first-success em `send`/`recv`. Erros mapeados para `TransportError`.
- `authenticator::EmbeddedAuthenticator` migra para `transports: Vec<Box<dyn Transport>>` mantendo acessores legados `transport()`/`transport_mut()` (primeiro elemento) + novos `transports()`/`transports_mut()`/`add_transport()`. `init_transports(&[TransportConfig]) -> Vec<Box<dyn Transport>>` substitui `init_transport(&Option<_>)` internamente; construtores `new_with_profile` e `new_with_profile_and_transport` alimentam o vetor.

**Camada CCID multi-applet:**

- Dois applets stub ISO 7816-4 novos, ambos `Applet` puros sem storage sensível:
  - `yubico_piv::PivApplet` AID `A000000308000010000100` (PIV Card Application, NIST SP 800-73).
  - `yubico_openpgp::OpenPgpApplet` AID `D27600012401` (OpenPGP Card 3.x).
  - SELECT retorna `9000` vazio; demais INS → `6D00` (stub). Suficiente para `ykman list` / `gpg --card-status` enxergarem o AID sem travar.
- Helper `register_multiprotocol_applets` registra Management+OATH+PIV+OpenPGP num `CardRouter` compartilhando o mesmo `StorageEngine` (OATH/Management já o fazem; PIV/OpenPGP são stateless). `register_yubico_applets` permanece como alias dos dois primeiros para compatibilidade.
- `yubico_management::SUPPORTED_CAPABILITIES` atualizada para `0x0624 | 0x02 (PIV) | 0x08 (OPENPGP)` = `0x062E` quando os stubs existem? Decisão: **não** alterar bits até PIV/OpenPGP ganharem implementação real; manter `0x0624` e documentar que bits adicionais virão com funcionalidade. Isso evita falsa promessa a hosts que já filtram por capability.

Referências: `firmware/device-profile/src/profile.rs:166`, `firmware/authenticator/src/authenticator.rs:312`, `firmware/transport/src/multitransport.rs`, `firmware/authenticator/src/yubico_piv.rs`, `firmware/authenticator/src/yubico_openpgp.rs`.

## Consequências

- Integradores podem declarar `DeviceProfileBuilder::new().transport_config(usb_hid()).add_transport(usb_ccid()).add_transport(nfc())` e obter um `EmbeddedAuthenticator` com 3 transportes ativos; `just hardware-check` continuará validando HID+CCID como antes.
- `profile.transport_config` legado permanece válido (primeiro da lista); testes existentes não quebram.
- CardRouter passa a demonstrar 4 vias protocolares distintas no mesmo slot CCID, viabilizando `tools/hardware_check.py --json` a validar `SELECT` de cada AID e habilitando fase posterior de PIV/OpenPGP reais sem mudar roteamento.
- Complexidade de ciclo de vida: `MultiTransport::send/recv` precisa escolher transporte; hoje escolhe o primeiro que não retorna `NotInitialized/Closed` (first-success). Futuro pode exigir roteamento por interface (HID vs CCID) — ADR complementar quando NFC/BLE ganharem drivers reais.
- Sem `unsafe` novo; applets stub são `no_std` compatíveis.
