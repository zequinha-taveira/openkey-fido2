# ADR-0025: Vendor YubiKey 4/5 — identidade USB 1050:0407 e Secure Boot/Lock

Status: accepted
Data: 2026-08-27

## Contexto

O firmware foi projetado para ser compatível com o ecossistema YubiKey (ykman, Yubico Authenticator, `python-yubikit`):

- Dispositivo composto HID (`0xF1D0`) + CCID T=0 sobre único `UsbBusAllocator` em `examples/rp2350-firmware/src/composite.rs:75`.
- Roteador ISO 7816-4 `transport::iso7816::CardRouter` com applets `OATH A0000005272101` e `Management A000000527471117`, estendidos para `PIV A000000308000010000100` e `OpenPGP D27600012401` em `firmware/authenticator/src/multiprotocol.rs`.
- `SUPPORTED_CAPABILITIES 0x0624` e `READ CONFIG 0x1D` já casam com `ManagementSession` do `python-yubikit`.
- Forma estendida `Le=0000→65536`, `dwFeatures bit17 extended APDU`, `61XX/0xC0` e `wLevelParameter 0/1` já compatíveis com Yubico Authenticator (`firmware/transport/src/embedded/usb_ccid_backend.rs:471`, `transport::iso7816`).

Faltava um **perfil de produto YubiKey 4/5** explícito: `VID:PID 1050:0407` (OTP+FIDO+CCID, `composite.rs:50`), strings `Yubico / YubiKey 5` (ykman deriva PID por substring `yubico+yubikey` em `tools/hardware_check.py:271`), e flags `Secure Boot: ✅ / Secure Lock: ✅` mapeadas nos `SecurityFeatures`.

Alternativas:
1. Manter só `yubikey5-identity` como feature ad-hoc — rejeitada: não modela YubiKey 4 nem permite `DeviceProfile` escolher VID/PID sem recompilar com feature distinta.
2. Adicionar `vid/pid` em `BoardDefinition` (HAL) — rejeitada: VID/PID é decisão de **produto**, não de pinagem/silício; pertence a `DeviceProfile`.
3. Novo `SecurityFeatures::yubikey()` separado de `rp2350()` — aceita: YK4/5 exige `tamper_detection=true` (secure lock completo) enquanto `rp2350()` mantém `false` para o board genérico.

Restrições:
- `0x1050` é VID da Yubico (USB-IF). Uso só opt-in `NÃO PARA DISTRIBUIÇÃO` (já documentado em `composite.rs:31` e `Cargo.toml:26`).
- `tamper_detection` no RP2350A é declaração de capacidade (sem pino dedicado); vale como `Secure Lock` lógico até prova física (`docs/hardware/rp2350-zero-validation.md:317`).

## Decisão

**Vendor YubiKey 4/5:**
- `UsbIdentity { vid: 0x1050, pid: 0x0407 }` em `firmware/device-profile/src/profile.rs` como parte de `DeviceProfile.usb` (`Option<UsbIdentity>`). Builder: `vendor_name("Yubico").product_name("YubiKey 4/5").usb_vid_pid(0x1050,0x0407)`.
- `SecurityFeatures::yubico()` (`firmware/board-generic/src/board_generic.rs:75`) — 8/8 `true` (`secure_boot, trust_zone, hardware_rng, sha256_accelerator, debug_disable, otp_memory, unique_id, tamper_detection`). `Secure Boot: ✅` → `secure_boot=true` (Boot ROM `IMAGE_DEF::secure_exe()` em `main.rs:166`); `Secure Lock: ✅` → `debug_disable+otp_memory+unique_id+tamper_detection=true`.
- Perfil `YUBIKEY_4_5: BoardDefinition` em `firmware/board-generic/src/profiles.rs:227` sobre `rp2350_with_pins` + `security_features(yubico())` + `presence_source(Bootsel)`, AAGUID `...06`→`...07`, `led 16`, `button u8::MAX` (igual `RP2350_ZERO`).
- `rp2350-firmware` expõe `yubikey4-identity` como alias de `yubikey5-identity` (`Cargo.toml:33`), `composite.rs:66` literal `YubiKey 5` mantido como `YubiKey 4/5`-compatível (ykman casa por substring), e `main.rs:214` migra de `register_yubico_applets` (2) para `register_multiprotocol_applets` (4).

## Consequências

- `DeviceProfileBuilder::from_board(&YUBIKEY_4_5).vendor_name("Yubico").usb_vid_pid(0x1050,0x0407).build()` produz `capabilities.security.secure_boot==true && debug_disable==true && tamper_detection==true` reportado em `GetInfo.security` (`protocol/ctap2/src/ctap2.rs:1951`).
- `cargo build --features yubikey5-identity` (ou `yubikey4-identity`) enumera `1050:0407 Yubico YubiKey 5 0` (compatível com `ykman list --serials` e Yubico Authenticator); sem feature enumera `1209:0001 openkey-fido2` (pid.codes).
- Sem `unsafe` novo; `YUBIKEY_4_5` é `const` puro, `UsbIdentity` é `Copy + PartialEq`.
- Validação física de secure boot/OTP/TrustZone permanece `🚧` (`runbook` §8); `TRNG contínuo` segue dev-only `BootRandom+splitmix64` (`main.rs:118`).

Referências: `firmware/board-generic/src/board_generic.rs:54`, `firmware/board-generic/src/profiles.rs:187`, `firmware/device-profile/src/profile.rs:148`, `examples/rp2350-firmware/src/composite.rs:66`, `firmware/authenticator/src/multiprotocol.rs:21`.
