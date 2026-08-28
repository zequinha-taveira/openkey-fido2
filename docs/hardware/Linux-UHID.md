# Pipeline Linux UHID — fido2-simulator → /dev/uhid → Browser / FIDO Conformance Tool

> **Escopo:** validação virtual sem hardware físico. O mesmo `EmbeddedAuthenticator`
> que compila para RP2350 roda como `fido2-simulator --raw-cbor` e é exposto ao OS
> como HID FIDO via UHID (Linux-only). Ver `BUILD.md:160` (Virtual CTAPHID Bridge)
> e `TODO.md:284` (Conformance Tool requer registro).

---

## Arquitetura

```
fido2-simulator --raw-cbor  (EmbeddedAuthenticator, CBOR length-prefixed)
        ↕  stdin/stdout  2 bytes len + 1 byte cmd + CBOR  (simulator/src/main.rs)
tools/ctaphid_bridge.py     (framing CTAPHID 64B §8.2 + wrapping CBOR §6.1)
        ↕  /dev/uhid  (UHID_CREATE2, report descriptor 0xF1D0, 64B reports)
Kernel hidraw / hiddev
        ↕  CTAPHID (CID, CMD_INIT/PING/CBOR/ERROR)
Chrome / webauthn.io / FIDO Conformance Tool
```

* Framing puro testável em qualquer OS: `tools/ctaphid_bridge.py:40` (`CTAPHID_PACKET_SIZE=64`,
  `CTAPHID_INIT_PAYLOAD=57`, `CTAPHID_CONT_PAYLOAD=59`, `FIDO_REPORT_DESCRIPTOR` `0xF1D0`)
  + `tests/python/test_ctaphid_bridge.py:1` (19 testes).
* Self-test sem UHID: `tools/ctaphid_bridge.py:488` `self_test()` (fragmentação multi-pacote,
  handshake `CMD_INIT`, round-trip `GetInfo`, dispatch via `RecordingUhid`).

---

## Pré-requisitos (Linux)

- Kernel com `CONFIG_UHID=y` (`/dev/uhid` existe)
- `cargo`, `python3`, `fido2`, `pytest`
- Permissão para `/dev/uhid` (grupo `plugdev` ou `sudo`)

```bash
ls -l /dev/uhid
cargo build -p fido2-simulator
pip install fido2 pytest
```

---

## 1. Host-gate (sem UHID, CI Windows/Linux)

```bash
python -m pytest tests/python/test_ctaphid_bridge.py -v   # 19 passed
PYTHONIOENCODING=utf-8 python tools/ctaphid_bridge.py --self-test  # 5/5
# ou via just:
just hardware-uhid-bridge
```

---

## 2. Bridge UHID (requer Linux + /dev/uhid)

```bash
sudo python tools/ctaphid_bridge.py
# ou com simulador explícito:
sudo python tools/ctaphid_bridge.py --simulator ./target/debug/fido2-simulator

# Verificar criação do hidraw:
ls -l /dev/hidraw*
dmesg | tail  # deve mostrar "openkey-fido2" 1209:0001
```

O processo cria o dispositivo `openkey-fido2` `VID 1209 PID 0001` (pid.codes) e
faz proxy `CtaphidBridge.run()` `tools/ctaphid_bridge.py:391`:
`UHID_OUTPUT` (host → device) → `Assembler` → `CTAP2` → `sim.send_raw()` →
`ctap2_response_encode` → `fragment()` → `UHID_INPUT` (device → host).

Debug `CtaphidBridge.handle_packet` cobre `CMD_INIT` → `ChannelManager.build_init_response`
`tools/ctaphid_bridge.py:209`, `CMD_PING` echo, `CMD_CBOR` → `sim.send_raw`,
desconhecido → `CMD_ERROR` `ERR_INVALID_CMD`.

Encerrar com `Ctrl-C` (destroy UHID + `sim.close()`).

---

## 3. Chrome / webauthn.io (manual checklist)

- [ ] Bridge ativo (`sudo python tools/ctaphid_bridge.py` rodando)
- [ ] Chrome `chrome://device-log` mostra `openkey-fido2` HID conectado
- [ ] Abrir https://webauthn.io → **Register** → popup de toque (user presence
      via `SimulatedPresence` `python/openkey_core/src/lib.rs:17` ou BOOTSEL no HW)
- [ ] **Authenticate** → assertion com `signCount` incrementado
- [ ] `tools/hardware_check.py` valida pós-bridge:
  ```bash
  python tools/hardware_check.py          # CTAPHID ping OK + GetInfo
  python tools/hardware_check.py --json   # JSON para CI
  just hardware-check
  ```

`fido2.hid.CtapHidDevice.list_devices()` `tools/hardware_check.py:28` enumera o
hidraw virtual; `CTAP2(dev).get_info()` deve retornar `versions ["FIDO_2_0","FIDO_2_1"]`,
`aaguid`, `options {rk, up, clientPin}`.

---

## 4. FIDO Conformance Tool (registro requerido)

> `TODO.md:284` — a FIDO Alliance exige registro de participante para baixar o
> FIDO2 Conformance Test Tool. Nenhuma ferramenta oficial está vendida no repo.

Passos após registro (https://fidoalliance.org/certification/functional-certification/conformance/):

- [ ] Baixar e instalar o **FIDO2 Server Conformance Tool** (ou **Authenticator
      Conformance**)
- [ ] Bridge UHID ativo (seção 2)
- [ ] Configurar o Tool para usar **HID authenticator** (auto-descoberta via hidraw)
- [ ] Rodar suíte **CTAP2** — esperado:
  - `GetInfo` com `pinUvAuthProtocols [1,2]`, `maxMsgSize 1200`, sem `uv` (sem built-in UV)
  - `MakeCredential`/`GetAssertion` com `hmac-secret` `tests/python/conformance/test_hmac_secret.py:1`
  - `ClientPIN` `tests/python/conformance/test_client_pin.py:1` (protocolos 1 e 2)
  - `CredentialManagement` `tests/python/conformance/test_credential_management.py:1`
- [ ] Exportar relatório e arquivar em `docs/conformance/`

Enquanto o acesso não é liberado, a cobertura host é garantida por
`tests/python/conformance/` (12 arquivos, `pytest tests/python/conformance/ -v`)
e `tests/python/diagnostics/` `just diagnose` (23 falhas injetadas, golden master
`wire_baseline.json`).

---

## Troubleshooting

| Sintoma | Causa | Solução |
|---------|-------|---------|
| `/dev/uhid` não existe | Kernel sem CONFIG_UHID | `modprobe uhid` ou kernel com UHID |
| `Permission denied /dev/uhid` | Sem permissão | `sudo` ou `sudo chmod 0660 /dev/uhid; sudo usermod -aG plugdev $USER` |
| `fido2-simulator não encontrado` | Não compilado | `cargo build -p fido2-simulator` |
| `UnicodeEncodeError` no self-test (Windows cp1252) | Console não UTF-8 | `PYTHONIOENCODING=utf-8 python tools/ctaphid_bridge.py --self-test` |
| Bridge não aparece no Chrome | UHID não criado | `dmesg` + `ls /dev/hidraw*`, verificar `FIDO_REPORT_DESCRIPTOR` `0xF1D0` |

---

## Referências

- `BUILD.md:160` — Virtual CTAPHID Bridge (Linux/UHID)
- `TODO.md:283` — validação física pendente (probe-rs, UHID real, Conformance Tool)
- `TODO.md:284` — Conformance Tool requer registro
- `tools/ctaphid_bridge.py:1` — implementação (framing, Assembler, ChannelManager, Simulator, CtaphidBridge)
- `tools/hardware_check.py:1` — validação pós-flash HID+CCID
- `docs/hardware/rp2350-zero-validation.md:1` — runbook físico RP2350-Zero
- `docs/adr/ADR-0012-fido-conformance-e-raw-cbor-interface.md` — decisão raw CBOR
- `docs/adr/ADR-0009-ctaphid-framing-e-hardware-transports.md` — framing CTAPHID
