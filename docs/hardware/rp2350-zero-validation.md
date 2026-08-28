# Runbook de Validação de Hardware — Waveshare RP2350-Zero

> **Este é um runbook (checklist), não um relatório:** nenhum passo abaixo foi
> executado em hardware real. Todos os itens permanecem `[ ]` até a validação
> física acontecer.
>
> Board: [Waveshare RP2350-Zero](https://www.waveshare.com/wiki/RP2350-Zero) —
> RP2350A (dual-core Cortex-M33, TrustZone, OTP, TRNG), 150 MHz, 520 KB SRAM,
> cristal de **12 MHz**, USB Type-C (USB 1.1 device, porta única), WS2812B no
> **GPIO16** via PIO, botões BOOT (linha CS da flash QSPI) e RUN (reset),
> SWD exposto nos pads de debug. Perfil Rust correspondente:
> `board_generic::profiles::RP2350_ZERO`
> (`firmware/board-generic/src/profiles.rs`).

---

## 1. Requisitos

### Hardware

- [ ] Placa Waveshare RP2350-Zero
- [ ] Cabo USB-C **com dados** (cabo só-de-carga não enumera USB)
- [ ] Opcional: debugger SWD (ex.: Raspberry Pi Debug Probe / CMSIS-DAP) — os
      pads de debug da placa expõem SWD, habilitando `probe-rs`

### Software

- [ ] Rust estável + target de compilação cruzada instalado:

  ```powershell
  rustup target list --installed   # deve conter thumbv8m.main-none-eabihf
  rustup target add thumbv8m.main-none-eabihf   # se ausente
  ```

- [ ] `probe-rs` **ou** `picotool` (para gravação/inspeção):

  ```powershell
  # probe-rs (https://probe.rs)
  cargo install probe-rs-tools --locked
  probe-rs --version

  # picotool (build a partir de https://github.com/raspberrypi/picotool
  # ou binário pré-compilado do pico-sdk)
  picotool version
  ```

> **Pré-instalado nesta máquina (2026-08-22):** `probe-rs 0.32.0`
> (`probe-rs`, `cargo-flash`, `cargo-embed` — chip `RP235x` confirmado em
> `probe-rs chip list`) e `elf2uf2-rs`.
>
> **Artefato já gerado:** UF2 pronto para drag-and-drop em
> `examples\rp2350-firmware\target\thumbv8m.main-none-eabihf\release\rp2350-firmware.uf2`
> (regenerar com o comando da seção 2 após qualquer mudança de firmware).
>
> **Nota de correção:** o runner do crate (`cargo run`) usava
> `--chip RP2350`, nome que o probe-rs não reconhece; corrigido para
> `--chip RP235x` em `examples/rp2350-firmware/.cargo/config.toml`.

### picotool nesta máquina

**picotool 2.3.0 (suporte completo a RP2350)** compilado do código-fonte
(2026-08-22; MinGW GCC + libusb 1.0.30 + Pico SDK 2.1.1 — o upstream não
publica binários Windows) e instalado em
`C:\Users\zequi\.cargo\bin\picotool.exe` (com `libusb-1.0.dll` ao lado).
Resolve antes do `picotool.exe` 1.1.2 legado que acompanha o
`pico-setup-windows` em `C:\Program Files\Raspberry Pi\...` (fora do PATH).

- `picotool info -a` (Método A da seção 5): **funciona** com a placa em modo
  BOOT
- `picotool uf2 convert`: disponível; a UF2 já gerada por `elf2uf2-rs`
  permanece válida

---

## 2. Build

O crate `rp2350-firmware` é **standalone** (workspace próprio, fora do
workspace raiz), então o build é feito a partir do diretório dele:

```powershell
cd examples\rp2350-firmware
cargo build -p rp2350-firmware --release
```

- [ ] Build conclui sem erros
- [ ] ELF gerado em
      `examples\rp2350-firmware\target\thumbv8m.main-none-eabihf\release\rp2350-firmware`

> **Nota sobre o alias `cargo build-rp2350`** (raiz do repositório): ele
> compila apenas a crate `transport` para o target RP2350 (`build -p transport
> --target thumbv8m.main-none-eabihf ...`) — útil como sanity check das libs,
> mas **não produz o ELF do firmware**. O ELF vem do comando acima.

### Conversão ELF → UF2 (necessária apenas para gravação via mass-storage)

```powershell
picotool uf2 convert target\thumbv8m.main-none-eabihf\release\rp2350-firmware -t elf `
    openkey-rp2350.uf2 -t uf2
# Para automação:
# picotool uf2 convert <elf> -t elf <out> -t uf2
```

---

## 3. Gravação via UF2 (drag-and-drop, sem debugger)

Procedimento do wiki da Waveshare (BOOTSEL entra no modo download da Boot ROM):

1. [ ] Com a placa **desconectada** do USB, segurar o botão **BOOT**
2. [ ] Conectar o cabo USB-C ao PC **mantendo BOOT pressionado**
     (alternativa equivalente: com a placa já conectada, segurar **BOOT** e
     dar um toque em **RESET**, soltando BOOT depois)
3. [ ] Confirmar que aparece uma unidade de massa chamada **RP2350**
4. [ ] Copiar `target\thumbv8m.main-none-eabihf\release\rp2350-firmware.uf2`
     para essa unidade — a placa reinicia sozinha ao término da cópia e a
     unidade some

---

## 4. Gravação via probe-rs (SWD)

Requer debugger ligado aos pads SWD da placa:

```powershell
cd examples\rp2350-firmware
probe-rs download --chip RP235x target\thumbv8m.main-none-eabihf\release\rp2350-firmware
probe-rs reset --chip RP235x
```

- [ ] `download` conclui sem erros
- [ ] `reset` reinicia a placa executando o firmware

---

## 5. Verificação pós-flash

### Tamanho real da flash (resolver discrepância documental)

Há uma **discrepância nas fontes**: o wiki da Waveshare e o DTS do Zephyr
indicam flash NOR de **4 MB**, mas o esquemático lista a memória
**W25Q16JVUXIQ = 16 Mbit = 2 MB**. Nenhum dos números foi assumido no código —
registrar aqui o valor medido:

- [ ] **Método A — `picotool`** (definitivo; v2.3.0 instalada localmente —
      ver seção "picotool nesta máquina"):

  Com a placa no modo BOOT (seção 3, passos 1–3):

  ```powershell
  picotool info -a
  ```

- [ ] **Método B — `probe-rs read`** (alternativa sem picotool; requer debugger
      SWD da seção 4). O flash fica mapeado em XIP a partir de `0x10000000`:

  ```powershell
  # Último setor de uma flash de 2 MB (0x101FF000) e de 4 MB (0x103FF000):
  probe-rs read b32 0x101FF000 4 --chip RP235x
  probe-rs read b32 0x103FF000 4 --chip RP235x
  ```

  Interpretação: numa W25Q16JV (2 MB), o acesso em `0x10200000+` espelha
  (*aliasing*) ou falha — as duas leituras retornam conteúdo idêntico ou erro.
  Numa flash de 4 MB, `0x103FF000` retorna o conteúdo real do último setor.
  > Cuidado: o comportamento de *aliasing* depende do controlador QSPI; este
  > método é **indicativo**. Em caso de ambiguidade, usar o método A.

- [ ] **Método C — capacidade da unidade USB** (sanity check instantâneo, zero
      tooling): com a placa no modo BOOT, conferir a capacidade que o Windows
      reporta para a unidade de massa **RP2350**:

  ```powershell
  Get-Volume | Where-Object DriveType -eq 'Removable' |
      Format-Table DriveLetter, SizeRemaining, Size -AutoSize
  ```

  A ROM reporta o tamanho real do chip como capacidade da unidade.

- [ ] Registrar o valor medido: `________ MB`
      (esperado 2 MB se for a W25Q16JV; corrigir este runbook e o perfil, se
      necessário, após a medição)

### Enumeração USB no Windows

O firmware tem duas identidades USB, escolhidas em tempo de compilação:

| Build | VID:PID | Finalidade |
|-------|---------|------------|
| Padrão (distribuição) | `1209:0001` (pid.codes do openkey-fido2) | identidade própria do projeto |
| Opt-in `--features yubikey5-identity` / `--features yubikey4-identity` (alias, ADR-0025) | `1050:0407` (Yubico YubiKey 4/5 — família `1050:0407` no modo OTP+FIDO+CCID) | reconhecimento automático por ykman / Yubico Authenticator (casamento por VID/PID) — **NÃO PARA DISTRIBUIÇÃO** |

> Vendor do profile `YUBIKEY_4_5` é `Yubikey 4/5` (`board_generic::YUBIKEY_4_5`, `device_profile::UsbIdentity::yubikey()` → `1050:0407`) com **Secure Boot ✅** (`secure_boot`) + **Secure Lock ✅** (`debug_disable+otp+unique_id+tamper`).

> A UF2 padrão desta máquina (`rp2350-firmware.uf2`) usa a identidade
> pid.codes. A variante YubiKey 4/5 é gerada com
> `cargo build --release --features yubikey5-identity` (ou `yubikey4-identity`, mesmo `1050:0407`) e destina-se apenas a
> testes privados. Firmware atual é **composto HID+CCID** (duas interfaces
> sobre um único `UsbDevice`): interface 0 HID/CTAPHID (`0xF1D0`) +
> interface 1 CCID/SmartCard T=0 com applets OATH (`A0000005272101`), Management (`A000000527471117`), PIV e OpenPGP (via `register_multiprotocol_applets`). Não há interface OTP.

Dispositivo composto esperado (HID `0xF1D0` + CCID `0x0B`):

- [ ] PowerShell — HID (identidade padrão):

  ```powershell
  Get-PnpDevice | Where-Object { $_.InstanceId -match 'VID_1209&PID_0001' } |
      Format-List FriendlyName, Class, Status
  ```

- [ ] PowerShell — HID (variante opt-in):

  ```powershell
  Get-PnpDevice | Where-Object { $_.InstanceId -match 'VID_1050&PID_0407' } |
      Format-List FriendlyName, Class, Status
  ```

  Esperado em ambos: entrada **HID** classe *Human Interface Device*,
  status `OK`. No composto há também um **leitor CCID** enumerado como
  *Smart Card* / *Leitor USB* (mesma VID:PID, interface 1). Conferir:

  ```powershell
  Get-PnpDevice | Where-Object { $_.Class -eq 'SmartCardReader' } |
      Format-List FriendlyName, InstanceId, Status
  # ou
  Get-PnpDevice | Where-Object { $_.InstanceId -match 'VID_1209' } |
      Format-Table FriendlyName, Class, Status -AutoSize
  ```

- [ ] Alternativa visual: **Gerenciador de Dispositivos** → "Dispositivos de
      Interface Humana" (HID FIDO) **e** "Leitores de cartão inteligente"
      (CCID) contêm as duas interfaces do composto sob a mesma VID:PID.

- [ ] Validação automatizada (HID+CCID+applets):

  ```powershell
  python tools/hardware_check.py
  # ou: just hardware-check
  # saída JSON: python tools/hardware_check.py --json
  #             just hardware-check-json
  ```

  Esperado: `ctap_ok=true`, `readers` contém o leitor CCID com ATR T=0
  (`3B DA ... 6F 70 65 6E...`), `select_oath` e `select_management` com
  `sw=9000` (ou payload de versão/desafio no SELECT).

---

## 6. Teste funcional CTAPHID

> `tools/ctaphid_bridge.py` depende de **UHID (Linux)** e não funciona no
> Windows. No Windows, validar via navegador (item abaixo) ou comparar o
> comportamento com o simulador host (`cargo run -p fido2-simulator`) como
> referência de resposta.

### GetInfo esperado

- [ ] `options`: `clientPin: true`; opção **`uv` AUSENTE** — a placa não tem
      sensor biométrico e não há built-in UV implementado; user verification
      acontece só via PIN/pinUvAuthToken
- [ ] Algoritmos anunciados: **ES256, Ed25519, RS256**
- [ ] `firmwareVersion` presente (mapeamento determinístico do perfil)

### Fluxo browser (Windows)

- [ ] Abrir <https://webauthn.io>, registrar uma credencial — o browser deve
      acionar o token (popup de toque)
- [ ] Autenticar (login) com a credencial registrada

### User presence via BOOT

- [ ] Durante um registro/login, **tocar BOOT**: a operação prossegue
      (`up=0x01` na assertion)
- [ ] Repetir **sem tocar**: a operação termina com
      `CTAP2_ERR_OPERATION_DENIED` (timeout de presença)

---

## 7. Persistência física (Yubico Authenticator + reboot)

A partir do incremento da flash QSPI física, o firmware grava o estado dos
applets (serial do Management e credenciais OATH) na **região reservada de
128 KiB no fim da flash real** — tamanho probeado via Boot ROM
(`FLASH_DEVINFO`/`cs0_size`), resolvendo em runtime a discrepância W25Q16
(2 MiB) × wiki (4 MiB) da seção 5. Dois slots com geração monótona dão
recuperação de power-loss (`FlashStorageBackend`).

Procedimento de validação:

- [ ] Gravar `rp2350-firmware.uf2` (seção 3) e confirmar enumeração USB (seção 5)
- [ ] Abrir o **Yubico Authenticator** (ou `ykman oath accounts list`) e
      confirmar que o dispositivo aparece via PCSC
- [ ] Adicionar uma credencial TOTP de teste no app (qualquer issuer/nome;
      usar segredo conhecido para conferir o código depois)
- [ ] Anotar o código TOTP exibido: `________`
- [ ] Desligar/religar a placa (power cycle REAL — puxar o cabo USB)
- [ ] Reabrir o Yubico Authenticator: credencial **presente** e código
      consistente com o mesmo segredo ✓
- [ ] Repetir o reboot 3× para exercitar o two-slot commit (cada alteração
      alterna o slot ativo)
- [ ] Opcional (`ykman info`): serial reportado é o MESMO antes/depois do
      reboot (identidade estável persistida)

> Se a credencial sumir após o reboot: verificar com o Método A/B/C da
> seção 5 se o tamanho probeado confere; um tamanho errado deslocaria a
> região. Registrar o resultado aqui: ________________

---

## 8. Ainda não verificado (honesto)

Itens que este runbook **não cobre** e continuam em aberto:

- [ ] WS2812B (GPIO16) como `StatusLed`: a trait existe em
      `transport::embedded`, mas falta o driver PIO; hoje o LED não reflete
      estados do autenticador
- [ ] Conformidade FIDO oficial (FIDO Conformance Tool) — requer ambiente
      Linux/UHID + acesso às ferramentas da FIDO Alliance
- [ ] TrustZone / secure boot / OTP efetivamente configurados no binário
      (hoje o perfil declara as capacidades do silício, não o uso delas)
- [ ] TRNG contínuo do RP2350 substituindo o PRNG semeado por boot
      (BootRandom/splitmix64): necessário antes de produção com nonces ECDSA
