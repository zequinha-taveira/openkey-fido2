"""Ponte de automação/integração openkey-fido2 ↔ PC.

Valida pós-flash em uma passada usando ferramentas neutras de padrão
(python-fido2, PC-SC genérico, OpenSC) e opcionais de fabricante (ykman):
  1. HID FIDO enumerável + CTAPHID vivo (INIT/PING via python-fido2)
  2. CTAP2 GetInfo pela camada HID (quando disponível)
  3. CCID/PCSC: leitor presente, status do cartão e ATR (via winscard/ctypes
     — acesso padrão neutro ISO 7816-4)
  4. Applets ISO 7816: SELECT por AID (OATH, Management, PIV, OpenPGP)
  5. Sondas de host: opensc-tool (OpenSC neutro), python-fido2 e ykman (opcional fabricante)

Nota sobre identidades USB:
  The default USB identity pid.codes is 0x1209:0x0001; the YubiKey USB identity
  that ykman / Yubico Authenticator auto-recognize is the opt-in VID:PID=Yubikey5
  (0x1050:0x0407, Product Name: "Yubico Yubikey" / "YubiKey OTP+FIDO+CCID") build,
  not for distribution.

Uso: python tools/hardware_check.py [--json] [--ykman-timeout S] [--opensc-timeout S]
"""

import argparse
import ctypes
import json
import subprocess
import sys

IDENTITY_NOTE = (
    "The default USB identity pid.codes is 0x1209:0x0001; "
    "the YubiKey USB identity that ykman / Yubico Authenticator auto-recognize "
    "is the opt-in VID:PID=Yubikey5 (0x1050:0x0407) build, not for distribution."
)

OATH_AID = bytes.fromhex("A0000005272101")
MGMT_AID = bytes.fromhex("A000000527471117")
PIV_AID = bytes.fromhex("A000000308000010000100")
OPENPGP_AID = bytes.fromhex("D27600012401")

PCSC_ERROR_MESSAGES = {
    "0x80100066": "SCARD_W_REMOVED_CARD (cartão ausente no slot CCID ou ATR ainda não respondido)",
    "0x8010000c": "SCARD_E_NO_SMARTCARD (nenhum cartão presente no leitor)",
    "0x80100069": "SCARD_W_UNRESPONSIVE_CARD (cartão não responde / mute)",
    "0x80100068": "SCARD_W_RESET_CARD (cartão sofreu reset)",
}


def check_fido2_lib():
    """Verifica se a biblioteca neutra de padrão python-fido2 está disponível no host."""
    out = {"present": False, "version": None}
    try:
        from importlib.metadata import version

        v = version("fido2")
        out["present"] = True
        out["version"] = v
    except Exception:
        try:
            import fido2

            out["present"] = True
            out["version"] = getattr(fido2, "__version__", "instalada")
        except Exception:
            pass
    return out


def check_opensc(timeout=10.0):
    """Sonda a ferramenta neutra padrão da indústria opensc-tool (OpenSC)."""
    out = {"present": False, "version": None}
    try:
        proc = subprocess.run(
            ["opensc-tool", "--version"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode == 0:
            lines = (proc.stdout or "").strip().splitlines()
            out["present"] = True
            out["version"] = lines[0].strip() if lines and lines[0].strip() else None
    except Exception:
        pass
    return out


# ---------------------------------------------------------------- HID / CTAP


def check_hid():
    out = {"hid_devices": [], "ctap_ok": False, "get_info": None}
    try:
        from fido2.hid import CtapHidDevice

        devs = list(CtapHidDevice.list_devices())
        for d in devs:
            desc = d.descriptor
            vid_hex = hex(desc.vendor_id)
            pid_hex = hex(desc.product_id)
            flavor = "desconhecido"
            if desc.vendor_id == 0x1209 and desc.product_id == 0x0001:
                flavor = "openkey (default)"
            elif desc.vendor_id == 0x1050 and desc.product_id == 0x0407:
                flavor = "yubikey (opt-in 1050:0407, não para distribuição)"
            out["hid_devices"].append(
                {
                    "path": str(desc.path),
                    "vid": vid_hex,
                    "pid": pid_hex,
                    "product": desc.product_name,
                    "identity_flavor": flavor,
                }
            )
        if not devs:
            return out
        # Primeiro dispositivo: valida CTAPHID com ping (responde eco).
        dev = devs[0].open()
        try:
            echo = dev.ping(b"openkey-ping")
            out["ctap_ok"] = echo == b"openkey-ping"
            try:
                try:
                    from fido2.ctap2 import CTAP2
                except ImportError:
                    from fido2.ctap2 import Ctap2 as CTAP2

                info = CTAP2(dev).get_info()
                out["get_info"] = {
                    "versions": list(info.versions),
                    "aaguid": info.aaguid.hex(),
                    "algorithms": [str(a) for a in getattr(info, "algorithms", [])],
                    "options": dict(getattr(info, "options", {}) or {}),
                }
            except Exception as e:  # CTAP2 pode não estar implementado ainda
                out["get_info"] = f"CTAP2 indisponível: {e}"
        finally:
            dev.close()
    except Exception as e:
        out["error"] = repr(e)
    return out


# ---------------------------------------------------------------- CCID/PCSC
# PC/SC via ctypes — Windows (winscard.dll) + Linux (libpcsclite.so.1).
# Sem dependência de pyscard; fido2.hid já é cross-platform (hidraw no Linux).

SCARD_S_SUCCESS = 0x00000000
SCARD_SCOPE_USER = 0
SCARD_SHARE_SHARED = 2
SCARD_PROTOCOL_T0 = 1
SCARD_STATE_UNAWARE = 0x0000
SCARD_STATE_PRESENT = 0x0020
SCARD_STATE_MUTE = 0x0400


def _load_pcsc():
    """Carrega a biblioteca PC/SC da plataforma e normaliza `SCard*`."""

    # SCARDCONTEXT/SCARDHANDLE são ULONG_PTR (64 bits no Win64); usar
    # c_ulong (32 bits) trunca o handle e SCardConnect falha com 0x6
    # (ERROR_INVALID_HANDLE). Usa c_size_t para largura de ponteiro.
    ULONG_PTR = ctypes.c_size_t

    if sys.platform.startswith("win"):
        mod = ctypes.windll.winscard
        # Winscard expõe variantes ANSI `*A`; Linux pcsclite usa nomes sem sufixo.
        mod.SCardEstablishContext.argtypes = [
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ULONG_PTR),
        ]
        mod.SCardEstablishContext.restype = ctypes.c_long
        mod.SCardListReadersA.argtypes = [
            ULONG_PTR,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        mod.SCardListReadersA.restype = ctypes.c_long
        mod.SCardConnectA.argtypes = [
            ULONG_PTR,
            ctypes.c_char_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.POINTER(ULONG_PTR),
            ctypes.POINTER(ctypes.c_ulong),
        ]
        mod.SCardConnectA.restype = ctypes.c_long
        mod.SCardStatusA.argtypes = [
            ULONG_PTR,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        mod.SCardStatusA.restype = ctypes.c_long
        mod.SCardTransmit.argtypes = [
            ULONG_PTR,
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        mod.SCardTransmit.restype = ctypes.c_long
        mod.SCardDisconnect.argtypes = [ULONG_PTR, ctypes.c_ulong]
        mod.SCardDisconnect.restype = ctypes.c_long
        mod.SCardReleaseContext.argtypes = [ULONG_PTR]
        mod.SCardReleaseContext.restype = ctypes.c_long
        # Alias sem sufixo para código unificado
        mod.SCardListReaders = mod.SCardListReadersA
        mod.SCardConnect = mod.SCardConnectA
        mod.SCardStatus = mod.SCardStatusA
        return mod

    # Linux / macOS — libpcsclite
    for name in ("libpcsclite.so.1", "libpcsclite.so", "libpcsclite.dylib"):
        try:
            mod = ctypes.CDLL(name)
            break
        except OSError:
            continue
    else:
        raise OSError("libpcsclite não encontrada (instale pcsc-lite)")

    mod.SCardEstablishContext.argtypes = [
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ULONG_PTR),
    ]
    mod.SCardEstablishContext.restype = ctypes.c_long
    mod.SCardListReaders.argtypes = [
        ULONG_PTR,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    mod.SCardListReaders.restype = ctypes.c_long
    mod.SCardConnect.argtypes = [
        ULONG_PTR,
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.POINTER(ULONG_PTR),
        ctypes.POINTER(ctypes.c_ulong),
    ]
    mod.SCardConnect.restype = ctypes.c_long
    mod.SCardStatus.argtypes = [
        ULONG_PTR,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    mod.SCardStatus.restype = ctypes.c_long
    mod.SCardTransmit.argtypes = [
        ULONG_PTR,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    mod.SCardTransmit.restype = ctypes.c_long
    mod.SCardDisconnect.argtypes = [ULONG_PTR, ctypes.c_ulong]
    mod.SCardDisconnect.restype = ctypes.c_long
    mod.SCardReleaseContext.argtypes = [ULONG_PTR]
    mod.SCardReleaseContext.restype = ctypes.c_long
    return mod


def _winscard():
    # Compatibilidade: código legado chamava _winscard()
    return _load_pcsc()


class SCARD_IO_REQUEST(ctypes.Structure):
    _fields_ = [("dwProtocol", ctypes.c_ulong), ("cbPciLength", ctypes.c_ulong)]


def check_ccid(apdu_checks=True):
    out = {"readers": [], "applets": {}}
    try:
        sc = _load_pcsc()
    except Exception as e:
        # Sem PC/SC instalado — não é erro fatal; mantém JSON compatível para CI.
        out["error"] = f"PC/SC indisponível: {e}"
        out["platform"] = sys.platform
        return out
    ctx = ctypes.c_size_t()
    if sc.SCardEstablishContext(SCARD_SCOPE_USER, None, None, ctypes.byref(ctx)) != SCARD_S_SUCCESS:
        out["error"] = "SCardEstablishContext falhou (serviço Smart Card ativo?)"
        out["platform"] = sys.platform
        return out
    try:
        length = ctypes.c_ulong(0)
        rc = sc.SCardListReaders(ctx, None, None, ctypes.byref(length))
        if rc != SCARD_S_SUCCESS or not length.value:
            out["error"] = "nenhum leitor PCSC"
            out["platform"] = sys.platform
            return out
        buf = ctypes.create_string_buffer(length.value)
        if sc.SCardListReaders(ctx, None, buf, ctypes.byref(length)) != SCARD_S_SUCCESS:
            out["error"] = "nenhum leitor PCSC"
            out["platform"] = sys.platform
            return out
        readers = [r.decode() for r in buf.raw[: length.value - 1].split(b"\x00") if r] if length.value > 1 else []
        out["readers"] = []
        out["platform"] = sys.platform

        proto_t0 = ctypes.c_ulong(SCARD_PROTOCOL_T0)
        pci_t0 = SCARD_IO_REQUEST(SCARD_PROTOCOL_T0, ctypes.sizeof(SCARD_IO_REQUEST))

        def transmit(card, apdu):
            resp = ctypes.create_string_buffer(1024)
            rlen = ctypes.c_ulong(1024)
            rc = sc.SCardTransmit(
                card,
                ctypes.byref(pci_t0),
                bytes(apdu),
                len(apdu),
                None,
                resp,
                ctypes.byref(rlen),
            )
            if rc != SCARD_S_SUCCESS:
                return None
            return bytes(resp.raw[: rlen.value])

        for name in readers:
            # Compatibilidade ykman/Yubico Authenticator exige DUAS coisas
            # (ykman/pcsc/_pid_from_name + yubikit PID.of):
            # 1. substring "yubico yubikey" (case-insensitive) no reader name;
            # 2. tokens de interface em MAIÚSCULAS ("OTP"/"FIDO"/"CCID"/"U2F")
            #    — sem eles o parser monta PID["YK4_"] e levanta KeyError,
            #    derrubando o helper do Authenticator. O flavor
            #    yubikey5-identity/yubikey4-identity expõe
            #    "Yubico YubiKey OTP+FIDO+CCID 0" (VID 1050:0407, ADR-0025).
            # Para ferramentas neutras de padrão (OpenSC, PC-SC genérico), qualquer
            # nome é suportado.
            has_brand = "yubico" in name.lower() and "yubikey" in name.lower()
            has_iface = any(t in name for t in ("OTP", "FIDO", "CCID", "U2F"))
            ykman_compatible = has_brand and has_iface
            is_yubikey_optin = has_brand
            entry = {
                "status": None,
                "atr": None,
                "mute": False,
                "ykman_compatible": ykman_compatible,
                "is_yubikey_optin": is_yubikey_optin,
            }
            card = ctypes.c_size_t()
            state = ctypes.c_ulong(SCARD_STATE_UNAWARE)
            prot = ctypes.c_ulong(0)
            atr_buf = ctypes.create_string_buffer(64)
            atr_len = ctypes.c_ulong(64)
            reader_b = name.encode()
            rc = sc.SCardConnect(
                ctx,
                reader_b,
                SCARD_SHARE_SHARED,
                SCARD_PROTOCOL_T0,
                ctypes.byref(card),
                ctypes.byref(prot),
            )
            if rc == SCARD_S_SUCCESS:
                sc.SCardStatus(
                    card,
                    reader_b,
                    ctypes.byref(ctypes.c_ulong(64)),
                    ctypes.byref(state),
                    ctypes.byref(prot),
                    atr_buf,
                    ctypes.byref(atr_len),
                )
                st = state.value
                entry["mute"] = bool(st & SCARD_STATE_MUTE)
                entry["present"] = bool(st & SCARD_STATE_PRESENT)
                entry["atr"] = atr_buf.raw[: atr_len.value].hex()
                if apdu_checks and not entry["mute"]:
                    for label, aid in (
                        ("oath", OATH_AID),
                        ("management", MGMT_AID),
                        ("piv", PIV_AID),
                        ("openpgp", OPENPGP_AID),
                    ):
                        select = bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid
                        raw = transmit(card, select)
                        if raw is None:
                            entry[f"select_{label}"] = None
                        else:
                            data, sw = raw[:-2], raw[-2:]
                            entry[f"select_{label}"] = {
                                "sw": sw.hex(),
                                "data": data.hex(),
                            }
                sc.SCardDisconnect(card, 0)
            else:
                err_hex = hex(rc & 0xFFFFFFFF)
                entry["connect_error"] = err_hex
                entry["connect_error_desc"] = PCSC_ERROR_MESSAGES.get(
                    err_hex.lower(), "erro de conexão PC/SC"
                )
            out["readers"].append({name: entry})
    finally:
        sc.SCardReleaseContext(ctx)
    return out


# ---------------------------------------------------------------- ykman presente?
# Sonda host via `ykman --version` (YubiKey Manager CLI). Nunca falha o check:
# ausente = reportado com present=False, exit 0. Validação física segue 🚧
# (TODO.md: validação física YubiKey — `ykman list --serials` em placa real).


def check_ykman(timeout=10.0):
    out = {"present": False, "version": None}
    try:
        proc = subprocess.run(
            ["ykman", "--version"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode == 0:
            version = (proc.stdout or "").strip().splitlines()
            out["present"] = True
            out["version"] = version[0].strip() if version and version[0].strip() else None
    except Exception:
        # FileNotFoundError (não instalado), TimeoutExpired, etc. — ausente.
        pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="saída JSON pura")
    ap.add_argument(
        "--ykman-timeout",
        type=float,
        default=10.0,
        help="timeout da sonda `ykman --version` (s)",
    )
    ap.add_argument(
        "--opensc-timeout",
        type=float,
        default=10.0,
        help="timeout da sonda `opensc-tool --version` (s)",
    )
    args = ap.parse_args()

    fido2_lib = check_fido2_lib()
    opensc = check_opensc(timeout=args.opensc_timeout)
    ykman = check_ykman(timeout=args.ykman_timeout)

    result = {
        "identity_note": IDENTITY_NOTE,
        "fido2": fido2_lib,
        "opensc": opensc,
        "ykman": ykman,
        "hid": check_hid(),
        "ccid": check_ccid(),
    }
    if args.json:
        print(json.dumps(result, indent=2))
        return

    print("=== IDENTIDADE USB PADRÃO vs OPT-IN ===")
    print("  " + IDENTITY_NOTE)

    print("=== FERRAMENTAS NEUTRAS DE PADRÃO (Padrões Abertos FIDO2 / CCID) ===")
    if fido2_lib.get("present"):
        print(f"  [FIDO2/CTAP2] python-fido2: presente versão={fido2_lib.get('version')}")
    else:
        print("  [FIDO2/CTAP2] python-fido2: ausente (instale via: pip install fido2)")
    if opensc.get("present"):
        print(f"  [SmartCard]   opensc-tool (OpenSC): presente versão={opensc.get('version')}")
    else:
        print("  [SmartCard]   opensc-tool (OpenSC): ausente no PATH (ferramenta neutra ISO 7816-4)")
    print("  [SmartCard]   PC-SC genérico: API nativa do SO (WinSCard/libpcsclite)")

    print("=== HID FIDO / CTAPHID (python-fido2) ===")
    hid = result["hid"]
    for d in hid.get("hid_devices", []):
        flavor = d.get("identity_flavor", "")
        print(f"  dispositivo: {d['product']} {d['vid']}:{d['pid']} [{flavor}]")
    print(f"  CTAPHID ping: {'OK' if hid.get('ctap_ok') else 'FALHOU'}")
    gi = hid.get("get_info")
    if isinstance(gi, dict):
        print(f"  GetInfo: versions={gi['versions']} aaguid={gi['aaguid']}")
        print(f"           algoritmos={gi['algorithms']} options={gi['options']}")
    elif gi:
        print(f"  GetInfo: {gi}")
    if hid.get("error"):
        print(f"  erro: {hid['error']}")
    if not hid.get("hid_devices"):
        print("  nenhum HID FIDO enumerado")

    print("=== CCID / PCSC (Padrão ISO 7816-4 neutro) ===")
    cc = result["ccid"]
    if cc.get("error"):
        print(f"  erro: {cc['error']}")
    for item in cc.get("readers", []):
        for name, e in item.items():
            yk = e.get("ykman_compatible")
            compat_str = "[ykman compatível]" if yk else "[leitor CCID neutro]"
            print(f"  leitor: {name} {compat_str}")
            print(f"    presente={e.get('present')} mute={e.get('mute')} ykman_compatible={yk}")
            if e.get("connect_error"):
                desc = e.get("connect_error_desc", "")
                print(f"    erro de conexão PC/SC: {e['connect_error']} ({desc})")
            if e.get("atr"):
                print(f"    ATR: {e.get('atr')}")
            for k in ("select_oath", "select_management", "select_piv", "select_openpgp"):
                v = e.get(k)
                if v is not None:
                    print(
                        f"    SELECT {k}: SW={v['sw']} data={v['data'][:32]}…"
                        if len(v["data"]) > 32
                        else f"    SELECT {k}: SW={v['sw']} data={v['data']}"
                    )

    print("=== FERRAMENTAS DE FABRICANTE (Opcional / Não-neutras) ===")
    if ykman.get("present"):
        print(f"  ykman: presente versão={ykman.get('version')}")
    else:
        print("  ykman: ausente (ferramenta de fabricante — validação física opcional)")


if __name__ == "__main__":
    main()
