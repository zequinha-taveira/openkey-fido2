"""Ponte de automação/integração openkey-fido2 ↔ PC.

Valida pós-flash em uma passada:
  1. HID FIDO enumerável + CTAPHID vivo (INIT/PING via python-fido2)
  2. CTAP2 GetInfo pela camada HID (quando disponível)
  3. CCID/PCSC: leitor presente, status do cartão e ATR (via winscard/ctypes
     — não depende de pyscard)
  4. Applets ISO 7816: SELECT por AID (OATH A0000005272101 e Management
     A000000527471117) com resposta SW

Uso: python tools/hardware_check.py [--json]
"""

import argparse
import ctypes
import json
import sys

OATH_AID = bytes.fromhex("A0000005272101")
MGMT_AID = bytes.fromhex("A000000527471117")

# ---------------------------------------------------------------- HID / CTAP


def check_hid():
    out = {"hid_devices": [], "ctap_ok": False, "get_info": None}
    try:
        from fido2.hid import CtapHidDevice

        devs = list(CtapHidDevice.list_devices())
        for d in devs:
            desc = d.descriptor
            out["hid_devices"].append(
                {
                    "path": str(desc.path),
                    "vid": hex(desc.vendor_id),
                    "pid": hex(desc.product_id),
                    "product": desc.product_name,
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

    if sys.platform.startswith("win"):
        mod = ctypes.windll.winscard
        # Winscard expõe variantes ANSI `*A`; Linux pcsclite usa nomes sem sufixo.
        mod.SCardEstablishContext.argtypes = [
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        mod.SCardListReadersA.argtypes = [
            ctypes.c_ulong,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        mod.SCardConnectA.argtypes = [
            ctypes.c_ulong,
            ctypes.c_char_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(ctypes.c_ulong),
        ]
        mod.SCardStatusA.argtypes = [
            ctypes.c_ulong,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        mod.SCardTransmit.argtypes = [
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        mod.SCardDisconnect.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
        mod.SCardReleaseContext.argtypes = [ctypes.c_ulong]
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
        ctypes.POINTER(ctypes.c_ulong),
    ]
    mod.SCardEstablishContext.restype = ctypes.c_long
    mod.SCardListReaders.argtypes = [
        ctypes.c_ulong,
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    mod.SCardListReaders.restype = ctypes.c_long
    mod.SCardConnect.argtypes = [
        ctypes.c_ulong,
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.c_ulong),
    ]
    mod.SCardConnect.restype = ctypes.c_long
    mod.SCardStatus.argtypes = [
        ctypes.c_ulong,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    mod.SCardStatus.restype = ctypes.c_long
    mod.SCardTransmit.argtypes = [
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    mod.SCardTransmit.restype = ctypes.c_long
    mod.SCardDisconnect.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
    mod.SCardDisconnect.restype = ctypes.c_long
    mod.SCardReleaseContext.argtypes = [ctypes.c_ulong]
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
    ctx = ctypes.c_ulong()
    if sc.SCardEstablishContext(SCARD_SCOPE_USER, None, None, ctypes.byref(ctx)) != SCARD_S_SUCCESS:
        out["error"] = "SCardEstablishContext falhou (serviço Smart Card ativo?)"
        out["platform"] = sys.platform
        return out
    try:
        length = ctypes.c_ulong(0)
        sc.SCardListReaders(ctx, None, None, ctypes.byref(length))
        buf = ctypes.create_string_buffer(length.value if length.value else 1)
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
            # ykman deriva PID via substring "yubico yubikey" (case-insensitive) no reader name;
            # composite yubikey5-identity/yubikey4-identity expõe "Yubico YubiKey 5 0"
            # (VID 1050:0407, família YubiKey 4/5 no mesmo modo OTP+FIDO+CCID, ADR-0025).
            ykman_compatible = "yubico" in name.lower() and "yubikey" in name.lower()
            entry = {"status": None, "atr": None, "mute": False, "ykman_compatible": ykman_compatible}
            card = ctypes.c_ulong()
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
                    for label, aid in (("oath", OATH_AID), ("management", MGMT_AID)):
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
                entry["connect_error"] = hex(rc)
            out["readers"].append({name: entry})
    finally:
        sc.SCardReleaseContext(ctx)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="saída JSON pura")
    args = ap.parse_args()

    result = {"hid": check_hid(), "ccid": check_ccid()}
    if args.json:
        print(json.dumps(result, indent=2))
        return

    print("=== HID FIDO / CTAPHID ===")
    hid = result["hid"]
    for d in hid.get("hid_devices", []):
        print(f"  dispositivo: {d['product']} {d['vid']}:{d['pid']}")
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

    print("=== CCID / PCSC ===")
    cc = result["ccid"]
    if cc.get("error"):
        print(f"  erro: {cc['error']}")
    for item in cc.get("readers", []):
        for name, e in item.items():
            yk = e.get("ykman_compatible")
            print(f"  leitor: {name} {'[ykman compatível]' if yk else '[não-Yubico]'}")
            print(f"    presente={e.get('present')} mute={e.get('mute')} ykman_compatible={yk}")
            print(f"    ATR: {e.get('atr')}")
            for k in ("select_oath", "select_management"):
                v = e.get(k)
                if v is None:
                    print(f"    SELECT {k}: sem resposta")
                else:
                    print(f"    SELECT {k}: SW={v['sw']} data={v['data'][:32]}…" if len(v["data"]) > 32 else f"    SELECT {k}: SW={v['sw']} data={v['data']}")


if __name__ == "__main__":
    main()
