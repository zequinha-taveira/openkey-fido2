"""Testes do hardware_check cross-platform (Windows + Linux pcsc_lite).

Cobre JSON compatível para CI, HID via fido2.hid, CCID via ctypes em ambos OS,
branch Linux sem pyscard e SELECT de applets. Sem hardware real.
"""

import json
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS_DIR))

import hardware_check as hc  # noqa: E402


def test_json_structure_without_hardware():
    hid = hc.check_hid()
    ccid = hc.check_ccid(apdu_checks=False)
    assert "hid_devices" in hid
    assert "ctap_ok" in hid
    assert isinstance(hid["hid_devices"], list)
    assert isinstance(hid["ctap_ok"], bool)
    assert "readers" in ccid
    assert isinstance(ccid["readers"], list)
    # plataforma reportada para CI Linux/Win
    assert "platform" in ccid or "error" in ccid
    # JSON completo serializável
    result = {"hid": hid, "ccid": ccid}
    json.dumps(result)


def test_cli_json_passes_no_hardware():
    out = subprocess.check_output([sys.executable, str(TOOLS_DIR / "hardware_check.py"), "--json"])
    data = json.loads(out)
    assert "hid" in data and "ccid" in data
    assert "hid_devices" in data["hid"]
    assert "readers" in data["ccid"]


def test_hid_mock_device_ping_and_getinfo():
    fake_desc = mock.Mock()
    fake_desc.path = "/dev/hidraw0"
    fake_desc.vendor_id = 0x1209
    fake_desc.product_id = 0x0001
    fake_desc.product_name = "openkey-fido2"

    fake_dev = mock.Mock()
    fake_dev.descriptor = fake_desc
    fake_dev.ping.return_value = b"openkey-ping"
    fake_opened = mock.Mock()
    fake_opened.ping.return_value = b"openkey-ping"
    fake_dev.open.return_value = fake_opened

    fake_info = mock.Mock()
    fake_info.versions = ["FIDO_2_0"]
    fake_info.aaguid = bytes(16)
    fake_info.algorithms = []
    fake_info.options = {"rk": True}

    with mock.patch("fido2.hid.CtapHidDevice.list_devices", return_value=[fake_dev]):
        # fido2 1.1 expõe Ctap2 (base), versões novas CTAP2 — cobre ambos
        with mock.patch("fido2.ctap2.Ctap2", create=True) as mock_ctap2:
            with mock.patch("fido2.ctap2.CTAP2", mock_ctap2, create=True):
                mock_ctap2.return_value.get_info.return_value = fake_info
                # também patcha o import interno usado por hardware_check
                with mock.patch.dict("sys.modules", {"fido2.ctap2.base": mock.Mock(Ctap2=mock_ctap2)}):
                    hid = hc.check_hid()
                    assert len(hid["hid_devices"]) == 1
                    assert hid["hid_devices"][0]["vid"] == hex(0x1209)
                    assert hid["ctap_ok"] is True
                    assert hid["get_info"]["versions"] == ["FIDO_2_0"]


def test_ccid_mock_pcsclite_ykman_compatible_and_select():
    # Simula lib PC/SC com 2 leitores, um compatível ykman
    fake_sc = mock.Mock()
    fake_sc.SCardEstablishContext.return_value = hc.SCARD_S_SUCCESS

    # SCardListReaders: primeiro chama para tamanho, segundo para buffer
    readers_raw = b"Yubico Yubikey 5 0\x00Generic Reader 0\x00\x00"
    def list_readers(ctx, _a, _b, plen):
        if _b is None:  # query tamanho
            plen._obj.value = len(readers_raw)
            return hc.SCARD_S_SUCCESS
        # copia para buffer
        ctypes = __import__("ctypes")
        buf = ctypes.cast(_b, ctypes.POINTER(ctypes.c_char))
        for i, b in enumerate(readers_raw):
            buf[i] = b.to_bytes(1, "little")
        plen._obj.value = len(readers_raw)
        return hc.SCARD_S_SUCCESS

    fake_sc.SCardListReaders.side_effect = list_readers
    fake_sc.SCardConnect.return_value = hc.SCARD_S_SUCCESS
    fake_sc.SCardStatus.return_value = hc.SCARD_S_SUCCESS

    def transmit(card, pci, apdu, alen, _, resp, rlen):
        # Retorna 9000 para todo SELECT
        import ctypes
        resp_buf = ctypes.cast(resp, ctypes.POINTER(ctypes.c_char))
        resp_buf[0] = b"\x90"
        resp_buf[1] = b"\x00"
        rlen._obj.value = 2
        return hc.SCARD_S_SUCCESS

    fake_sc.SCardTransmit.side_effect = transmit

    with mock.patch.object(hc, "_load_pcsc", return_value=fake_sc):
        ccid = hc.check_ccid(apdu_checks=True)
        assert len(ccid["readers"]) == 2
        # ykman compatível detectado pelo nome
        assert ccid["readers"][0]["Yubico Yubikey 5 0"]["ykman_compatible"] is True
        assert ccid["readers"][1]["Generic Reader 0"]["ykman_compatible"] is False
        # SELECT applets retornou 9000
        oat = ccid["readers"][0]["Yubico Yubikey 5 0"]["select_oath"]
        assert oat["sw"] == "9000"


def test_ccid_linux_fallback_when_lib_missing():
    with mock.patch.object(hc, "_load_pcsc", side_effect=OSError("libpcsclite não encontrada")):
        ccid = hc.check_ccid()
        assert "PC/SC indisponível" in ccid["error"]
        assert ccid["platform"] == sys.platform


def test_applet_aids_constants():
    assert hc.OATH_AID == bytes.fromhex("A0000005272101")
    assert hc.MGMT_AID == bytes.fromhex("A000000527471117")
    assert len(hc.OATH_AID) == 7
    assert len(hc.MGMT_AID) == 8
