"""End-to-end tests for PIV/OpenPGP applets via the simulator APDU bridge.

Covers: PIV VERIFY -> GENERATE 9A (Ed25519) -> GET DATA -> AUTH sign ->
PUT DATA cert roundtrip; OpenPGP SELECT -> VERIFY PW1 -> GENERATE SIG ->
PSO SIGN -> GET DATA B600/00C5; negatives 6982/6A82/6A80/6D00.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
_EXE = ".exe" if sys.platform == "win32" else ""
SIM_BIN = WORKSPACE_ROOT / "target" / "debug" / f"fido2-simulator{_EXE}"
BUILD_TIMEOUT_S = 600
RUN_TIMEOUT_S = 30

SW_OK = 0x9000
SW_SECURITY_STATUS = 0x6982
SW_FILE_NOT_FOUND = 0x6A82
SW_WRONG_SYNTAX = 0x6A80
SW_INS_NOT_SUPPORTED = 0x6D00

PIV_AID = "a000000308000010000100"
OPENPGP_AID = "d27600012401"
PIV_PIN_DEFAULT_PADDED = "313233343536ffff"  # "123456" + FF FF
OPENPGP_PW1_DEFAULT = "313233343536"  # "123456"


def _select(aid_hex: str) -> str:
    aid = bytes.fromhex(aid_hex)
    return "00a40400" + f"{len(aid):02x}" + aid_hex


def _short(cla: int, ins: int, p1: int, p2: int, data_hex: str = "", le: str | None = None) -> str:
    data = bytes.fromhex(data_hex) if data_hex else b""
    frame = bytes([cla, ins, p1, p2])
    if data:
        if len(data) > 255:
            raise ValueError("short APDU data too long; use _extended")
        frame += bytes([len(data)]) + data
    if le is not None:
        frame += bytes.fromhex(le)
    return frame.hex()


def _extended(cla: int, ins: int, p1: int, p2: int, data_hex: str, le_hex: str = "") -> str:
    data = bytes.fromhex(data_hex)
    frame = bytes([cla, ins, p1, p2, 0x00]) + len(data).to_bytes(2, "big") + data
    if le_hex:
        frame += bytes.fromhex(le_hex)
    return frame.hex()


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82]) + n.to_bytes(2, "big")


def parse_7f49(obj: bytes) -> tuple[int, bytes]:
    assert obj[:2] == b"\x7f\x49", obj.hex()
    assert len(obj) == 3 + obj[2]
    inner = obj[3:]
    assert inner[:2] == b"\x80\x01"
    alg = inner[2]
    assert inner[3] == 0x86
    pub_len = inner[4]
    assert len(inner) == 5 + pub_len
    return alg, inner[5:]


class SimulatorClient:
    def __init__(self, proc):
        self.proc = proc

    def _send(self, payload):
        line = json.dumps(payload, separators=(",", ":"))
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        response = self.proc.stdout.readline()
        if not response:
            raise RuntimeError("simulator exited prematurely")
        return json.loads(response)

    def reset(self):
        return self._send({"op": "reset"})

    def apdu(self, apdu_hex: str):
        return self._send({"op": "apdu", "apdu": apdu_hex})

    def transact(self, apdu_hex: str) -> tuple[bytes, int]:
        """Send an APDU, following 61 XX chaining via GET RESPONSE."""
        data = b""
        resp = self.apdu(apdu_hex)
        assert resp.get("ok"), resp
        data += bytes.fromhex(resp["data"])
        sw = resp["sw"]
        while 0x6100 <= sw <= 0x61FF:
            remaining = sw & 0xFF or 256
            le = min(remaining, 256)
            get_resp = self.apdu("00c00000" + f"{le & 0xFF:02x}")
            assert get_resp.get("ok"), get_resp
            data += bytes.fromhex(get_resp["data"])
            sw = get_resp["sw"]
        return data, sw


def _start_simulator(storage_path=None):
    args = [str(SIM_BIN)]
    if storage_path is not None:
        args.extend(["--storage-path", str(storage_path)])
    proc = subprocess.Popen(
        args,
        cwd=WORKSPACE_ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        bufsize=1,
    )
    try:
        client = SimulatorClient(proc)
        info = client._send({"op": "get_info"})
        if not info.get("ok"):
            raise RuntimeError(f"simulator did not respond: {info}")
        return client, proc
    except Exception:
        proc.kill()
        proc.wait()
        raise


def _stop_simulator(proc):
    proc.terminate()
    try:
        proc.wait(timeout=RUN_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


@pytest.fixture(scope="session")
def simulator():
    if not SIM_BIN.exists():
        cargo = shutil.which("cargo")
        if cargo is None:
            pytest.skip("simulator not compiled and cargo not available")
        proc = subprocess.run(
            [cargo, "build", "-p", "fido2-simulator"],
            cwd=WORKSPACE_ROOT,
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT_S,
        )
        if proc.returncode != 0:
            pytest.skip(f"cargo build failed:\n{proc.stderr[-1000:]}")
    client, proc = _start_simulator()
    yield client
    proc.terminate()
    try:
        proc.wait(timeout=RUN_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def test_piv_full_cycle(simulator):
    assert simulator.reset()["ok"]
    data, sw = simulator.transact(_select(PIV_AID))
    assert sw == SW_OK, hex(sw)

    # Status query before VERIFY: 3 retries left.
    data, sw = simulator.transact(_short(0x00, 0x20, 0x00, 0x80))
    assert sw == 0x63C3, hex(sw)

    # VERIFY with factory PIN.
    data, sw = simulator.transact(_short(0x00, 0x20, 0x00, 0x80, PIV_PIN_DEFAULT_PADDED))
    assert sw == SW_OK, hex(sw)

    # GENERATE slot 9A, Ed25519.
    data, sw = simulator.transact(_short(0x00, 0x47, 0x00, 0x9A, "ac038001e0"))
    assert sw == SW_OK, hex(sw)
    alg, pubkey = parse_7f49(data)
    assert alg == 0xE0
    assert len(pubkey) == 32
    key_object = data

    # GET DATA key object matches GENERATE output.
    data, sw = simulator.transact(_short(0x00, 0xCB, 0x3F, 0xFF, "5fc105", le="00"))
    assert sw == SW_OK, hex(sw)
    assert data == key_object

    # AUTH signs a challenge; Ed25519 signatures are deterministic.
    challenge = bytes(range(32)).hex()
    data, sw = simulator.transact(_short(0x00, 0x87, 0x00, 0x9A, challenge))
    assert sw == SW_OK, hex(sw)
    assert len(data) == 64
    sig = data
    data, sw = simulator.transact(_short(0x00, 0x87, 0x00, 0x9A, challenge))
    assert sw == SW_OK and data == sig
    other = bytes(reversed(range(32))).hex()
    data, sw = simulator.transact(_short(0x00, 0x87, 0x00, 0x9A, other))
    assert sw == SW_OK and data != sig

    # PUT DATA cert roundtrip (verbatim bytes).
    cert = bytes((i * 7 + 3) % 256 for i in range(128))
    put_value = bytes.fromhex("5fc105") + _ber_len(len(cert)) + cert
    data, sw = simulator.transact(_short(0x00, 0xDB, 0x3F, 0xFF, put_value.hex()))
    assert sw == SW_OK, hex(sw)
    data, sw = simulator.transact(_short(0x00, 0xCB, 0x3F, 0xFF, "5fc105", le="00"))
    assert sw == SW_OK, hex(sw)
    assert data == cert


def test_openpgp_full_cycle(simulator):
    assert simulator.reset()["ok"]
    data, sw = simulator.transact(_select(OPENPGP_AID))
    assert sw == SW_OK, hex(sw)
    assert data[:1] == b"\x6f"

    # VERIFY PW1 (spec form: P1=00, P2=81).
    data, sw = simulator.transact(_short(0x00, 0x20, 0x00, 0x81, OPENPGP_PW1_DEFAULT))
    assert sw == SW_OK, hex(sw)

    # GENERATE SIG slot, Ed25519.
    data, sw = simulator.transact(_short(0x00, 0x47, 0x00, 0x00, "e0"))
    assert sw == SW_OK, hex(sw)
    alg, pubkey = parse_7f49(data)
    assert alg == 0xE0
    assert len(pubkey) == 32
    key_object = data

    # PSO SIGN.
    payload = b"openpgp-sign-me".hex()
    data, sw = simulator.transact(_short(0x00, 0x2A, 0x9E, 0x9A, payload))
    assert sw == SW_OK, hex(sw)
    assert len(data) == 64

    # GET DATA B600 returns the key object; 00C5 the SHA-256 fingerprint.
    data, sw = simulator.transact(_short(0x00, 0xCA, 0xB6, 0x00, le="00"))
    assert sw == SW_OK, hex(sw)
    assert data == key_object
    data, sw = simulator.transact(_short(0x00, 0xCA, 0x00, 0xC5, le="00"))
    assert sw == SW_OK, hex(sw)
    assert data == hashlib.sha256(pubkey).digest()


def test_negatives_without_verify_are_6982(simulator):
    assert simulator.reset()["ok"]

    # PIV: key exists but slot 9A requires a verified session.
    assert simulator.transact(_select(PIV_AID))[1] == SW_OK
    assert simulator.transact(_short(0x00, 0x47, 0x00, 0x9A, "ac038001e0"))[1] == SW_OK
    _, sw = simulator.transact(_short(0x00, 0x87, 0x00, 0x9A, "aa" * 32))
    assert sw == SW_SECURITY_STATUS, hex(sw)

    # OpenPGP: PSO SIGN without VERIFY.
    assert simulator.transact(_select(OPENPGP_AID))[1] == SW_OK
    assert simulator.transact(_short(0x00, 0x47, 0x00, 0x00, "e0"))[1] == SW_OK
    _, sw = simulator.transact(_short(0x00, 0x2A, 0x9E, 0x9A, b"probe".hex()))
    assert sw == SW_SECURITY_STATUS, hex(sw)

    # Reset drops verified sessions: VERIFY, reset, AUTH is denied again.
    assert simulator.transact(_select(PIV_AID))[1] == SW_OK
    assert simulator.transact(_short(0x00, 0x20, 0x00, 0x80, PIV_PIN_DEFAULT_PADDED))[1] == SW_OK
    assert simulator.reset()["ok"]
    assert simulator.transact(_select(PIV_AID))[1] == SW_OK
    _, sw = simulator.transact(_short(0x00, 0x87, 0x00, 0x9A, "aa" * 32))
    assert sw == SW_SECURITY_STATUS, hex(sw)


def test_negatives_unknown_tag_slot_are_6a82(simulator):
    assert simulator.reset()["ok"]
    assert simulator.transact(_select(PIV_AID))[1] == SW_OK

    # Unknown GET DATA tag.
    _, sw = simulator.transact(_short(0x00, 0xCB, 0x3F, 0xFF, "5fc1ff", le="00"))
    assert sw == SW_FILE_NOT_FOUND, hex(sw)
    # Unknown slots on GENERATE / AUTHENTICATE.
    _, sw = simulator.transact(_short(0x00, 0x47, 0x00, 0x9B, "ac038001e0"))
    assert sw == SW_FILE_NOT_FOUND, hex(sw)
    _, sw = simulator.transact(_short(0x00, 0x87, 0x00, 0x9B, "aa" * 32))
    assert sw == SW_FILE_NOT_FOUND, hex(sw)

    assert simulator.transact(_select(OPENPGP_AID))[1] == SW_OK
    # Unknown GET DATA tag.
    _, sw = simulator.transact(_short(0x00, 0xCA, 0x5F, 0x50, le="00"))
    assert sw == SW_FILE_NOT_FOUND, hex(sw)
    # DEC CRT is out of scope -> 6A82.
    _, sw = simulator.transact(_short(0x00, 0x47, 0x80, 0x00, "b8038001e0"))
    assert sw == SW_FILE_NOT_FOUND, hex(sw)

    # Unknown INS after applet selection -> 6D00.
    _, sw = simulator.transact(_short(0x00, 0xFF, 0x00, 0x00))
    assert sw == SW_INS_NOT_SUPPORTED, hex(sw)


def test_negatives_bad_cert_is_6a80(simulator):
    assert simulator.reset()["ok"]
    assert simulator.transact(_select(PIV_AID))[1] == SW_OK
    assert simulator.transact(_short(0x00, 0x20, 0x00, 0x80, PIV_PIN_DEFAULT_PADDED))[1] == SW_OK

    # Empty certificate value.
    _, sw = simulator.transact(_short(0x00, 0xDB, 0x3F, 0xFF, "5fc10500"))
    assert sw == SW_WRONG_SYNTAX, hex(sw)

    # Certificate above the 2048-byte ceiling (extended APDU).
    big = bytes((i * 13 + 1) % 256 for i in range(2049))
    put_value = (bytes.fromhex("5fc105") + _ber_len(len(big)) + big).hex()
    _, sw = simulator.transact(_extended(0x00, 0xDB, 0x3F, 0xFF, put_value))
    assert sw == SW_WRONG_SYNTAX, hex(sw)


def test_piv_key_and_ctap2_credential_survive_simulator_restart(tmp_path):
    """Chave PIV e credencial CTAP2 sobrevivem ao restart com --storage-path.

    Prova que os applets usam o mesmo backend persistente do CTAP2 (mesma
    identidade entre reinícios): o objeto de chave PIV e a assinatura
    determinística Ed25519 coincidem após o restart, e a credencial FIDO2
    criada no mesmo arquivo continua válida (coexistência `sys:*` + `cred:*`).
    """
    import base64

    storage_path = tmp_path / "applet_persist.json"
    client, proc = _start_simulator(storage_path=storage_path)
    try:
        assert client.reset()["ok"]
        assert client.transact(_select(PIV_AID))[1] == SW_OK
        assert (
            client.transact(_short(0x00, 0x20, 0x00, 0x80, PIV_PIN_DEFAULT_PADDED))[1] == SW_OK
        )

        # Gera chave Ed25519 no slot 9A e assina um desafio.
        data, sw = client.transact(_short(0x00, 0x47, 0x00, 0x9A, "ac038001e0"))
        assert sw == SW_OK, hex(sw)
        key_object = data
        challenge = bytes(range(32)).hex()
        sig_before, sw = client.transact(_short(0x00, 0x87, 0x00, 0x9A, challenge))
        assert sw == SW_OK, hex(sw)

        # Credencial CTAP2 no mesmo arquivo (escrita após as dos applets).
        created = client._send(
            {
                "op": "make_credential",
                "rp_id": "example.com",
                "user_id": base64.b64encode(b"restart_user").decode("ascii"),
                "client_data": base64.b64encode(b"challenge").decode("ascii"),
                "algorithms": [-8],
                "options": {"rk": False, "uv": True, "up": True},
            }
        )
        assert created["ok"], created
        cred_id = created["credential_id"]
    finally:
        _stop_simulator(proc)

    client2, proc2 = _start_simulator(storage_path=storage_path)
    try:
        # GET DATA da chave não exige sessão: objeto idêntico ao pré-restart.
        assert client2.transact(_select(PIV_AID))[1] == SW_OK
        data, sw = client2.transact(_short(0x00, 0xCB, 0x3F, 0xFF, "5fc105", le="00"))
        assert sw == SW_OK, hex(sw)
        assert data == key_object

        # Sessão não sobrevive ao restart: AUTH nega até novo VERIFY; após
        # VERIFY, a assinatura determinística coincide (mesma chave).
        _, sw = client2.transact(_short(0x00, 0x87, 0x00, 0x9A, challenge))
        assert sw == SW_SECURITY_STATUS, hex(sw)
        assert (
            client2.transact(_short(0x00, 0x20, 0x00, 0x80, PIV_PIN_DEFAULT_PADDED))[1]
            == SW_OK
        )
        sig_after, sw = client2.transact(_short(0x00, 0x87, 0x00, 0x9A, challenge))
        assert sw == SW_OK, hex(sw)
        assert sig_after == sig_before

        # Credencial CTAP2 do mesmo arquivo continua válida.
        asserted = client2._send(
            {
                "op": "get_assertion",
                "rp_id": "example.com",
                "credential_id": cred_id,
                "client_data_hash": base64.b64encode(b"client data hash").decode("ascii"),
                "options": {"up": True, "uv": True},
            }
        )
        assert asserted["ok"], asserted
    finally:
        _stop_simulator(proc2)
