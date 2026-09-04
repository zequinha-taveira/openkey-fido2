"""Host-side Yubico Authenticator compatibility probe (no board needed).

Drives the SIMULATOR's multiprotocol applets through the REAL yubikit
parsers (same code Yubico Authenticator/ykman use):
  - ManagementSession -> DeviceInfo (version/serial/form_factor/capabilities)
  - OathSession -> list (empty), put TOTP (SHA1), calculate vs RFC 6238,
    delete

Run: python tools/yubikit_compat_probe.py
Requires: yubikit (pip install --no-deps yubikey-manager), fido2-simulator
built (cargo build -p fido2-simulator).
Exit nonzero on any incompatibility.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
SIM_BIN = WORKSPACE_ROOT / "target" / "debug" / (
    "fido2-simulator.exe" if sys.platform == "win32" else "fido2-simulator"
)

from yubikit.core.smartcard import SmartCardConnection  # noqa: E402
from yubikit.core import TRANSPORT  # noqa: E402
from yubikit.management import (  # noqa: E402
    CAPABILITY,
    ManagementSession,
)
from yubikit.oath import (  # noqa: E402
    HASH_ALGORITHM,
    OATH_TYPE,
    CredentialData,
    OathSession,
)


class SimConnection(SmartCardConnection):
    """yubikit SmartCardConnection backed by the simulator APDU bridge."""

    usb_interface = None

    def __init__(self, client):
        self._client = client

    @property
    def transport(self):
        return TRANSPORT.USB

    def send_and_receive(self, apdu: bytes):
        data, sw = self._client.transact(apdu.hex())
        return data, sw

    def close(self):
        pass


class SimulatorClient:
    def __init__(self, proc):
        self.proc = proc

    def _send(self, payload):
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("simulator exited")
        return json.loads(line)

    def transact(self, apdu_hex: str) -> tuple[bytes, int]:
        data = b""
        resp = self._send({"op": "apdu", "apdu": apdu_hex})
        assert resp.get("ok"), resp
        data += bytes.fromhex(resp["data"])
        sw = resp["sw"]
        while 0x6100 <= sw <= 0x61FF:
            remaining = sw & 0xFF or 256
            r = self._send({"op": "apdu", "apdu": "00c00000" + f"{min(remaining, 256):02x}"})
            assert r.get("ok"), r
            data += bytes.fromhex(r["data"])
            sw = r["sw"]
        return data, sw


def check_management(conn) -> None:
    session = ManagementSession(conn)
    info = session.read_device_info()
    print(f"  version={info.version} serial={info.serial} "
          f"form_factor={info.form_factor} capabilities={info.config}")
    assert tuple(info.version) >= (4, 1, 0), info.version
    assert info.serial, "serial must be non-zero"
    assert info.version == (5, 4, 0), info.version
    from yubikit.core import TRANSPORT as _T  # noqa: E402
    usb_caps = info.config.enabled_capabilities[_T.USB]
    assert CAPABILITY.OATH in usb_caps
    assert CAPABILITY.FIDO2 in usb_caps
    print("  management: OK")


def check_oath(conn) -> None:
    session = OathSession(conn)
    assert session.locked is False
    assert session.version >= (3, 4, 0)
    assert list(session.list_credentials()) == []
    # RFC 6238 Appendix B TOTP-SHA1 secret ("12345678901234567890")
    secret = bytes.fromhex("3132333435363738393031323334353637383930")
    cred = session.put_credential(
        CredentialData("rfc6238", OATH_TYPE.TOTP, HASH_ALGORITHM.SHA1, secret, issuer="probe"),
    )
    print(f"  put: {cred}")
    creds = session.list_credentials()
    assert len(creds) == 1 and creds[0].name == "rfc6238", creds
    # T=59 -> full HMAC-SHA1, truncate (dynamic, RFC 4226) -> 94287082
    import hmac as _hmac  # noqa: E402
    resp = session.calculate(creds[0].id, (59 // 30).to_bytes(8, "big"))
    off = resp[-1] & 0x0F
    code = int.from_bytes(resp[off:off + 4], "big") & 0x7FFFFFFF
    assert f"{code % 10**8:08d}" == "94287082", code
    session.delete_credential(creds[0].id)
    assert session.list_credentials() == []
    print("  oath: OK")


def main() -> int:
    if not SIM_BIN.exists():
        print(f"simulator not found: {SIM_BIN}", file=sys.stderr)
        return 2
    proc = subprocess.Popen(
        [str(SIM_BIN)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        text=True, bufsize=1,
    )
    try:
        client = SimulatorClient(proc)
        print("== management (real yubikit parser) ==")
        check_management(SimConnection(client))
        print("== oath (real yubikit parser) ==")
        check_oath(SimConnection(client))
    finally:
        proc.kill()
    print("YUBIKIT COMPAT: ALL OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
