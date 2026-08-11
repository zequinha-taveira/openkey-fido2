"""Testes end-to-end das extensoes WebAuthn via simulador.

Cobre: credProtect, credBlob, minPinLength, hmac-secret.
"""

import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest

WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
SIM_BIN = WORKSPACE_ROOT / "target" / "debug" / "fido2-simulator.exe"
BUILD_TIMEOUT_S = 600
RUN_TIMEOUT_S = 30

ERR_INVALID_PARAMETER = 0x02


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class SimulatorClient:
    def __init__(self, proc):
        self.proc = proc

    def _send(self, payload):
        line = json.dumps(payload, separators=(",", ":"))
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        response = self.proc.stdout.readline()
        if not response:
            raise RuntimeError("simulador encerrou prematuramente")
        return json.loads(response)

    def get_info(self):
        return self._send({"op": "get_info"})

    def make_credential(
        self,
        rp_id="example.com",
        user_id=b"user123",
        client_data=b"challenge",
        algorithms=(-7,),
        exclude=(),
        options=None,
        extensions=None,
    ):
        return self._send(
            {
                "op": "make_credential",
                "rp_id": rp_id,
                "user_id": _b64(user_id),
                "client_data": _b64(client_data),
                "algorithms": list(algorithms),
                "exclude": [_b64(item) for item in exclude],
                "options": options or {"rk": False, "uv": True, "up": True},
                "extensions": extensions,
            }
        )

    def get_assertion(
        self,
        rp_id="example.com",
        credential_id=None,
        allow_list=(),
        client_data_hash=b"client data hash",
        options=None,
        extensions=None,
    ):
        return self._send(
            {
                "op": "get_assertion",
                "rp_id": rp_id,
                "credential_id": _b64(credential_id),
                "allow_list": [_b64(item) for item in allow_list],
                "client_data_hash": _b64(client_data_hash),
                "options": options or {"up": True, "uv": True},
                "extensions": extensions,
            }
        )

    def reset(self):
        return self._send({"op": "reset"})


def _start_simulator():
    proc = subprocess.Popen(
        [str(SIM_BIN)],
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
        info = client.get_info()
        if not info.get("ok"):
            raise RuntimeError(f"simulador nao respondeu: {info}")
        return client, proc
    except Exception:
        proc.kill()
        proc.wait()
        raise


@pytest.fixture(scope="session")
def simulator():
    if not SIM_BIN.exists():
        cargo = shutil.which("cargo")
        if cargo is None:
            pytest.skip("simulador nao compilado e cargo nao disponivel")
        proc = subprocess.run(
            [cargo, "build", "-p", "fido2-simulator"],
            cwd=WORKSPACE_ROOT,
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT_S,
        )
        if proc.returncode != 0:
            pytest.skip(f"cargo build falhou:\n{proc.stderr[-1000:]}")
    client, proc = _start_simulator()
    yield client
    proc.terminate()
    try:
        proc.wait(timeout=RUN_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def test_get_info_lists_all_extensions(simulator):
    info = simulator.get_info()
    assert info["ok"]
    assert "credProtect" in info["extensions"]
    assert "credBlob" in info["extensions"]
    assert "minPinLength" in info["extensions"]
    assert "hmac-secret" in info["extensions"]


def test_cred_protect_user_verification_required(simulator):
    simulator.reset()
    result = simulator.make_credential(
        extensions={"credProtect": 3},
    )
    assert result["ok"], result
    assert result.get("credProtect") == 3


def test_cred_protect_user_verification_optional(simulator):
    simulator.reset()
    result = simulator.make_credential(
        extensions={"credProtect": 1},
    )
    assert result["ok"], result
    assert result.get("credProtect") == 1


def test_cred_blob_set_and_get(simulator):
    simulator.reset()
    blob = b"my-cred-blob-value"
    result = simulator.make_credential(
        extensions={"credBlob": _b64(blob)},
    )
    assert result["ok"], result
    assert result.get("credBlob") == _b64(blob)

    credential_id = base64.b64decode(result["credential_id"])
    asserted = simulator.get_assertion(
        credential_id=credential_id,
        extensions={"minPinLength": True},
    )
    assert asserted["ok"], asserted
    assert asserted.get("credBlob") == _b64(blob)


def test_cred_blob_reject_too_large(simulator):
    simulator.reset()
    blob = b"x" * 33
    result = simulator.make_credential(
        extensions={"credBlob": _b64(blob)},
    )
    assert not result["ok"]
    assert result["code"] == ERR_INVALID_PARAMETER


def test_min_pin_length_returned(simulator):
    simulator.reset()
    result = simulator.make_credential(
        extensions={"minPinLength": True},
    )
    assert result["ok"], result
    assert result.get("minPinLength") == 4


def test_hmac_secret_creation(simulator):
    simulator.reset()
    result = simulator.make_credential(
        extensions={"hmacSecret": {"saltEnc": _b64(b"a" * 16)}},
    )
    assert result["ok"], result
    assert "hmac-secret" in result
    secret = base64.b64decode(result["hmac-secret"])
    assert len(secret) == 48


def test_hmac_secret_get_via_get_assertion(simulator):
    simulator.reset()
    made = simulator.make_credential()
    assert made["ok"], made

    credential_id = base64.b64decode(made["credential_id"])
    salt = b"1234567890123456"
    asserted = simulator.get_assertion(
        credential_id=credential_id,
        extensions={"hmacSecret": {"saltEnc": _b64(salt)}},
    )
    assert asserted["ok"], asserted
    assert "hmac-secret" in asserted
    secret = base64.b64decode(asserted["hmac-secret"])
    assert len(secret) == 48


def test_multiple_extensions_combined(simulator):
    simulator.reset()
    blob = b"combined-blob"
    result = simulator.make_credential(
        extensions={
            "credProtect": 2,
            "credBlob": _b64(blob),
            "minPinLength": True,
        },
    )
    assert result["ok"], result
    assert result.get("credProtect") == 2
    assert result.get("credBlob") == _b64(blob)
    assert result.get("minPinLength") == 4
