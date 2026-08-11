"""Testes end-to-end dos formatos de attestation via simulador.

Cobre: none (padrao), self e packed (CTAP2 6.3.3).
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
ALG_EDDSA = -8
ALG_ES256 = -7


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

    def set_attestation_format(self, format_name):
        return self._send({"op": "set_attestation_format", "format": format_name})

    def make_credential(
        self,
        rp_id="example.com",
        user_id=b"user123",
        client_data=b"challenge",
        algorithms=(ALG_EDDSA,),
        options=None,
    ):
        return self._send(
            {
                "op": "make_credential",
                "rp_id": rp_id,
                "user_id": _b64(user_id),
                "client_data": _b64(client_data),
                "algorithms": list(algorithms),
                "exclude": [],
                "options": options or {"rk": False, "uv": True, "up": True},
                "extensions": None,
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


@pytest.fixture(autouse=True)
def clean_state(simulator):
    """Cada teste comeca com o authenticator zerado e attestation `none`."""
    simulator.reset()
    simulator.set_attestation_format("none")
    yield
    simulator.set_attestation_format("none")


def test_default_attestation_is_none(simulator):
    result = simulator.make_credential()
    assert result["ok"], result
    assert result["fmt"] == "none"
    assert result["att_stmt"] == {}


def test_self_attestation(simulator):
    configured = simulator.set_attestation_format("self")
    assert configured["ok"], configured
    assert configured["format"] == "self"

    result = simulator.make_credential(algorithms=(ALG_EDDSA,))
    assert result["ok"], result
    assert result["fmt"] == "self"

    att_stmt = result["att_stmt"]
    assert att_stmt["alg"] == ALG_EDDSA
    assert "x5c" not in att_stmt
    signature = base64.b64decode(att_stmt["sig"])
    assert len(signature) == 64


def test_self_attestation_es256(simulator):
    assert simulator.set_attestation_format("self")["ok"]

    result = simulator.make_credential(algorithms=(ALG_ES256,))
    assert result["ok"], result
    assert result["fmt"] == "self"
    assert result["att_stmt"]["alg"] == ALG_ES256
    assert base64.b64decode(result["att_stmt"]["sig"])


def test_packed_attestation(simulator):
    configured = simulator.set_attestation_format("packed")
    assert configured["ok"], configured
    assert configured["format"] == "packed"

    result = simulator.make_credential(algorithms=(ALG_EDDSA,))
    assert result["ok"], result
    assert result["fmt"] == "packed"

    att_stmt = result["att_stmt"]
    assert att_stmt["alg"] == ALG_EDDSA
    assert base64.b64decode(att_stmt["sig"])
    assert len(att_stmt["x5c"]) == 1
    assert base64.b64decode(att_stmt["x5c"][0]).startswith(b"\x30\x82")


def test_packed_attestation_cert_is_stable_across_credentials(simulator):
    assert simulator.set_attestation_format("packed")["ok"]

    first = simulator.make_credential(user_id=b"user-a")
    second = simulator.make_credential(user_id=b"user-b")
    assert first["ok"] and second["ok"]
    assert first["att_stmt"]["x5c"] == second["att_stmt"]["x5c"]
    assert first["att_stmt"]["sig"] != second["att_stmt"]["sig"]


def test_switching_back_to_none_clears_att_stmt(simulator):
    assert simulator.set_attestation_format("self")["ok"]
    with_self = simulator.make_credential(user_id=b"user-self")
    assert with_self["fmt"] == "self"

    assert simulator.set_attestation_format("none")["ok"]
    with_none = simulator.make_credential(user_id=b"user-none")
    assert with_none["fmt"] == "none"
    assert with_none["att_stmt"] == {}


def test_unsupported_attestation_format_is_rejected(simulator):
    assert simulator.set_attestation_format("u2f")["ok"]

    result = simulator.make_credential()
    assert not result["ok"], result
    assert result["code"] == 0x0D


def test_unknown_attestation_format_string(simulator):
    result = simulator.set_attestation_format("nao-existe")
    assert not result["ok"]
    assert result["code"] == ERR_INVALID_PARAMETER
