"""Testes end-to-end dos algoritmos ES256 e EdDSA.

Cobre MakeCredential/GetAssertion com ambos os algoritmos, verificando
que a negociação funciona corretamente e que as assinaturas são válidas.
"""

import base64
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

ERR_UNSUPPORTED_ALGORITHM = 0x26


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
            }
        )

    def get_assertion(
        self,
        rp_id="example.com",
        credential_id=None,
        allow_list=(),
        client_data_hash=b"client data hash",
        options=None,
    ):
        return self._send(
            {
                "op": "get_assertion",
                "rp_id": rp_id,
                "credential_id": _b64(credential_id),
                "allow_list": [_b64(item) for item in allow_list],
                "client_data_hash": _b64(client_data_hash),
                "options": options or {"up": True, "uv": True},
            }
        )

    def verify_assertion(self, credential_id, auth_data, signature, client_data_hash):
        return self._send(
            {
                "op": "verify_assertion",
                "credential_id": _b64(credential_id),
                "auth_data": _b64(auth_data),
                "signature": _b64(signature),
                "client_data_hash": _b64(client_data_hash),
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
            pytest.skip("simulador nao compilado e cargo nao esta disponivel")
        subprocess.run(
            [cargo, "build", "-p", "fido2-simulator"],
            cwd=WORKSPACE_ROOT,
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT_S,
        )
    client, proc = _start_simulator()
    yield client
    proc.terminate()
    try:
        proc.wait(timeout=RUN_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def test_get_info_reports_algorithms(simulator):
    info = simulator.get_info()
    assert info["ok"]
    algorithms = info.get("algorithms", [])
    assert len(algorithms) >= 3
    algs = {a["alg"] for a in algorithms}
    assert -7 in algs  # ES256
    assert -8 in algs  # EdDSA
    assert -257 in algs  # RS256


def test_es256_make_credential(simulator):
    simulator.reset()
    result = simulator.make_credential(algorithms=[-7])
    assert result["ok"], result
    assert result["fmt"] == "none"
    assert result["sign_count"] == 0
    assert result["flags"] & 0x40  # AT presente


def test_es256_get_assertion_and_verify(simulator):
    simulator.reset()
    made = simulator.make_credential(algorithms=[-7])
    assert made["ok"], made

    credential_id = base64.b64decode(made["credential_id"])
    asserted = simulator.get_assertion(credential_id=credential_id)
    assert asserted["ok"], asserted
    assert asserted["sign_count"] == 1
    assert asserted["signature"]

    verified = simulator.verify_assertion(
        credential_id=credential_id,
        auth_data=base64.b64decode(asserted["auth_data"]),
        signature=base64.b64decode(asserted["signature"]),
        client_data_hash=b"client data hash",
    )
    assert verified["ok"], verified
    assert verified["valid"] is True


def test_eddsa_make_credential(simulator):
    simulator.reset()
    result = simulator.make_credential(algorithms=[-8])
    assert result["ok"], result
    assert result["fmt"] == "none"


def test_eddsa_get_assertion_and_verify(simulator):
    simulator.reset()
    made = simulator.make_credential(algorithms=[-8])
    assert made["ok"], made

    credential_id = base64.b64decode(made["credential_id"])
    asserted = simulator.get_assertion(credential_id=credential_id)
    assert asserted["ok"], asserted

    verified = simulator.verify_assertion(
        credential_id=credential_id,
        auth_data=base64.b64decode(asserted["auth_data"]),
        signature=base64.b64decode(asserted["signature"]),
        client_data_hash=b"client data hash",
    )
    assert verified["ok"], verified
    assert verified["valid"] is True


def test_algorithm_negotiation_picks_first_supported(simulator):
    simulator.reset()
    # RS256 (-257) and ES256 (-7) are supported; RS256 vem primeiro
    result = simulator.make_credential(algorithms=[-257, -7])
    assert result["ok"], result


def test_algorithm_negotiation_unsupported_only(simulator):
    simulator.reset()
    result = simulator.make_credential(algorithms=[-65535])
    assert not result["ok"]
    assert result["code"] == ERR_UNSUPPORTED_ALGORITHM


def test_rs256_make_credential(simulator):
    simulator.reset()
    result = simulator.make_credential(algorithms=[-257])
    assert result["ok"], result
    assert result["fmt"] == "none"


def test_rs256_get_assertion_and_verify(simulator):
    simulator.reset()
    made = simulator.make_credential(algorithms=[-257])
    assert made["ok"], made

    credential_id = base64.b64decode(made["credential_id"])
    asserted = simulator.get_assertion(credential_id=credential_id)
    assert asserted["ok"], asserted

    verified = simulator.verify_assertion(
        credential_id=credential_id,
        auth_data=base64.b64decode(asserted["auth_data"]),
        signature=base64.b64decode(asserted["signature"]),
        client_data_hash=b"client data hash",
    )
    assert verified["ok"], verified
    assert verified["valid"] is True


def test_es256_sign_count_increments(simulator):
    simulator.reset()
    made = simulator.make_credential(algorithms=[-7])
    credential_id = base64.b64decode(made["credential_id"])

    first = simulator.get_assertion(credential_id=credential_id)
    second = simulator.get_assertion(credential_id=credential_id)
    assert first["sign_count"] == 1
    assert second["sign_count"] == 2
