"""End-to-end tests for remaining CTAP2 commands via simulator.

Covers: Reset, GetNextAssertion, EnumerateRPs, BioEnroll.
"""

import base64
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

ERR_SUCCESS = 0x00
ERR_NO_CREDENTIALS = 0x2E
ERR_UNSUPPORTED_OPTION = 0x2B
# CTAP2_ERR_NOT_ALLOWED: comando não permitido no estado atual.
ERR_INVALID_STATE = 0x30


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
            raise RuntimeError("simulator exited prematurely")
        return json.loads(response)

    def get_info(self):
        return self._send({"op": "get_info"})

    def make_credential(
        self,
        rp_id="example.com",
        user_id=b"user123",
        client_data=b"challenge",
        algorithms=(-8,),
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
                "credential_id": _b64(credential_id) if credential_id else None,
                "allow_list": [_b64(item) for item in allow_list],
                "client_data_hash": _b64(client_data_hash),
                "options": options or {"up": True, "uv": True},
                "extensions": extensions,
            }
        )

    def get_next_assertion(self):
        return self._send({"op": "get_next_assertion"})

    def enumerate_rps_initial(self):
        return self._send({"op": "enumerate_rps_initial"})

    def enumerate_rps_next(self):
        return self._send({"op": "enumerate_rps_next"})

    def bio_enroll(self, sub_command, params=None):
        return self._send(
            {
                "op": "bio_enroll",
                "sub_command": sub_command,
                "sub_command_params": params,
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
            raise RuntimeError(f"simulator did not respond: {info}")
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


def test_reset_clears_credentials(simulator):
    simulator.reset()
    result = simulator.make_credential(rp_id="example.com")
    assert result["ok"], result

    result = simulator.reset()
    assert result["ok"], result

    result = simulator.get_assertion(rp_id="example.com")
    assert not result["ok"]
    assert result.get("code") == ERR_NO_CREDENTIALS


def test_reset_clears_get_next_assertion_state(simulator):
    simulator.reset()
    simulator.make_credential(rp_id="example.com")
    simulator.make_credential(rp_id="example.com")

    result = simulator.get_assertion(rp_id="example.com")
    assert result["ok"], result

    simulator.reset()

    result = simulator.get_next_assertion()
    assert not result["ok"]
    assert result.get("code") == ERR_INVALID_STATE


def test_get_next_assertion_flow(simulator):
    simulator.reset()
    user_ids = []
    for i in range(3):
        user_id = f"user{i}".encode()
        user_ids.append(user_id)
        result = simulator.make_credential(
            rp_id="example.com",
            user_id=user_id,
        )
        assert result["ok"], result

    result = simulator.get_assertion(rp_id="example.com")
    assert result["ok"], result

    # A cadeia termina por NO_CREDENTIALS (CTAP 2.1 §6.2) — sem flag `next`
    # no wire. Cada asserção encadeada carrega o `user_handle` próprio.
    seen_handles = set()
    for _ in range(2):
        result = simulator.get_next_assertion()
        assert result["ok"], result
        assert result.get("credential_id"), result
        assert result.get("user_handle"), result
        seen_handles.add(result["user_handle"])

    assert len(seen_handles) == 2

    result = simulator.get_next_assertion()
    assert not result["ok"]
    assert result.get("code") == ERR_NO_CREDENTIALS


def test_get_next_assertion_without_state(simulator):
    simulator.reset()
    result = simulator.get_next_assertion()
    assert not result["ok"]
    assert result.get("code") == ERR_INVALID_STATE


def test_enumerate_rps_initial(simulator):
    simulator.reset()
    result = simulator.make_credential(rp_id="example.com")
    assert result["ok"], result
    result = simulator.make_credential(rp_id="another.com")
    assert result["ok"], result
    result = simulator.make_credential(rp_id="example.com", user_id=b"user2")
    assert result["ok"], result

    result = simulator.enumerate_rps_initial()
    assert result["ok"], result
    assert result.get("total_rps") == 2
    assert "rp" in result
    assert "id" in result["rp"]
    assert "rp_hash" in result
    rp_hash = base64.b64decode(result["rp_hash"])
    assert len(rp_hash) == 32


def test_enumerate_rps_next(simulator):
    simulator.reset()
    result = simulator.make_credential(rp_id="example.com")
    assert result["ok"], result
    result = simulator.make_credential(rp_id="another.com")
    assert result["ok"], result
    result = simulator.make_credential(rp_id="third.com")
    assert result["ok"], result

    result = simulator.enumerate_rps_initial()
    assert result["ok"], result
    assert result.get("total_rps") == 3
    first_rp_id = result["rp"]["id"]

    result = simulator.enumerate_rps_next()
    assert result["ok"], result
    assert result.get("total_rps") == 3
    second_rp_id = result["rp"]["id"]
    assert second_rp_id != first_rp_id

    result = simulator.enumerate_rps_next()
    assert result["ok"], result
    assert result.get("total_rps") == 3

    result = simulator.enumerate_rps_next()
    assert not result["ok"]
    assert result.get("code") == ERR_NO_CREDENTIALS


def test_enumerate_rps_empty(simulator):
    simulator.reset()
    result = simulator.enumerate_rps_initial()
    assert not result["ok"]
    assert result.get("code") == ERR_NO_CREDENTIALS


def test_enumerate_rps_next_without_initial(simulator):
    simulator.reset()
    result = simulator.enumerate_rps_next()
    assert not result["ok"]
    assert result.get("code") == ERR_INVALID_STATE


def test_bio_enroll_unsupported(simulator):
    simulator.reset()
    result = simulator.bio_enroll(sub_command=0x01)
    assert not result["ok"]
    assert result.get("code") == ERR_UNSUPPORTED_OPTION


def test_bio_get_fingerprint_characteristics(simulator):
    simulator.reset()
    result = simulator.bio_enroll(sub_command=0x03)
    assert result["ok"], result
    assert result.get("fingerprint_kind") == 1
    assert result.get("max_enrollments") == 5
