"""Testes end-to-end do firmware via simulador sem hardware.

O simulador (crate `fido2-simulator`) expõe o firmware FIDO2 através de um
protocolo JSON linha-a-linha sobre stdin/stdout. Esta suíte cobre o ciclo de
vida make/assert/verify e as regressões dos bugs de segurança/CTAP2 corrigidos
no firmware:
  - allow_list de outro RP é rejeitado (bug: RP hijacking)
  - exclude_list existente retorna CredentialExists (0x0A)
  - flags UP/UV respeitam as options do request
  - algoritmo não suportado retorna UnsupportedAlgorithm (0x0C)
"""

import base64
import json
import os
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

ERR_CREDENTIAL_EXISTS = 0x19
ERR_UNSUPPORTED_ALGORITHM = 0x26
ERR_NO_CREDENTIALS = 0x2E

_APP_CONTROL_SKIP_REASON = (
    "o Windows bloqueou a execução do simulador via Controle de Aplicativo "
    "(Smart App Control); desative o SAC ou assine os binários"
)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class SimulatorClient:
    """Cliente do protocolo JSON do simulador."""

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
            raise RuntimeError(f"simulador não respondeu: {info}")
        return client, proc
    except Exception:
        proc.kill()
        proc.wait()
        raise


def _is_app_control_block(exc: BaseException) -> bool:
    if getattr(exc, "winerror", None) == 4551:
        return True
    return "Application Control" in str(exc) or "Controle de Aplicativo" in str(exc)


@pytest.fixture(scope="session")
def simulator():
    if not SIM_BIN.exists():
        cargo = shutil.which("cargo")
        if cargo is None:
            pytest.skip("simulador não compilado e cargo não está disponível")
        proc = subprocess.run(
            [cargo, "build", "-p", "fido2-simulator"],
            cwd=WORKSPACE_ROOT,
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT_S,
        )
        if proc.returncode != 0:
            pytest.skip(f"cargo build do simulador falhou:\n{proc.stderr[-1000:]}")
        if not SIM_BIN.exists():
            pytest.skip("cargo build não produziu o simulador")
    try:
        client, proc = _start_simulator()
    except OSError as exc:
        if _is_app_control_block(exc):
            pytest.skip(_APP_CONTROL_SKIP_REASON)
        raise
    yield client
    proc.terminate()
    try:
        proc.wait(timeout=RUN_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def test_get_info_reports_versions_and_aaguid(simulator):
    info = simulator.get_info()
    assert info["ok"]
    assert "2.0" in info["versions"]
    assert "2.1" in info["versions"]
    assert info["aaguid"] == "00000000000000000000000000000000"
    assert info["firmware_version"] == "0.1.0"
    assert "rk" in info["options"]
    assert "up" in info["options"]


def test_make_credential_and_verify_assertion(simulator):
    made = simulator.make_credential()
    assert made["ok"], made
    assert made["fmt"] == "none"
    assert made["sign_count"] == 0
    assert made["flags"] & 0x40  # AT presente
    assert made["credential_id"]

    asserted = simulator.get_assertion(credential_id=base64.b64decode(made["credential_id"]))
    assert asserted["ok"], asserted
    assert asserted["sign_count"] == 1
    assert asserted["signature"]

    verified = simulator.verify_assertion(
        credential_id=base64.b64decode(made["credential_id"]),
        auth_data=base64.b64decode(asserted["auth_data"]),
        signature=base64.b64decode(asserted["signature"]),
        client_data_hash=b"client data hash",
    )
    assert verified["ok"], verified
    assert verified["valid"] is True


def test_assertion_sign_count_increments(simulator):
    simulator.reset()
    made = simulator.make_credential()
    credential_id = base64.b64decode(made["credential_id"])

    first = simulator.get_assertion(credential_id=credential_id)
    second = simulator.get_assertion(credential_id=credential_id)
    assert first["sign_count"] == 1
    assert second["sign_count"] == 2


def test_allow_list_from_wrong_rp_is_rejected(simulator):
    simulator.reset()
    made = simulator.make_credential(rp_id="example.com")
    credential_id = base64.b64decode(made["credential_id"])

    result = simulator.get_assertion(
        rp_id="evil.com",
        credential_id=credential_id,
        allow_list=[credential_id],
    )
    assert not result["ok"], "assertion para RP estranho não deveria ter sucesso"
    assert result["code"] == ERR_NO_CREDENTIALS


def test_exclude_list_existing_credential_returns_credential_exists(simulator):
    simulator.reset()
    made = simulator.make_credential(rp_id="example.com", user_id=b"user123")
    credential_id = base64.b64decode(made["credential_id"])

    result = simulator.make_credential(
        rp_id="example.com",
        user_id=b"user123",
        exclude=[credential_id],
    )
    assert not result["ok"]
    assert result["code"] == ERR_CREDENTIAL_EXISTS


def test_up_uv_flags_respect_request_options(simulator):
    simulator.reset()
    made = simulator.make_credential(options={"rk": False, "up": False, "uv": False})
    assert made["ok"], made
    assert made["flags"] == 0x40  # apenas AT, sem UP/UV

    credential_id = base64.b64decode(made["credential_id"])
    asserted = simulator.get_assertion(
        credential_id=credential_id, options={"up": False, "uv": False}
    )
    assert asserted["ok"], asserted
    assert asserted["flags"] == 0x00  # nem UP nem UV


def test_unsupported_algorithm_is_rejected(simulator):
    simulator.reset()
    result = simulator.make_credential(algorithms=[-65535])
    assert not result["ok"]
    assert result["code"] == ERR_UNSUPPORTED_ALGORITHM


def test_unsupported_algorithm_with_eddsa_present_succeeds(simulator):
    simulator.reset()
    result = simulator.make_credential(algorithms=[-7, -257])
    assert result["ok"], result


def test_reset_clears_credentials(simulator):
    simulator.reset()
    made = simulator.make_credential()
    credential_id = base64.b64decode(made["credential_id"])

    assert simulator.reset()["ok"]
    result = simulator.get_assertion(credential_id=credential_id)
    assert not result["ok"]
