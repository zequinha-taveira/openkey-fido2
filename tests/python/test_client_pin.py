"""Testes end-to-end do ClientPIN via simulador.

Cobra getPINRetries, setPIN, changePIN, getPINToken e getPINHashEnc.
"""

import base64
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

ERR_PIN_INVALID = 0x31
ERR_PIN_REQUIRED = 0x33
ERR_PIN_POLICY_VIOLATION = 0x34


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class SimulatorClient:
    """Cliente do protocolo JSON do simulador."""

    def __init__(self, proc):
        self.proc = proc

    def _send(self, payload):
        import json

        line = json.dumps(payload, separators=(",", ":"))
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        response = self.proc.stdout.readline()
        if not response:
            raise RuntimeError("simulador encerrou prematuramente")
        return json.loads(response)

    def client_pin(self, sub_command, pin=None, new_pin=None):
        payload = {"op": "client_pin", "sub_command": sub_command}
        if pin is not None:
            payload["pin"] = _b64(pin)
        if new_pin is not None:
            payload["new_pin"] = _b64(new_pin)
        return self._send(payload)

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
        info = client.reset()
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


class TestClientPIN:
    """Testes do modulo ClientPIN via operacao `client_pin` do simulador."""

    def test_get_pin_retries_initial(self, simulator):
        """PIN retries deve comecar em 8 quando nao configurado."""
        simulator.reset()
        result = simulator.client_pin(sub_command=0x03)
        assert result["ok"], result
        assert result["retries"] == 8
        assert result["power_cycle_state"] is False

    def test_set_pin_success(self, simulator):
        """setPIN com PIN valido (>= 4 bytes) deve retornar sucesso."""
        simulator.reset()
        result = simulator.client_pin(sub_command=0x01, pin=b"1234")
        assert result["ok"], result

    def test_set_pin_too_short(self, simulator):
        """setPIN com PIN < 4 bytes deve retornar erro."""
        simulator.reset()
        result = simulator.client_pin(sub_command=0x01, pin=b"12")
        assert not result["ok"]
        assert result["code"] == ERR_PIN_POLICY_VIOLATION

    def test_change_pin_success(self, simulator):
        """changePIN com PIN atual correto e novo PIN valido."""
        simulator.reset()
        simulator.client_pin(sub_command=0x01, pin=b"1234")
        result = simulator.client_pin(sub_command=0x02, pin=b"1234", new_pin=b"5678")
        assert result["ok"], result

    def test_change_pin_wrong_old_pin(self, simulator):
        """changePIN com PIN atual errado deve decrementar retries."""
        simulator.reset()
        simulator.client_pin(sub_command=0x01, pin=b"1234")

        result = simulator.client_pin(sub_command=0x02, pin=b"9999", new_pin=b"5678")
        assert not result["ok"]
        assert result["code"] == ERR_PIN_INVALID

        retries = simulator.client_pin(sub_command=0x03)
        assert retries["retries"] == 7

    def test_get_pin_token_after_set(self, simulator):
        """getPINToken apos setPIN deve retornar token valido."""
        simulator.reset()
        simulator.client_pin(sub_command=0x01, pin=b"1234")

        result = simulator.client_pin(sub_command=0x05, pin=b"1234")
        assert result["ok"], result
        assert result["pin_uv_auth_token"]
        token = base64.b64decode(result["pin_uv_auth_token"])
        assert len(token) > 0

    def test_get_pin_hash_enc(self, simulator):
        """getPINHashEnc apos setPIN deve retornar hash criptografado."""
        simulator.reset()
        simulator.client_pin(sub_command=0x01, pin=b"1234")

        result = simulator.client_pin(sub_command=0x06)
        assert result["ok"], result
        assert result["key_agreement"]
        hash_enc = base64.b64decode(result["key_agreement"])
        assert len(hash_enc) > 0

    def test_pin_retry_counter_decrement(self, simulator):
        """Retries deve decrementar em tentativa falha."""
        simulator.reset()
        simulator.client_pin(sub_command=0x01, pin=b"1234")

        simulator.client_pin(sub_command=0x02, pin=b"0000", new_pin=b"9999")
        assert simulator.client_pin(sub_command=0x03)["retries"] == 7

        simulator.client_pin(sub_command=0x02, pin=b"0000", new_pin=b"9999")
        assert simulator.client_pin(sub_command=0x03)["retries"] == 6

    def test_pin_block_after_max_retries(self, simulator):
        """PIN deve bloquear apos retries abaixo do threshold (powerCycleState)."""
        simulator.reset()
        simulator.client_pin(sub_command=0x01, pin=b"1234")

        for _ in range(6):
            simulator.client_pin(sub_command=0x02, pin=b"0000", new_pin=b"9999")

        result = simulator.client_pin(sub_command=0x03)
        assert result["power_cycle_state"] is True

    def test_get_pin_token_wrong_pin(self, simulator):
        """getPINToken com PIN errado deve retornar PinInvalid."""
        simulator.reset()
        simulator.client_pin(sub_command=0x01, pin=b"1234")

        result = simulator.client_pin(sub_command=0x05, pin=b"9999")
        assert not result["ok"]
        assert result["code"] == ERR_PIN_INVALID

    def test_get_pin_token_no_pin_set(self, simulator):
        """getPINToken sem PIN configurado deve retornar PinRequired."""
        simulator.reset()
        result = simulator.client_pin(sub_command=0x05, pin=b"1234")
        assert not result["ok"]
        assert result["code"] == ERR_PIN_REQUIRED

    def test_get_pin_hash_enc_no_pin_set(self, simulator):
        """getPINHashEnc sem PIN configurado deve retornar PinRequired."""
        simulator.reset()
        result = simulator.client_pin(sub_command=0x06)
        assert not result["ok"]
        assert result["code"] == ERR_PIN_REQUIRED
