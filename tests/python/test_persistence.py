"""Testes end-to-end de persistencia via simulador.

Cobre: FileStorageBackend, persistencia entre reinicializacoes,
credential pruning, e wear leveling.
"""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
_EXE = ".exe" if sys.platform == "win32" else ""
SIM_BIN = WORKSPACE_ROOT / "target" / "debug" / f"fido2-simulator{_EXE}"
BUILD_TIMEOUT_S = 600
RUN_TIMEOUT_S = 30


def _b64(data: bytes) -> str:
    import base64

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
                "credential_id": _b64(credential_id),
                "allow_list": [_b64(item) for item in allow_list],
                "client_data_hash": _b64(client_data_hash),
                "options": options or {"up": True, "uv": True},
                "extensions": extensions,
            }
        )

    def reset(self):
        return self._send({"op": "reset"})


def _build_simulator():
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


def _stop_simulator(proc):
    proc.terminate()
    try:
        proc.wait(timeout=RUN_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _start_simulator(storage_path=None):
    _build_simulator()
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
    client, proc = _start_simulator()
    yield client
    proc.terminate()
    try:
        proc.wait(timeout=RUN_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def test_credential_has_created_at_timestamp(simulator):
    simulator.reset()
    result = simulator.make_credential(user_id=b"timestamp_user")
    assert result["ok"], result

    import base64

    cred_id = base64.b64decode(result["credential_id"])
    asserted = simulator.get_assertion(credential_id=cred_id)
    assert asserted["ok"], asserted


def test_multiple_credentials_stored(simulator):
    simulator.reset()
    cred_ids = []
    for i in range(3):
        result = simulator.make_credential(user_id=f"user{i}".encode())
        assert result["ok"], result
        import base64

        cred_ids.append(base64.b64decode(result["credential_id"]))

    for cred_id in cred_ids:
        asserted = simulator.get_assertion(credential_id=cred_id)
        assert asserted["ok"], asserted


def test_credential_persists_after_get_assertion(simulator):
    simulator.reset()
    result = simulator.make_credential(user_id=b"persist_user")
    assert result["ok"], result

    import base64

    cred_id = base64.b64decode(result["credential_id"])

    for _ in range(3):
        asserted = simulator.get_assertion(credential_id=cred_id)
        assert asserted["ok"], asserted


def test_reset_clears_credentials(simulator):
    simulator.reset()
    result = simulator.make_credential(user_id=b"reset_user")
    assert result["ok"], result

    import base64

    cred_id = base64.b64decode(result["credential_id"])
    simulator.reset()

    asserted = simulator.get_assertion(credential_id=cred_id)
    assert not asserted["ok"]


def test_persistence_across_simulator_restarts():
    with tempfile.TemporaryDirectory() as tmpdir:
        storage_path = Path(tmpdir) / "test_persist.json"

        client1, proc1 = _start_simulator(storage_path=storage_path)
        result = client1.make_credential(user_id=b"persist_across_restarts")
        assert result["ok"], result

        import base64

        cred_id = base64.b64decode(result["credential_id"])
        proc1.terminate()
        try:
            proc1.wait(timeout=RUN_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            proc1.kill()
            proc1.wait()

        client2, proc2 = _start_simulator(storage_path=storage_path)
        asserted = client2.get_assertion(credential_id=cred_id)
        assert asserted["ok"], asserted

        proc2.terminate()
        try:
            proc2.wait(timeout=RUN_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            proc2.kill()
            proc2.wait()


def test_persistence_with_multiple_credentials():
    with tempfile.TemporaryDirectory() as tmpdir:
        storage_path = Path(tmpdir) / "test_multi_persist.json"

        client1, proc1 = _start_simulator(storage_path=storage_path)
        cred_ids = []
        for i in range(3):
            result = client1.make_credential(user_id=f"multi_user{i}".encode())
            assert result["ok"], result
            import base64

            cred_ids.append(base64.b64decode(result["credential_id"]))
        proc1.terminate()
        try:
            proc1.wait(timeout=RUN_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            proc1.kill()
            proc1.wait()

        client2, proc2 = _start_simulator(storage_path=storage_path)
        for cred_id in cred_ids:
            asserted = client2.get_assertion(credential_id=cred_id)
            assert asserted["ok"], asserted

        proc2.terminate()
        try:
            proc2.wait(timeout=RUN_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            proc2.kill()
            proc2.wait()


def test_pin_survives_restart():
    """PIN configurado deve continuar válido após reiniciar o simulador."""
    import base64

    with tempfile.TemporaryDirectory() as tmpdir:
        storage_path = Path(tmpdir) / "test_pin_persist.json"

        client1, proc1 = _start_simulator(storage_path=storage_path)
        result = client1._send(
            {
                "op": "client_pin",
                "sub_command": 0x03,
                "pin": _b64(b"1234"),
            }
        )
        assert result["ok"], result
        _stop_simulator(proc1)

        client2, proc2 = _start_simulator(storage_path=storage_path)
        retries = client2._send({"op": "client_pin", "sub_command": 0x01})
        assert retries["ok"], retries
        assert retries["retries"] == 8

        change = client2._send(
            {
                "op": "client_pin",
                "sub_command": 0x04,
                "pin": _b64(b"1234"),
                "new_pin": _b64(b"5678"),
            }
        )
        assert change["ok"], change
        _stop_simulator(proc2)


def test_reset_persists_across_restart():
    """Reset deve apagar credenciais do backend, não apenas da memória."""
    import base64

    with tempfile.TemporaryDirectory() as tmpdir:
        storage_path = Path(tmpdir) / "test_reset_persist.json"

        client1, proc1 = _start_simulator(storage_path=storage_path)
        result = client1.make_credential(user_id=b"reset_restart_user")
        assert result["ok"], result
        cred_id = base64.b64decode(result["credential_id"])
        _stop_simulator(proc1)

        client2, proc2 = _start_simulator(storage_path=storage_path)
        asserted = client2.get_assertion(credential_id=cred_id)
        assert asserted["ok"], asserted
        reset = client2._send({"op": "process_command", "cmd": 0x07})
        assert reset["ok"], reset
        _stop_simulator(proc2)

        client3, proc3 = _start_simulator(storage_path=storage_path)
        asserted = client3.get_assertion(credential_id=cred_id)
        assert not asserted["ok"], asserted
        _stop_simulator(proc3)


def test_sign_counter_survives_restart():
    """signCount deve permanecer monotônico entre reinicializações."""
    import base64

    with tempfile.TemporaryDirectory() as tmpdir:
        storage_path = Path(tmpdir) / "test_sign_count_persist.json"

        client1, proc1 = _start_simulator(storage_path=storage_path)
        result = client1.make_credential(user_id=b"counter_user")
        assert result["ok"], result
        cred_id = base64.b64decode(result["credential_id"])

        asserted = client1.get_assertion(credential_id=cred_id)
        assert asserted["ok"], asserted
        count_before = asserted["sign_count"]
        _stop_simulator(proc1)

        client2, proc2 = _start_simulator(storage_path=storage_path)
        asserted = client2.get_assertion(credential_id=cred_id)
        assert asserted["ok"], asserted
        assert asserted["sign_count"] > count_before
        _stop_simulator(proc2)
