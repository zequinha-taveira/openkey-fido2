"""Cliente JSON line-protocol para operações de conveniência do simulador.

Mesmo protocolo usado por test_algorithms.py/test_client_pin.py, centralizado
aqui para o fluxo de diagnóstico (falhas da camada STATE via PIN).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parents[3]


def simulator_binary() -> Path:
    exe = ".exe" if sys.platform == "win32" else ""
    sim = WORKSPACE_ROOT / "target" / "debug" / f"fido2-simulator{exe}"
    if not sim.is_file():
        raise FileNotFoundError(
            "fido2-simulator não encontrado; execute 'cargo build -p fido2-simulator'."
        )
    return sim


class JsonSimulator:
    """Um processo do simulador falando JSON por linha no stdio."""

    def __init__(self) -> None:
        self.proc = subprocess.Popen(
            [str(simulator_binary())],
            cwd=WORKSPACE_ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )

    def send(self, payload: dict) -> dict:
        line = json.dumps(payload, separators=(",", ":"))
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        response = self.proc.stdout.readline()
        if not response:
            raise RuntimeError("simulador encerrou prematuramente")
        return json.loads(response)

    def client_pin(self, sub_command: int, pin: bytes | None = None) -> dict:
        req: dict = {"op": "client_pin", "sub_command": sub_command}
        if pin is not None:
            import base64

            req["pin"] = base64.b64encode(pin).decode("ascii")
        return self.send(req)

    def close(self) -> None:
        if self.proc.poll() is None:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
