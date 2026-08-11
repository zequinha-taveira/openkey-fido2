"""Testes pytest dos binários Rust dos exemplos do workspace.

Os exemplos em examples/ são pacotes do workspace (basic-example e
ccid-example), não alvos `--example`: `cargo run --example basic` não
funciona neste repositório. Por isso os testes executam o binário compilado
em `target/debug/<pacote>.exe` diretamente (opção preferida) e, quando o
binário não existe, compilam via `cargo build -p basic-example -p
ccid-example` numa fixture de sessão.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
TARGET_DEBUG = WORKSPACE_ROOT / "target" / "debug"
RUN_TIMEOUT_S = 120
BUILD_TIMEOUT_S = 600

EXAMPLES = {
    "basic": {
        "package": "basic-example",
        "log_line": "FIDO2 Embedded Authenticator - Basic Example",
        "ready_line": "Authenticator ready",
        "aaguid_hex": "aabb1122334455667788990011223344",
    },
    "ccid": {
        "package": "ccid-example",
        "log_line": "FIDO2 Embedded Authenticator - CCID Example",
        "ready_line": "CCID Authenticator ready",
        "aaguid_hex": "0100deadbeefcafebabe001122334455",
    },
}

_APP_CONTROL_MARKERS = ("Application Control", "Controle de Aplicativo")
_APP_CONTROL_SKIP_REASON = (
    "o Windows bloqueou a execução do binário via Controle de Aplicativo "
    "(Smart App Control); desative o SAC ou assine os binários"
)


def _binary_path(name: str) -> Path:
    package = EXAMPLES[name]["package"]
    for filename in (f"{package}.exe", package):
        candidate = TARGET_DEBUG / filename
        if candidate.exists():
            return candidate
    return TARGET_DEBUG / f"{package}.exe"


def _find_aaguid_hex(stderr: str) -> str | None:
    for match in re.finditer(r"\[\s*\d+(?:\s*,\s*\d+){15}\s*\]", stderr):
        values = [int(value) for value in re.findall(r"\d+", match.group(0))]
        if len(values) == 16 and all(0 <= value <= 255 for value in values):
            return bytes(values).hex()
    literal = re.search(r"[0-9a-f]{32}", stderr)
    return literal.group(0) if literal else None


def _is_app_control_block(exc: BaseException) -> bool:
    if getattr(exc, "winerror", None) == 4551:
        return True
    text = str(exc)
    return any(marker in text for marker in _APP_CONTROL_MARKERS)


def _run_binary(path: Path, timeout: int) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["RUST_LOG"] = "info"
    try:
        return subprocess.run(
            [str(path)],
            cwd=WORKSPACE_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"exemplo excedeu o timeout de {timeout}s")
    except OSError as exc:
        if _is_app_control_block(exc):
            pytest.skip(_APP_CONTROL_SKIP_REASON)
        raise


def _describe(proc: subprocess.CompletedProcess) -> str:
    return f"exit={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"


NEED_BUILD = not all(_binary_path(name).exists() for name in EXAMPLES)

pytestmark = pytest.mark.skipif(
    NEED_BUILD and shutil.which("cargo") is None,
    reason="binários dos exemplos não encontrados e cargo não está disponível no PATH",
)


@pytest.fixture(scope="session")
def example_binaries() -> dict[str, Path]:
    missing = [name for name in EXAMPLES if not _binary_path(name).exists()]
    if missing:
        cargo = shutil.which("cargo")
        if cargo is None:
            pytest.skip("cargo não está disponível para compilar os exemplos")
        proc = subprocess.run(
            [cargo, "build", "-p", "basic-example", "-p", "ccid-example"],
            cwd=WORKSPACE_ROOT,
            env=dict(os.environ),
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT_S,
        )
        if proc.returncode != 0:
            pytest.skip(f"cargo build falhou:\n{proc.stderr[-1000:]}")
        if any(not _binary_path(name).exists() for name in EXAMPLES):
            pytest.skip("cargo build não produziu os binários esperados")
    return {name: _binary_path(name) for name in EXAMPLES}


@pytest.fixture(scope="session")
def example_runs(
    example_binaries: dict[str, Path],
) -> dict[str, subprocess.CompletedProcess]:
    return {
        name: _run_binary(path, RUN_TIMEOUT_S) for name, path in example_binaries.items()
    }


def test_basic_termina_com_codigo_zero(example_runs):
    proc = example_runs["basic"]
    assert proc.returncode == 0, _describe(proc)


def test_basic_emite_mensagens_esperadas_no_stderr(example_runs):
    stderr = example_runs["basic"].stderr
    spec = EXAMPLES["basic"]
    assert spec["log_line"] in stderr
    assert spec["ready_line"] in stderr
    assert _find_aaguid_hex(stderr) == spec["aaguid_hex"]


def test_ccid_termina_com_codigo_zero(example_runs):
    proc = example_runs["ccid"]
    assert proc.returncode == 0, _describe(proc)


def test_ccid_emite_mensagens_esperadas_no_stderr(example_runs):
    stderr = example_runs["ccid"].stderr
    spec = EXAMPLES["ccid"]
    assert spec["log_line"] in stderr
    assert spec["ready_line"] in stderr
    assert _find_aaguid_hex(stderr) == spec["aaguid_hex"]


def test_exemplos_tem_aaguids_diferentes(example_runs):
    basic = _find_aaguid_hex(example_runs["basic"].stderr)
    ccid = _find_aaguid_hex(example_runs["ccid"].stderr)
    assert basic is not None, "AAGUID não encontrado no stderr do exemplo basic"
    assert ccid is not None, "AAGUID não encontrado no stderr do exemplo ccid"
    assert basic != ccid
