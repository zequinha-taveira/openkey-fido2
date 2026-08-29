"""Focused tests for the repository's cross-platform build entry points.

The POSIX script is exercised with a fake Rust toolchain so these tests verify
command selection without compiling the workspace.  The Windows script cannot
be executed on every test host, so its parser and release command blocks are
checked as a static contract; actual Windows CI can then cover ``cmd.exe``
semantics separately.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
SHELL_SCRIPT = REPO_ROOT / "build_openkey_fido2.sh"
BATCH_SCRIPT = REPO_ROOT / "build_openkey_fido2.bat"


def _write_fake_command(directory: Path, name: str) -> None:
    command = directory / name
    command.write_text(
        """#!/usr/bin/env bash
printf '%s' "$(basename "$0")" >> "$COMMAND_LOG"
printf '\\t%s' "$@" >> "$COMMAND_LOG"
printf '\\n' >> "$COMMAND_LOG"

if [[ "$1" == "--version" ]]; then
    printf '%s fake 1.0\\n' "$(basename "$0")"
fi

if [[ -n "${FAKE_FAIL_ON:-}" && "$1" == "$FAKE_FAIL_ON" ]]; then
    exit "${FAKE_EXIT_CODE:-1}"
fi
""",
        encoding="utf-8",
    )
    command.chmod(0o755)


@pytest.fixture
def fake_toolchain(tmp_path: Path) -> Dict[str, object]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for command in ("cargo", "rustc"):
        _write_fake_command(bin_dir, command)

    command_log = tmp_path / "commands.log"
    env = os.environ.copy()
    env.update(
        {
            "COMMAND_LOG": str(command_log),
            "PATH": os.pathsep.join((str(bin_dir), "/usr/bin", "/bin")),
        }
    )
    return {"env": env, "log": command_log}


def _run_shell(
    args: Sequence[str],
    *,
    env: Dict[str, str],
    cwd: Optional[Path] = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(SHELL_SCRIPT), *args],
        cwd=cwd or REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def _logged_calls(command_log: Path, command: str) -> List[List[str]]:
    if not command_log.exists():
        return []
    return [
        line.split("\t")[1:]
        for line in command_log.read_text(encoding="utf-8").splitlines()
        if line.split("\t", 1)[0] == command
    ]


@pytest.mark.parametrize("args", [[], ["--debug"]])
def test_shell_debug_workspace_build_uses_unlocked_debug_command(
    fake_toolchain: Dict[str, object], args: Sequence[str]
) -> None:
    result = _run_shell(args, env=fake_toolchain["env"])

    assert result.returncode == 0, result.stderr
    assert _logged_calls(fake_toolchain["log"], "cargo") == [
        ["--version"],
        ["build", "--workspace"],
    ]
    assert "Ação : workspace" in result.stdout
    assert "Modo : debug" in result.stdout


def test_shell_release_workspace_build_is_locked(
    fake_toolchain: Dict[str, object],
) -> None:
    """Regression: a release invocation must not silently run a debug build."""
    result = _run_shell(["--release"], env=fake_toolchain["env"])

    assert result.returncode == 0, result.stderr
    assert _logged_calls(fake_toolchain["log"], "cargo")[-1] == [
        "build",
        "--workspace",
        "--release",
        "--locked",
    ]
    assert "Modo : release" in result.stdout


@pytest.mark.parametrize(
    ("option", "expected"),
    [
        ("--sim", ["build", "-p", "fido2-simulator"]),
        ("--simulator", ["build", "-p", "fido2-simulator"]),
        ("--test", ["test", "--workspace"]),
        ("--tests", ["test", "--workspace"]),
        ("--clippy", ["clippy", "--workspace", "--all-targets", "--", "-D", "warnings"]),
        ("--fmt", ["fmt", "--all", "--", "--check"]),
        ("--fmt-check", ["fmt", "--all", "--", "--check"]),
    ],
)
def test_shell_action_and_alias_dispatch(
    fake_toolchain: Dict[str, object], option: str, expected: List[str]
) -> None:
    result = _run_shell([option], env=fake_toolchain["env"])

    assert result.returncode == 0, result.stderr
    assert _logged_calls(fake_toolchain["log"], "cargo")[-1] == expected


def test_shell_all_runs_validation_steps_in_order(
    fake_toolchain: Dict[str, object],
) -> None:
    result = _run_shell(["--all"], env=fake_toolchain["env"])

    assert result.returncode == 0, result.stderr
    assert _logged_calls(fake_toolchain["log"], "cargo")[1:] == [
        ["build", "--workspace"],
        ["test", "--workspace"],
        ["clippy", "--workspace", "--all-targets", "--", "-D", "warnings"],
        ["fmt", "--all", "--", "--check"],
    ]


def test_shell_propagates_cargo_failure_and_omits_success_banner(
    fake_toolchain: Dict[str, object],
) -> None:
    env = fake_toolchain["env"].copy()
    env.update({"FAKE_FAIL_ON": "build", "FAKE_EXIT_CODE": "23"})

    result = _run_shell(["--release"], env=env)

    assert result.returncode == 23
    assert "BUILD CONCLUÍDO" not in result.stdout


def test_shell_help_does_not_require_rust_toolchain(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["PATH"] = os.pathsep.join(("/usr/bin", "/bin"))

    result = _run_shell(["--help"], env=env, cwd=tmp_path)

    assert result.returncode == 0
    assert "Uso:" in result.stdout
    assert "--release" in result.stdout
    assert "não encontrado" not in result.stderr


def test_shell_rejects_unknown_option_before_running_toolchain(
    fake_toolchain: Dict[str, object],
) -> None:
    result = _run_shell(["--definitely-unknown"], env=fake_toolchain["env"])

    assert result.returncode != 0
    assert "Opção desconhecida" in result.stderr
    assert _logged_calls(fake_toolchain["log"], "cargo") == []


def test_shell_script_has_valid_bash_syntax() -> None:
    result = subprocess.run(
        ["bash", "-n", str(SHELL_SCRIPT)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def _batch_source() -> str:
    return BATCH_SCRIPT.read_text(encoding="utf-8").replace("\r\n", "\n")


def _batch_section(label: str) -> str:
    match = re.search(
        rf"(?ms)^:{re.escape(label)}\s*$\n(.*?)(?=^:[A-Za-z0-9_-]+\s*$|\Z)",
        _batch_source(),
    )
    assert match is not None, f"batch label not found: {label}"
    return match.group(1)


def test_batch_release_parser_preserves_action_and_consumes_more_options() -> None:
    """Regression contract for combinations such as ``--sim --release``."""
    parser = _batch_section("parse_args")
    release_branch = re.search(
        r'if /I "%~1"=="--release" \((.*?)\n\)', parser, re.DOTALL
    )

    assert release_branch is not None
    assert 'set "MODE=release"' in release_branch.group(1)
    assert 'set "ACTION=' not in release_branch.group(1)
    assert "shift" in release_branch.group(1)
    assert "goto :parse_args" in release_branch.group(1)


@pytest.mark.parametrize(
    ("label", "release_command", "debug_command", "failure_guard"),
    [
        (
            "workspace",
            "cargo build --workspace --release --locked",
            "cargo build --workspace",
            "if errorlevel 1 exit /b 1",
        ),
        (
            "sim",
            "cargo build -p fido2-simulator --release --locked",
            "cargo build -p fido2-simulator",
            "if errorlevel 1 exit /b 1",
        ),
        (
            "rp2350",
            "cargo build --release --locked",
            "cargo build",
            'if not "%RC%"=="0" exit /b %RC%',
        ),
    ],
)
def test_batch_build_sections_select_release_and_debug_commands(
    label: str, release_command: str, debug_command: str, failure_guard: str
) -> None:
    section = _batch_section(label)

    assert 'if /I "%MODE%"=="release" (' in section
    assert release_command in section
    assert re.search(rf"\) else \(\s+{re.escape(debug_command)}\s+\)", section)
    assert failure_guard in section


@pytest.mark.parametrize(
    ("option", "action"),
    [
        ("--sim", "sim"),
        ("--rp2350", "rp2350"),
        ("--rp2350-uf2", "rp2350-uf2"),
        ("--nrf52840", "nrf52840"),
        ("--check", "check"),
        ("--test", "test"),
        ("--clippy", "clippy"),
        ("--fmt", "fmt"),
        ("--all", "all"),
        ("--clean", "clean"),
    ],
)
def test_batch_parser_and_run_dispatch_cover_each_documented_action(
    option: str, action: str
) -> None:
    parser = _batch_section("parse_args")
    run = _batch_section("run")

    assert re.search(
        rf'if /I "%~1"=="{re.escape(option)}" \(.*?'
        rf'set "ACTION={re.escape(action)}".*?goto :parse_args\s+\)',
        parser,
        re.DOTALL,
    )
    assert f'if /I "%ACTION%"=="{action}" goto :{action}' in run


def test_batch_all_stops_after_each_failed_step() -> None:
    section = _batch_section("all")

    assert re.findall(r"call :(workspace|test|clippy|fmt)", section) == [
        "workspace",
        "test",
        "clippy",
        "fmt",
    ]
    assert section.count("if errorlevel 1 exit /b 1") == 4
