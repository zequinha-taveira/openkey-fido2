"""Testes do wrapper flash_rp2350 (dry-run sem HW)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"
FLASH = TOOLS_DIR / "flash_rp2350.py"


def run_flash(*args):
    return subprocess.check_output([sys.executable, str(FLASH), *args], text=True)


def test_dry_run_default_auto():
    out = run_flash("--dry-run", "--json")
    data = json.loads(out)
    assert data["dry_run"] is True
    assert data["chip"] == "RP235x"
    assert "probe_rs" in data and "picotool" in data
    assert data["probe_rs"]["would_run"] is True
    assert "download" in " ".join(data["probe_rs"]["cmd"])
    assert data["vid"] == "0x1209" and data["pid"] == "0x1"


def test_dry_run_yubikey_identity():
    out = run_flash("--dry-run", "--yubikey5-identity", "--json")
    data = json.loads(out)
    assert data["vid"] == "0x1050" and data["pid"] == "0x407"


def test_dry_run_yubikey4_alias_matches_yubikey5():
    out4 = run_flash("--dry-run", "--yubikey4-identity", "--json")
    out5 = run_flash("--dry-run", "--yubikey5-identity", "--json")
    data4 = json.loads(out4)
    data5 = json.loads(out5)
    assert data4["vid"] == data5["vid"] == "0x1050"
    assert data4["pid"] == data5["pid"] == "0x407"


def test_dry_run_vid_pid_override():
    out = run_flash("--dry-run", "--vid", "0x1209", "--pid", "0x0001", "--json")
    data = json.loads(out)
    assert data["vid"] == "0x1209" and data["pid"] == "0x1"


def test_dry_run_release_elf():
    out = run_flash("--dry-run", "--release", "--json")
    data = json.loads(out)
    assert "release" in data["elf"]


def test_dry_run_picotool_poll():
    out = run_flash("--dry-run", "--method", "picotool", "--poll", "--json")
    data = json.loads(out)
    assert "picotool" in data
    assert "poll" in data and data["poll"]["would_poll"] is True
    assert data["method"] == "picotool"


def test_dry_run_validates_args_without_hw():
    # Deve sair 0 mesmo sem HW ou ELF inexistente (dry-run)
    result = subprocess.run([sys.executable, str(FLASH), "--dry-run", "--elf", "/tmp/fake.elf", "--json"], capture_output=True, text=True)
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["dry_run"] is True
    # elf_exists false mas não falha em dry-run
    assert data["elf_exists"] is False
