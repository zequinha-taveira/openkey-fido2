#!/usr/bin/env python3
"""Wrapper de gravação do RP2350 — probe-rs (SWD) + fallback UF2 (BOOTSEL).

Fluxo:
  1. Resolve ELF/UF2 (debug/release, yubikey5-identity)
  2. Tenta probe-rs `download --chip RP235x <elf>` (+ `reset`)
  3. Fallback: `picotool uf2 convert <elf> -t elf <uf2> -t uf2` (requer BOOT mass-storage RP2350)
  4. Poll de enumeração USB VID:PID (Windows Get-PnpDevice / Linux lsusb)

Uso sem HW:
  python tools/flash_rp2350.py --dry-run
  python tools/flash_rp2350.py --dry-run --yubikey5-identity --release
  python tools/flash_rp2350.py --dry-run --method picotool --elf path/to.elf

Com HW:
  python tools/flash_rp2350.py --method probe-rs
  python tools/flash_rp2350.py --method picotool
  python tools/flash_rp2350.py --method auto
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CHIP = "RP235x"
DEFAULT_VID_PID = (0x1209, 0x0001)  # pid.codes openkey
YUBIKEY_VID_PID = (0x1050, 0x0407)

ELF_DEBUG = REPO_ROOT / "examples" / "rp2350-firmware" / "target" / "thumbv8m.main-none-eabihf" / "debug" / "rp2350-firmware"
ELF_RELEASE = REPO_ROOT / "examples" / "rp2350-firmware" / "target" / "thumbv8m.main-none-eabihf" / "release" / "rp2350-firmware"


def _resolve_elf(release: bool, elf_arg: str | None) -> Path:
    if elf_arg:
        return Path(elf_arg)
    return ELF_RELEASE if release else ELF_DEBUG


def _resolve_vid_pid(yubikey: bool, vid_arg: str | None, pid_arg: str | None) -> tuple[int, int]:
    if vid_arg is not None or pid_arg is not None:
        vid = int(vid_arg, 0) if vid_arg else DEFAULT_VID_PID[0]
        pid = int(pid_arg, 0) if pid_arg else DEFAULT_VID_PID[1]
        return vid, pid
    return YUBIKEY_VID_PID if yubikey else DEFAULT_VID_PID


def poll_usb(vid: int, pid: int, timeout: float = 10.0) -> dict:
    """Poll de enumeração USB cross-platform. Retorna dict JSON-serializável."""
    system = platform.system()
    deadline = time.time() + timeout
    pattern_vid = f"{vid:04X}"
    pattern_pid = f"{pid:04X}"

    while time.time() < deadline:
        if system == "Windows":
            # PowerShell Get-PnpDevice — sem HW retorna lista vazia
            try:
                ps = (
                    f"Get-PnpDevice | Where-Object {{ $_.InstanceId -match 'VID_{pattern_vid}&PID_{pattern_pid}' }} "
                    f"| Select-Object FriendlyName,InstanceId,Status | ConvertTo-Json"
                )
                out = subprocess.check_output(
                    ["powershell", "-NoProfile", "-Command", ps],
                    text=True,
                    timeout=5,
                ).strip()
                if out:
                    # Pode ser objeto único ou array
                    data = json.loads(out)
                    devices = data if isinstance(data, list) else [data]
                    if devices and any(d.get("InstanceId") for d in devices):
                        return {"found": True, "method": "Get-PnpDevice", "devices": devices, "vid": hex(vid), "pid": hex(pid)}
                # Tenta também classe SmartCardReader para interface CCID
            except Exception:
                pass
        else:
            # Linux / macOS — lsusb
            lsusb = shutil.which("lsusb")
            if lsusb:
                try:
                    out = subprocess.check_output([lsusb], text=True, timeout=5)
                    needle = f"{vid:04x}:{pid:04x}"
                    if needle in out.lower():
                        lines = [l for l in out.splitlines() if needle in l.lower()]
                        return {"found": True, "method": "lsusb", "lines": lines, "vid": hex(vid), "pid": hex(pid)}
                except Exception:
                    pass
            else:
                # Fallback: /sys/bus/usb/devices
                try:
                    import os

                    for dev in Path("/sys/bus/usb/devices").glob("*/idVendor"):
                        v = dev.read_text().strip()
                        p = (dev.parent / "idProduct").read_text().strip()
                        if v.lower() == f"{vid:04x}" and p.lower() == f"{pid:04x}":
                            return {"found": True, "method": "sysfs", "path": str(dev.parent), "vid": hex(vid), "pid": hex(pid)}
                except Exception:
                    pass
        time.sleep(0.5)

    return {"found": False, "vid": hex(vid), "pid": hex(pid), "timeout": timeout, "method": "poll"}


def run_probe_rs(elf: Path, chip: str, dry_run: bool) -> dict:
    cmd = ["probe-rs", "download", "--chip", chip, str(elf)]
    if dry_run:
        return {"cmd": cmd, "dry_run": True, "would_run": True}
    if not elf.exists():
        return {"cmd": cmd, "error": f"ELF não encontrado: {elf}", "would_run": False}
    if shutil.which("probe-rs") is None:
        return {"cmd": cmd, "error": "probe-rs não encontrado no PATH", "would_run": False}
    try:
        subprocess.check_call(cmd)
        subprocess.check_call(["probe-rs", "reset", "--chip", chip])
        return {"cmd": cmd, "ok": True}
    except subprocess.CalledProcessError as e:
        return {"cmd": cmd, "error": repr(e), "ok": False}
    except Exception as e:
        return {"cmd": cmd, "error": repr(e), "ok": False}


def run_picotool(elf: Path, uf2: Path | None, dry_run: bool) -> dict:
    if uf2 is None:
        uf2 = elf.with_suffix(".uf2") if elf.suffix else Path(str(elf) + ".uf2")
    cmd = ["picotool", "uf2", "convert", str(elf), "-t", "elf", str(uf2), "-t", "uf2"]
    if dry_run:
        return {"cmd": cmd, "dry_run": True, "would_run": True, "elf": str(elf), "uf2": str(uf2)}
    if not elf.exists():
        return {"cmd": cmd, "error": f"ELF não encontrado: {elf}", "would_run": False}
    picotool = shutil.which("picotool")
    # Em Windows pode estar em .cargo/bin/picotool.exe
    if picotool is None and (REPO_ROOT / "target").exists():
        # fallback: tenta via cargo
        pass
    if picotool is None:
        # Tenta encontrar no PATH + cargo bin
        cargo_bin = Path.home() / ".cargo" / "bin" / "picotool.exe"
        if cargo_bin.exists():
            picotool = str(cargo_bin)
    if picotool is None:
        return {"cmd": cmd, "error": "picotool não encontrado no PATH", "would_run": False}
    try:
        subprocess.check_call(cmd)
        return {"cmd": cmd, "ok": True, "uf2": str(uf2)}
    except subprocess.CalledProcessError as e:
        return {"cmd": cmd, "error": repr(e), "ok": False}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--elf", help="caminho do ELF (default: examples/rp2350-firmware/target/.../rp2350-firmware)")
    p.add_argument("--uf2", help="caminho de saída UF2 (picotool)")
    p.add_argument("--chip", default=DEFAULT_CHIP, help=f"chip probe-rs (default: {DEFAULT_CHIP})")
    p.add_argument("--release", action="store_true", help="usa ELF release em vez de debug")
    p.add_argument("--yubikey5-identity", action="store_true", help="usa VID:PID 1050:0407 (opt-in, não para distribuição)")
    p.add_argument("--yubikey4-identity", action="store_true", help="alias de --yubikey5-identity (família YubiKey 4/5, mesmo 1050:0407)")
    p.add_argument("--vid", help="VID hex override (ex: 0x1209)")
    p.add_argument("--pid", help="PID hex override (ex: 0x0001)")
    p.add_argument("--method", choices=["auto", "probe-rs", "picotool"], default="auto", help="método de gravação")
    p.add_argument("--dry-run", action="store_true", help="valida args e mostra comandos sem tocar HW")
    p.add_argument("--poll", action="store_true", help="após gravar, poll USB VID:PID")
    p.add_argument("--poll-timeout", type=float, default=10.0, help="timeout do poll USB (s)")
    p.add_argument("--json", action="store_true", help="saída JSON (CI)")
    args = p.parse_args(argv)

    elf = _resolve_elf(args.release, args.elf)
    yubikey = args.yubikey5_identity or args.yubikey4_identity
    vid, pid = _resolve_vid_pid(yubikey, args.vid, args.pid)

    result: dict = {
        "elf": str(elf),
        "elf_exists": elf.exists(),
        "chip": args.chip,
        "method": args.method,
        "vid": hex(vid),
        "pid": hex(pid),
        "dry_run": args.dry_run,
    }

    # Validação de args — dry-run deve passar sem HW
    if args.dry_run:
        errors = []
        if not args.elf and not elf.exists():
            # Não é erro fatal em dry-run: apenas reporta would_run
            result["elf_warning"] = f"ELF não existe ainda: {elf} (rode cargo build em examples/rp2350-firmware)"
        # Valida VID/PID hex
        try:
            int(hex(vid), 16)
            int(hex(pid), 16)
        except Exception as e:
            errors.append(f"VID/PID inválido: {e}")
        if errors:
            result["errors"] = errors
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print("dry-run falhou:", errors, file=sys.stderr)
            return 2

        # Mostra comandos que seriam executados
        if args.method in ("auto", "probe-rs"):
            pr = run_probe_rs(elf, args.chip, dry_run=True)
            result["probe_rs"] = pr
        if args.method in ("auto", "picotool"):
            pt = run_picotool(elf, Path(args.uf2) if args.uf2 else None, dry_run=True)
            result["picotool"] = pt
        if args.poll:
            result["poll"] = {"would_poll": True, "vid": hex(vid), "pid": hex(pid), "timeout": args.poll_timeout}

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"[dry-run] ELF: {elf} ({'existe' if elf.exists() else 'não existe — build pendente'})")
            print(f"[dry-run] chip: {args.chip}  method: {args.method}  VID:PID {vid:04x}:{pid:04x}")
            if "probe_rs" in result:
                print(f"[dry-run] would run: {' '.join(result['probe_rs']['cmd'])}")
            if "picotool" in result:
                print(f"[dry-run] would run: {' '.join(result['picotool']['cmd'])}")
            if args.poll:
                print(f"[dry-run] would poll USB {vid:04x}:{pid:04x} por {args.poll_timeout}s via Get-PnpDevice/lsusb")
            print("[dry-run] OK — args válidos sem HW")
        return 0

    # Execução real
    if args.method in ("probe-rs", "auto"):
        pr = run_probe_rs(elf, args.chip, dry_run=False)
        result["probe_rs"] = pr
        if pr.get("ok"):
            if args.poll:
                result["poll"] = poll_usb(vid, pid, timeout=args.poll_timeout)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"probe-rs OK — {elf} gravado via SWD")
                if args.poll:
                    print(f"poll USB {vid:04x}:{pid:04x}: {'found' if result['poll'].get('found') else 'not found'}")
            return 0
        else:
            if args.method == "probe-rs":
                if args.json:
                    print(json.dumps(result, indent=2))
                else:
                    print(f"probe-rs falhou: {pr.get('error')}", file=sys.stderr)
                return 1
            # auto → fallback picotool
            if not args.json:
                print(f"probe-rs falhou ({pr.get('error')}), tentando picotool...", file=sys.stderr)

    # picotool
    pt = run_picotool(elf, Path(args.uf2) if args.uf2 else None, dry_run=False)
    result["picotool"] = pt
    if pt.get("ok"):
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"picotool OK — UF2 {pt.get('uf2')} gerado (copie para unidade RP2350)")
        if args.poll:
            poll_res = poll_usb(vid, pid, timeout=args.poll_timeout)
            result["poll"] = poll_res
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"poll USB {vid:04x}:{pid:04x}: {'found' if poll_res.get('found') else 'not found'}")
        return 0
    else:
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"picotool falhou: {pt.get('error')}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
