"""Fluxo real de diagnóstico: executar → injetar → capturar → atribuir → travar.

Uso (a partir de `tests/python/`):

    python -m diagnostics.runner                    # diagnóstico completo
    python -m diagnostics.runner --layer STATE      # só uma camada
    python -m diagnostics.runner --json report.json # relatório estruturado
    python -m diagnostics.runner --lock             # trava baseline no fio
    python -m diagnostics.runner --check-scope STATE  # guarda de escopo do diff

Ciclo:
1. EXECUTA cada caso do catálogo contra um simulador recém-iniciado;
2. INJETA a falha e CAPTURA o outcome no fio (status, sentinela ou exceção
   com traceback completo);
3. ATRIBUI a camada responsável comparando com o golden master
   (`wire_baseline.json`) e aponta os arquivos/símbolos donos da correção;
4. REGRESSÃO AUTOMÁTICA: `--lock` grava o comportamento atual como baseline,
   e `test_wire_regression.py` reexecuta o catálogo contra o baseline em
   toda suíte — qualquer retorno de erro antigo quebra o CI.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
import sys
import traceback
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .catalog import FAULT_CATALOG, ControlFailure, FaultCase
from conformance.ctap2_transport import SimulatorClient
from .json_client import JsonSimulator
from .model import Layer, fix_scope, layer_of, name

BASELINE_PATH = Path(__file__).resolve().parent / "wire_baseline.json"
REPO_ROOT = BASELINE_PATH.parents[2]


@dataclass
class CaseResult:
    id: str
    layer: str
    description: str
    expected: object  # valor travado no baseline (None = ausente)
    observed: object | None
    verdict: str  # PASS | MISSING | DRIFT | EXCEPTION | CONTROL_FAIL | INTERNAL_ERROR
    detail: str = ""
    traceback_text: str = ""


def load_baseline() -> dict:
    if not BASELINE_PATH.is_file():
        return {}
    # utf-8-sig tolera BOM de editores Windows.
    data = json.loads(BASELINE_PATH.read_text(encoding="utf-8-sig"))
    return data.get("outcomes", {})


def lock_baseline(outcomes: dict[str, object]) -> None:
    payload = {
        "_meta": {
            "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "cases": len(outcomes),
            "note": (
                "Golden master dos outcomes no fio por caso do catálogo. "
                "Atualize SOMENTE com 'python -m diagnostics.runner --lock' "
                "após mudança intencional de comportamento, junto com a "
                "correção atribuída à camada responsável."
            ),
        },
        "outcomes": outcomes,
    }
    BASELINE_PATH.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def run_case(case: FaultCase) -> CaseResult:
    """Executa um caso: injeta a falha e captura o resultado bruto."""
    result = CaseResult(
        id=case.id,
        layer=case.layer.value,
        description=case.description,
        expected=load_baseline().get(case.id),
        observed=None,
        verdict="INTERNAL_ERROR",
    )
    client = JsonSimulator() if case.kind == "json" else SimulatorClient()
    try:
        result.observed = case.provoke(client)
    except ControlFailure as exc:
        result.verdict = "CONTROL_FAIL"
        result.detail = str(exc)
        return result
    except Exception:
        result.verdict = "EXCEPTION"
        result.traceback_text = traceback.format_exc()
        return result
    finally:
        client.close()

    if result.expected is None:
        result.verdict = "MISSING"
        result.detail = "sem entrada no baseline; rode --lock após revisar"
    elif result.observed == result.expected:
        result.verdict = "PASS"
    else:
        result.verdict = "DRIFT"
        result.detail = (
            f"baseline=0x{result.expected:02X} ({name(result.expected)}) "
            f"observado=0x{result.observed:02X} ({name(result.observed)})"
            if isinstance(result.expected, int) and isinstance(result.observed, int)
            else f"baseline={result.expected!r} observado={result.observed!r}"
        )
    return result


def diagnose(results: list[CaseResult]) -> list[CaseResult]:
    """Enriquece falhas com camada responsável + escopo de correção."""
    for result in results:
        if result.verdict in ("PASS", "MISSING"):
            continue
        layer = _layer_enum(result.layer)
        paths, anchors = fix_scope(layer)
        result.detail += (
            f"\n         camada responsável: {layer.value}"
            f"\n         correção restrita a: {', '.join(anchors)}"
            f"\n         arquivos da camada: {', '.join(paths[:3])}..."
        )
    return results


def _layer_enum(layer_value: str) -> Layer:
    for layer in Layer:
        if layer.value == layer_value:
            return layer
    raise ValueError(f"camada desconhecida: {layer_value}")


def print_report(results: list[CaseResult], problems: int) -> None:
    total = len(results)
    passed = sum(1 for r in results if r.verdict == "PASS")
    print("═" * 78)
    print(f"DIAGNÓSTICO DE FALHAS openkey-fido2 — {passed}/{total} PASS")
    print("═" * 78)
    icons = {
        "PASS": "[OK]     ",
        "DRIFT": "[DRIFT]  ",
        "MISSING": "[SEM-BASE]",
        "EXCEPTION": "[EXCEÇÃO]",
        "CONTROL_FAIL": "[CONTROLE]",
        "INTERNAL_ERROR": "[INTERNO]",
    }
    for r in results:
        print(f"{icons[r.verdict]} {r.id:<42} {r.verdict}")
        if r.verdict == "PASS":
            continue
        print(f"          {r.description}")
        if r.detail:
            print(f"          {r.detail}")
        if r.traceback_text:
            last = r.traceback_text.strip().splitlines()
            print(f"          {last[-1] if last else ''}")

    if problems:
        print("-" * 78)
        print(f"{problems} caso(s) exigem atenção. Fluxo:")
        print("  1. rode o caso isolado e reproduza a exceção/falha;")
        print("  2. corrija APENAS na camada apontada (veja escopo acima);")
        print("  3. se a mudança foi intencional, atualize o catálogo/testes")
        print("     e trave com: python -m diagnostics.runner --lock;")
        print("  4. pytest tests/python/test_wire_regression.py garante que o")
        print("     erro não volta.")
    print("═" * 78)


# ---------------------------------------------------------------------------
# Guarda de escopo: correção de uma camada não pode vazar para outra
# ---------------------------------------------------------------------------


def changed_files() -> list[str]:
    def git(*args: str) -> list[str]:
        out = subprocess.run(
            ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True
        )
        return [line.strip() for line in out.stdout.splitlines() if line.strip()]

    tracked = git("diff", "--name-only", "HEAD")
    untracked = git("ls-files", "--others", "--exclude-standard")
    return [p.replace("\\", "/") for p in tracked + untracked]


def check_scope(layer_name: str) -> int:
    layer = Layer[layer_name.upper()]
    allowed_globs, _ = fix_scope(layer)
    offenders: list[tuple[str, str]] = []
    for path in changed_files():
        if path.startswith(("tests/python/diagnostics/", "tests/python/test_wire")):
            continue  # o próprio fluxo de diagnóstico é sempre permitido
        if not any(fnmatch.fnmatch(path, glob) for glob in allowed_globs):
            owner_layer = next(_layer_ownership(path), None)
            offenders.append((path, owner_layer.value if owner_layer else "?"))
    if not offenders:
        print(f"[ESCOTO-OK] diff atual pertence apenas à camada {layer.name}.")
        return 0
    print(f"[FORA-DE-ESCOPO] correção de {layer.name} tocando arquivos de outras camadas:")
    for path, owner in offenders:
        print(f"  - {path}  (pertence a: {owner})")
    return 1


def _layer_ownership(path: str):
    """Itera as camadas que possuem o caminho (pode ser mais de uma)."""
    from .model import LAYER_FIX_SCOPE

    for layer, scope in LAYER_FIX_SCOPE.items():
        if any(fnmatch.fnmatch(path, glob) for glob in scope["paths"]):
            yield layer


def main(argv: list[str] | None = None) -> int:
    # Console Windows pode estar em cp1252; relatórios usam UTF-8.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--layer", choices=[l.name for l in Layer],
                        help="filtra casos por camada")
    parser.add_argument("--json", metavar="PATH", help="grava relatório estruturado")
    parser.add_argument("--lock", action="store_true",
                        help="trava o comportamento atual como novo baseline")
    parser.add_argument("--list", action="store_true", help="lista os casos do catálogo")
    parser.add_argument("--check-scope", metavar="LAYER",
                        help="verifica se o diff git respeita o escopo da camada")
    args = parser.parse_args(argv)

    if args.list:
        for case in FAULT_CATALOG:
            print(f"{case.layer.name:<11} {case.id:<44} {case.description}")
        return 0

    if args.check_scope:
        return check_scope(args.check_scope)

    cases = [
        c for c in FAULT_CATALOG
        if args.layer is None or c.layer.name == args.layer.upper()
    ]
    results = diagnose([run_case(c) for c in cases])

    problems = sum(1 for r in results if r.verdict != "PASS")
    print_report(results, problems)

    if args.lock:
        merged = load_baseline()
        added = updated = 0
        for r in results:
            if r.observed is None:
                continue
            if merged.get(r.id) != r.observed:
                if r.id in merged:
                    print(f"[LOCK] alteração intencional travada: {r.id}: "
                          f"{merged[r.id]!r} → {r.observed!r}")
                    updated += 1
                else:
                    added += 1
                merged[r.id] = r.observed
        lock_baseline(merged)
        print(f"[LOCK] baseline atualizado ({BASELINE_PATH}): "
              f"+{added} novos, ~{updated} alterados.")

    if args.json:
        Path(args.json).write_text(
            json.dumps([asdict(r) for r in results], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"[JSON] relatório gravado em {args.json}")

    return 1 if problems and not args.lock else 0


if __name__ == "__main__":
    sys.exit(main())
