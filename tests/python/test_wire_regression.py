"""Regressão automática do fio contra o golden master (`wire_baseline.json`).

Reexecuta o catálogo completo de falhas deliberadas em toda suíte e compara
cada outcome com o comportamento travado. Qualquer retorno de um erro antigo
(ex.: 0x05 TIMEOUT no lugar de 0x30 NOT_ALLOWED) quebra aqui — impedindo que
o erro volte sem revisão explícita (`python -m diagnostics.runner --lock`).
"""

from __future__ import annotations

import pytest

from diagnostics.catalog import FAULT_CATALOG, ControlFailure
from diagnostics.json_client import JsonSimulator
from diagnostics.model import fix_scope, layer_of, name
from conformance.ctap2_transport import SimulatorClient


def _load_baseline() -> dict:
    from diagnostics.runner import load_baseline

    return load_baseline()


def test_baseline_covers_entire_catalog():
    """Todo caso do catálogo tem entrada travada — nada escapa da trava."""
    baseline = _load_baseline()
    catalog_ids = {case.id for case in FAULT_CATALOG}
    baseline_ids = set(baseline)

    missing = sorted(catalog_ids - baseline_ids)
    stale = sorted(baseline_ids - catalog_ids)
    assert not missing and not stale, (
        "baseline e catálogo divergiram:\n"
        f"  casos sem baseline (rode --lock): {missing}\n"
        f"  entradas órfãs no baseline (remova): {stale}"
    )


@pytest.mark.parametrize("case", FAULT_CATALOG, ids=lambda c: c.id)
def test_wire_behavior_matches_locked_baseline(case):
    """O outcome no fio deve ser exatamente o travado para este caso."""
    baseline = _load_baseline()
    client = JsonSimulator() if case.kind == "json" else SimulatorClient()
    try:
        observed = case.provoke(client)
    except ControlFailure as exc:
        pytest.fail(f"[{case.id}] CONTROLE POSITIVO QUEBROU: {exc}", pytrace=False)
    finally:
        client.close()

    expected = baseline[case.id]
    assert observed == expected, (
        f"[{case.id}] REGRESSÃO NO FIO: esperado {expected!r} "
        f"({name(expected)}); obtido {observed!r} ({name(observed)}) → "
        f"{layer_of(observed)}.\n"
        f"Se a mudança foi intencional, atualize os testes da camada e trave "
        f"com 'python -m diagnostics.runner --lock'."
    )
