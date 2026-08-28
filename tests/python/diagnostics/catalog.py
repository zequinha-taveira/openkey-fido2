"""Catálogo declarativo de falhas deliberadas por camada.

Cada `FaultCase` sabe provocar exatamente uma falha contra um simulador
recém-iniciado e devolver o OUTCOME observado no fio:

* int          → byte de status CTAP2 retornado;
* DISCARDED    → framing descartou o frame sem gerar resposta;
* EOF_NO_STATUS→ stream morreu antes de qualquer status (falha no framing).

Controles positivos rodam DENTRO de cada caso (`ControlFailure` quando o
caminho feliz está quebrado): assim a rejeição vem da falha injetada, e não
de estado prévio ruim. O valor esperado de cada caso vive travado em
`wire_baseline.json` (golden master), não aqui.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass

from fido2 import cbor

from conformance.ctap2_transport import CtapCmd, SimulatorClient

from .model import Layer, OUTCOME_DISCARDED, OUTCOME_EOF_NO_STATUS


class ControlFailure(AssertionError):
    """O controle positivo falhou: o problema NÃO é a falha injetada."""


def _assert_status(actual: int, expected: int, label: str) -> None:
    if actual != expected:
        raise ControlFailure(
            f"[{label}] controle positivo quebrou: esperado 0x{expected:02X}, "
            f"obtido 0x{actual:02X}. Corrija o caminho feliz antes de diagnosticar."
        )


def sample_make_credential(rp_id="fault.example", alg=-7):
    client_data = b'{"type":"webauthn.create","challenge":"RkFVTFQ","origin":"https://fault.example"}'
    return {
        0x01: hashlib.sha256(client_data).digest(),
        0x02: {"id": rp_id, "name": "Fault Corp"},
        0x03: {"id": b"fault_user", "name": "bob@fault.example", "displayName": "Bob"},
        0x04: [{"type": "public-key", "alg": alg}],
        0x05: [],
        0x07: {"rk": False, "uv": False, "up": True},
    }


# ---------------------------------------------------------------------------
# FRAMING/TRANSPORTE
# ---------------------------------------------------------------------------


def provoke_empty_frame(client: SimulatorClient) -> object:
    client.send_frame(b"\x00\x00")  # total_len == 0 → run_raw_cbor descarta
    status, _ = client.send_cbor(CtapCmd.GET_INFO, None)
    _assert_status(status, 0x00, "framing/empty-frame")
    return OUTCOME_DISCARDED


def provoke_truncated_frame(client: SimulatorClient) -> object:
    client.send_frame(b"\x00\x10" + b"\x04\x00\x00\x00")  # promete 16, envia 4
    client.close_stdin()
    assert client.wait_exited(timeout=5) is not None, (
        "simulador deveria encerrar no EOF do meio do frame"
    )
    try:
        client._read_exact(1)
    except EOFError:
        return OUTCOME_EOF_NO_STATUS
    raise AssertionError("leitura deveria ter levantado EOFError após frame truncado")


def provoke_paramless_tolerant(client: SimulatorClient) -> object:
    """Leniência documentada: comandos sem parâmetros ignoram payload extra."""
    for cmd in (CtapCmd.GET_INFO, CtapCmd.RESET, CtapCmd.SELECTION):
        _assert_status(
            client.send_raw(cmd, b"\xff\xff")[0], 0x00, "leniency/paramless-extra-payload"
        )
    return 0x00


# ---------------------------------------------------------------------------
# DESPACHO CTAP2
# ---------------------------------------------------------------------------


def _unknown_opcode_probe(opcode: int) -> Callable[[SimulatorClient], object]:
    def provoke(client: SimulatorClient) -> object:
        status, _ = client.send_cbor(opcode, b"\xff\xff\xff")  # lixo: despacho precede codec
        return status

    return provoke


# ---------------------------------------------------------------------------
# CODEC CBOR
# ---------------------------------------------------------------------------


def _raw_payload_probe(payload: bytes) -> Callable[[SimulatorClient], object]:
    def provoke(client: SimulatorClient) -> object:
        status, _ = client.send_cbor(CtapCmd.MAKE_CREDENTIAL, payload)
        return status

    return provoke


# ---------------------------------------------------------------------------
# VALIDAÇÃO DE REQUEST
# ---------------------------------------------------------------------------


def provoke_unsupported_algorithm(client: SimulatorClient) -> object:
    _assert_status(
        client.send_cbor(CtapCmd.MAKE_CREDENTIAL, sample_make_credential(alg=-7))[0],
        0x00,
        "validation/unsupported-algorithm",
    )
    status, _ = client.send_cbor(CtapCmd.MAKE_CREDENTIAL, sample_make_credential(alg=-999))
    return status


def _extract_credential_id(response) -> bytes | None:
    auth_data = response.get(0x02)
    if not isinstance(auth_data, bytes) or len(auth_data) < 55:
        return None
    cred_len = int.from_bytes(auth_data[53:55], "big")
    return auth_data[55 : 55 + cred_len]


def provoke_exclude_collision(client: SimulatorClient) -> object:
    status, first = client.send_cbor(CtapCmd.MAKE_CREDENTIAL, sample_make_credential())
    _assert_status(status, 0x00, "validation/exclude-collision")

    stored_id = _extract_credential_id(first)
    assert stored_id is not None, "MakeCredential de controle não retornou authData"

    benign = sample_make_credential()
    benign[0x05] = [{"type": "public-key", "id": b"id-desconhecido"}]
    _assert_status(
        client.send_cbor(CtapCmd.MAKE_CREDENTIAL, benign)[0],
        0x00,
        "validation/exclude-collision/id-novo",
    )

    collision = sample_make_credential()
    collision[0x05] = [{"type": "public-key", "id": stored_id}]
    return client.send_cbor(CtapCmd.MAKE_CREDENTIAL, collision)[0]


# ---------------------------------------------------------------------------
# ESTADO DO AUTENTICADOR
# ---------------------------------------------------------------------------


def provoke_gna_without_transaction(client: SimulatorClient) -> object:
    _assert_status(client.send_cbor(CtapCmd.GET_INFO, None)[0], 0x00, "state/gna-without-txn")
    return client.send_cbor(CtapCmd.GET_NEXT_ASSERTION, None)[0]


def provoke_rps_next_without_initial(client: SimulatorClient) -> object:
    return client.send_cbor(CtapCmd.ENUMERATE_RPS_NEXT, None)[0]


def provoke_rps_initial_empty_storage(client: SimulatorClient) -> object:
    return client.send_cbor(CtapCmd.ENUMERATE_RPS_INITIAL, None)[0]


def provoke_ghost_rp(client: SimulatorClient) -> object:
    request = {
        0x01: "ghost.example",
        0x02: hashlib.sha256(b"assertion").digest(),
        0x05: {"up": True, "uv": False},
    }
    return client.send_cbor(CtapCmd.GET_ASSERTION, request)[0]


def provoke_pin_not_set(client) -> object:
    result = client.client_pin(0x05, pin=b"1234")  # getPINToken
    if result.get("ok"):
        raise ControlFailure(f"[state/pin-not-set] getPINToken sem PIN teve sucesso: {result}")
    return result.get("code")


def provoke_wrong_pin_retries(client) -> object:
    setup = client.client_pin(0x03, pin=b"1234")  # setPIN
    if not setup.get("ok"):
        raise ControlFailure(f"[state/wrong-pin-retries] setPIN falhou: {setup}")

    before = client.client_pin(0x01)
    if before.get("retries") != 8:
        raise ControlFailure(f"[state/wrong-pin-retries] retries inicial != 8: {before}")

    wrong = client.client_pin(0x05, pin=b"9999")
    code = wrong.get("code")

    after = client.client_pin(0x01)
    if after.get("retries") != before["retries"] - 1:
        raise AssertionError(
            f"[state/wrong-pin-retries] retries deveria decrementar exatamente "
            f"uma vez: antes={before['retries']} depois={after['retries']}"
        )
    return code


@dataclass(frozen=True)
class FaultCase:
    id: str
    layer: Layer
    description: str
    provoke: Callable[..., object]
    kind: str = "wire"  # "wire" (SimulatorClient raw-cbor) | "json" (JsonSimulator)


UNKNOWN_OPCODES = [0x10, 0x20, 0x3F, 0x50, 0x7D, 0xFE]


def build_catalog() -> list[FaultCase]:
    valid_request = cbor.encode(sample_make_credential())

    cases: list[FaultCase] = [
        FaultCase("framing/empty-frame-discarded", Layer.FRAMING,
                  "Frame de comprimento zero é descartado sem gerar status.",
                  provoke_empty_frame),
        FaultCase("framing/truncated-frame-eof", Layer.FRAMING,
                  "Frame truncado mata o stream sem qualquer byte de status.",
                  provoke_truncated_frame),

        FaultCase("dispatch/garbage-payload-precedence", Layer.DISPATCH,
                  "Opcode desconhecido com payload inválido → 0x01 (despacho precede codec).",
                  _unknown_opcode_probe(0x7D)),
        FaultCase("leniency/paramless-extra-payload", Layer.FRAMING,
                  "GetInfo/Reset/Selection ignoram payload residual (comportamento documentado).",
                  provoke_paramless_tolerant),
    ]
    cases += [
        FaultCase(f"dispatch/unknown-opcode-0x{op:02X}", Layer.DISPATCH,
                  f"Opcode reservado 0x{op:02X} → INVALID_COMMAND.",
                  _unknown_opcode_probe(op))
        for op in UNKNOWN_OPCODES
    ]

    codec_cases = [
        ("codec/empty-payload", b"", "Payload vazio no MakeCredential."),
        ("codec/break-token", b"\xff", "Token indefinido CBOR isolado."),
        ("codec/truncated-cbor", valid_request[: len(valid_request) // 2],
         "Request válida cortada ao meio."),
        ("codec/wrong-top-level-type", cbor.encode(7), "Inteiro no lugar do mapa."),
    ]
    incomplete = sample_make_credential()
    del incomplete[0x01]  # clientDataHash obrigatório (exigido na desserialização)
    codec_cases.append(("codec/missing-required-field", cbor.encode(incomplete),
                        "Mapa válido sem campo obrigatório → codec, não handler."))

    cases += [
        FaultCase(cid, Layer.CODEC, desc, _raw_payload_probe(payload))
        for cid, payload, desc in codec_cases
    ]

    cases += [
        FaultCase("validation/unsupported-algorithm", Layer.VALIDATION,
                  "CBOR decodificável com algoritmo -999 → UNSUPPORTED_ALGORITHM.",
                  provoke_unsupported_algorithm),
        FaultCase("validation/exclude-collision", Layer.VALIDATION,
                  "excludeList citando credencial do mesmo RP → 0x19.",
                  provoke_exclude_collision),
        FaultCase("state/gna-without-txn", Layer.STATE,
                  "GetNextAssertion sem transação → NOT_ALLOWED (nunca 0x05/TIMEOUT).",
                  provoke_gna_without_transaction),
        FaultCase("state/rpsnext-without-initial", Layer.STATE,
                  "EnumerateRPsNext sem initial → NOT_ALLOWED.",
                  provoke_rps_next_without_initial),
        FaultCase("state/rps-initial-empty-storage", Layer.STATE,
                  "Enumeração inicial sem RPs armazenados → NO_CREDENTIALS.",
                  provoke_rps_initial_empty_storage),
        FaultCase("state/ga-ghost-rp", Layer.STATE,
                  "GetAssertion em RP inexistente → NO_CREDENTIALS.",
                  provoke_ghost_rp),
        FaultCase("state/pin-not-set", Layer.STATE,
                  "getPINToken sem PIN configurado → PIN_NOT_SET.",
                  provoke_pin_not_set, kind="json"),
        FaultCase("state/wrong-pin-retries", Layer.STATE,
                  "PIN errado → PIN_INVALID com decremento único persistente de retries.",
                  provoke_wrong_pin_retries, kind="json"),
    ]
    return cases


FAULT_CATALOG: list[FaultCase] = build_catalog()


def case_ids() -> list[str]:
    return [case.id for case in FAULT_CATALOG]
