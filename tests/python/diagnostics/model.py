"""Modelo de camadas da pilha openkey-fido2 e escopo de correção de cada uma.

Fonte única usada por `test_fault_injection.py`, `test_wire_regression.py`
e pelo runner de diagnóstico. Cada camada conhece os arquivos que a possuem:
a correção atribuída a uma camada NÃO deve vazar para arquivos de outra.
"""

from __future__ import annotations

from enum import Enum


class Layer(Enum):
    """Camadas da pilha, da mais externa à mais interna."""

    FRAMING = "FRAMING/TRANSPORTE (run_raw_cbor no simulador)"
    DISPATCH = "DESPACHO CTAP2 (Ctap2Command::from_u8 + process_command)"
    CODEC = "CODEC CBOR (decode_cbor do request / encode da resposta)"
    VALIDATION = "VALIDAÇÃO DE REQUEST (handler semântico do comando)"
    STATE = "ESTADO DO AUTENTICADOR (storage/sessão PIN/transações)"


ERROR_NAMES = {
    0x00: "SUCCESS",
    0x01: "INVALID_COMMAND",
    0x02: "INVALID_PARAMETER",
    0x03: "INVALID_LENGTH",
    0x05: "TIMEOUT",
    0x12: "INVALID_CBOR",
    0x14: "MISSING_PARAMETER",
    0x19: "CREDENTIAL_EXCLUDED/EXISTS",
    0x26: "UNSUPPORTED_ALGORITHM",
    0x27: "OPERATION_DENIED",
    0x2E: "NO_CREDENTIALS",
    0x30: "NOT_ALLOWED",
    0x31: "PIN_INVALID",
    0x32: "PIN_BLOCKED",
    0x33: "PIN_AUTH_INVALID",
    0x35: "PIN_NOT_SET",
    0x7F: "OTHER/UNSPECIFIED",
}

# Sentinelas para comportamentos que não produzem byte de status.
OUTCOME_DISCARDED = "DISCARDED"
OUTCOME_EOF_NO_STATUS = "EOF_NO_STATUS"

#: Atribuição camada ← código de status no fio. Códigos fora deste mapa são
#: reportados como camada desconhecida.
CODE_TO_LAYER = {
    0x01: Layer.DISPATCH,
    0x12: Layer.CODEC,
    0x14: Layer.VALIDATION,
    0x19: Layer.VALIDATION,
    0x26: Layer.VALIDATION,
    0x27: Layer.STATE,
    0x30: Layer.STATE,
    0x2E: Layer.STATE,
    0x31: Layer.STATE,
    0x33: Layer.STATE,
    0x35: Layer.STATE,
}

#: Escopo de correção por camada: globs de arquivos que a camada possui
#: (relativos à raiz do repo) + símbolos-âncora onde a decisão vive.
LAYER_FIX_SCOPE: dict[Layer, dict] = {
    Layer.FRAMING: {
        "paths": ["simulator/src/main.rs", "firmware/transport/src/ctaphid/**"],
        "anchors": ["simulator/src/main.rs :: run_raw_cbor"],
    },
    Layer.DISPATCH: {
        "paths": ["protocol/ctap2/src/ctap2.rs"],
        "anchors": [
            "protocol/ctap2/src/ctap2.rs :: Ctap2Command::from_u8",
            "protocol/ctap2/src/ctap2.rs :: process_command",
        ],
    },
    Layer.CODEC: {
        "paths": ["protocol/ctap2/src/*.rs"],
        "anchors": [
            "protocol/ctap2/src/ctap2.rs :: decode_cbor / structs serde",
        ],
    },
    Layer.VALIDATION: {
        "paths": ["protocol/ctap2/src/*.rs"],
        "anchors": [
            "protocol/ctap2/src/ctap2.rs :: make_credential / get_assertion",
            "protocol/ctap2/src/client_pin.rs :: handle_client_pin",
            "protocol/ctap2/src/authnr_config.rs :: handle_authnr_config",
            "protocol/ctap2/src/hmac_secret.rs",
        ],
    },
    Layer.STATE: {
        "paths": [
            "protocol/ctap2/src/*.rs",
            "firmware/storage/src/**",
            "firmware/authenticator/src/**",
        ],
        "anchors": [
            "protocol/ctap2/src/ctap2.rs :: handle_get_next_assertion / handle_enumerate_rps_*",
            "protocol/ctap2/src/client_pin.rs :: retry counter",
            "firmware/storage/src/storage.rs",
        ],
    },
}


def name(code) -> str:
    """Nome legível de um outcome (status ou sentinela)."""
    if isinstance(code, str):
        return code
    return ERROR_NAMES.get(code, f"0x{code:02X}")


def layer_of(code) -> str:
    """Camada responsável por um outcome; desconhecida se fora do mapa."""
    layer = CODE_TO_LAYER.get(code)
    return layer.value if layer else "CAMADA DESCONHECIDA"


def fix_scope(layer: Layer) -> tuple[list[str], list[str]]:
    """Retorna (globs de arquivos, âncoras-símbolo) da camada."""
    scope = LAYER_FIX_SCOPE[layer]
    return list(scope["paths"]), list(scope["anchors"])
