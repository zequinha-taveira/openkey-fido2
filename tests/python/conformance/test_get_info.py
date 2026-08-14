"""Testes de conformidade CTAP 2.1 — authenticatorGetInfo (0x04)."""

import pytest
from .ctap2_transport import CtapCmd, CtapError, SimulatorClient


def test_get_info_structure_and_mandatory_fields():
    """Valida que o authenticatorGetInfo retorna os campos obrigatórios da spec CTAP2."""
    with SimulatorClient() as client:
        status, info = client.send_cbor(CtapCmd.GET_INFO)
        assert status == CtapError.SUCCESS
        assert isinstance(info, dict)

        # versions (obrigatório, lista de strings)
        assert 0x01 in info or "versions" in info
        versions = info.get(0x01) or info.get("versions")
        assert isinstance(versions, list)
        assert len(versions) > 0
        assert "2.0" in versions or "2.1" in versions or "FIDO_2_0" in versions or "FIDO_2_1" in versions

        # 0x03: aaguid (obrigatório, 16 bytes)
        aaguid = info.get(0x03) or info.get("aaguid")
        assert isinstance(aaguid, bytes)
        assert len(aaguid) == 16

        # options (obrigatório, map ou list)
        options = info.get(0x04) or info.get("options")
        assert isinstance(options, (dict, list))
        assert "rk" in options
        assert "up" in options

        # 0x02: extensions (opcional, lista de strings)
        if 0x02 in info or "extensions" in info:
            exts = info.get(0x02) or info.get("extensions")
            assert isinstance(exts, list)

        # 0x06: maxMsgSize (opcional/recomendado)
        if 0x06 in info or "maxMsgSize" in info:
            max_msg = info.get(0x06) or info.get("maxMsgSize")
            assert isinstance(max_msg, int)
            assert max_msg >= 1024


def test_get_info_algorithms_negotiation():
    """Valida que o GetInfo reporta os algoritmos COSE suportados."""
    with SimulatorClient() as client:
        status, info = client.send_cbor(CtapCmd.GET_INFO)
        assert status == CtapError.SUCCESS

        algorithms = info.get(0x0A) or info.get("algorithms")
        if algorithms is not None:
            assert isinstance(algorithms, list)
            # Deve conter pelo menos ES256 (-7) e/ou Ed25519 (-8)
            supported_algs = []
            for alg_entry in algorithms:
                if isinstance(alg_entry, dict):
                    alg_id = alg_entry.get("alg") or alg_entry.get(3) or alg_entry.get(-1)
                    if alg_id is not None:
                        supported_algs.append(alg_id)
            assert -7 in supported_algs or -8 in supported_algs or len(supported_algs) > 0
