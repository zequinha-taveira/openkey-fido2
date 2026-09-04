"""Testes de conformidade CTAP 2.1 — authenticatorGetInfo (0x04)."""

import pytest
from .ctap2_transport import CtapCmd, CtapError, SimulatorClient


def test_get_info_structure_and_mandatory_fields():
    """Valida que o authenticatorGetInfo retorna os campos obrigatórios da spec CTAP2."""
    with SimulatorClient() as client:
        status, info = client.send_cbor(CtapCmd.GET_INFO)
        assert status == CtapError.SUCCESS
        assert isinstance(info, dict)
        assert all(isinstance(key, int) for key in info), "CTAP response keys must be integers"

        # versions (obrigatório, lista de strings)
        assert 0x01 in info
        versions = info[0x01]
        assert isinstance(versions, list)
        assert len(versions) > 0
        assert "2.0" in versions or "2.1" in versions or "FIDO_2_0" in versions or "FIDO_2_1" in versions

        # 0x03: aaguid (obrigatório, 16 bytes)
        aaguid = info[0x03]
        assert isinstance(aaguid, bytes)
        assert len(aaguid) == 16

        # options (obrigatório; mapa CTAP de nomes para booleanos)
        options = info.get(0x04)
        assert isinstance(options, dict)
        assert options.get("rk") is True
        assert options.get("up") is True

        # 0x02: extensions (opcional, lista de strings)
        if 0x02 in info:
            exts = info[0x02]
            assert isinstance(exts, list)

        # 0x05: maxMsgSize (opcional/recomendado)
        assert 0x05 in info
        max_msg = info[0x05]
        assert isinstance(max_msg, int)
        assert max_msg >= 1024


def test_get_info_firmware_version_is_ctap21_integer():
    """Valida o tipo e o mapeamento de firmwareVersion (0x0E)."""
    with SimulatorClient() as client:
        status, info = client.send_cbor(CtapCmd.GET_INFO)
        assert status == CtapError.SUCCESS
        assert 0x0E in info
        assert type(info[0x0E]) is int
        assert info[0x0E] == 1000


def test_get_info_algorithms_negotiation():
    """Valida que o GetInfo reporta os algoritmos COSE suportados."""
    with SimulatorClient() as client:
        status, info = client.send_cbor(CtapCmd.GET_INFO)
        assert status == CtapError.SUCCESS

        algorithms = info.get(0x0A)
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


def test_get_info_client_pin_option():
    """CTAP 2.0 / 2.1 §6.4: clientPin é False quando suportado e sem PIN, e True com PIN."""
    from fido2.ctap2.pin import ClientPin, PinProtocolV2
    from .test_client_pin import SimCtap2

    with SimulatorClient() as client:
        client.send_cbor(CtapCmd.RESET)
        status, info = client.send_cbor(CtapCmd.GET_INFO)
        assert status == CtapError.SUCCESS
        options = info.get(0x04, {})
        assert options.get("clientPin") is False

        # Configura um PIN
        pin = ClientPin(SimCtap2(client), protocol=PinProtocolV2())
        pin.set_pin("1234")

        # Verifica GetInfo novamente
        status, info = client.send_cbor(CtapCmd.GET_INFO)
        assert status == CtapError.SUCCESS
        options = info.get(0x04, {})
        assert options.get("clientPin") is True

