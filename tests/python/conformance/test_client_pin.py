"""Testes de conformidade CTAP 2.1 — authenticatorClientPIN (0x06)."""

import pytest
from .ctap2_transport import CtapCmd, CtapError, SimulatorClient


def test_client_pin_retries_and_flow():
    """Valida o subcomando getPINRetries (0x03) do ClientPIN."""
    with SimulatorClient() as client:
        pin_req = {
            "subCommand": 0x03,  # getPINRetries
            "pinProtocol": 1,
        }
        status, resp = client.send_cbor(CtapCmd.CLIENT_PIN, pin_req)
        assert status == CtapError.SUCCESS
        assert isinstance(resp, dict)

        retries = resp.get("retries") or resp.get(0x03)
        assert isinstance(retries, int)
        assert retries >= 1
