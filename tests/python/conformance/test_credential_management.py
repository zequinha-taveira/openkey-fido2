"""Testes de conformidade CTAP 2.1 — authenticatorCredentialManagement (0x0A)."""

import hashlib
import pytest
from .ctap2_transport import CtapCmd, CtapError, SimulatorClient


def test_credential_management_metadata():
    """Valida subcomando getCredsMetadata (0x01) de Credential Management."""
    with SimulatorClient() as client:
        # Reset para estado conhecido
        client.send_cbor(CtapCmd.RESET)

        req = {"subCommand": 0x01}
        status, resp = client.send_cbor(CtapCmd.CRED_MGMT, req)
        assert status == CtapError.SUCCESS
        existing = resp.get("existingResidentCredentialsCount")
        if existing is None:
            existing = resp.get(0x01)
        assert existing == 0

        remaining = resp.get("maxPossibleRemainingResidentCredentialsCount")
        if remaining is None:
            remaining = resp.get(0x02)
        assert remaining is not None and remaining >= 0
