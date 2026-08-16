"""Testes de conformidade CTAP 2.1 — authenticatorCredentialManagement (0x0A)."""

import hashlib
import pytest
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from .ctap2_transport import CtapCmd, CtapError, SimulatorClient
from .test_client_pin import SimCtap2


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


def test_credential_management_pin_uv_auth_param():
    """Credential Management autentica `subCommand || subCommandParams`."""
    client = SimulatorClient()
    with client:
        pin = ClientPin(SimCtap2(client), protocol=PinProtocolV2())
        pin.set_pin("1234")
        token = pin.get_pin_token("1234", permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT)
        pin_uv_param = pin.protocol.authenticate(token, bytes([0x01]))

        request = {0x01: 0x01, 0x03: 0x02, 0x04: pin_uv_param}
        status, response = client.send_cbor(CtapCmd.CRED_MGMT, request)
        assert status == CtapError.SUCCESS
        assert response[0x01] == 0

        request[0x04] = b"\x00" * 32
        status, _ = client.send_cbor(CtapCmd.CRED_MGMT, request)
        assert status == CtapError.PIN_AUTH_INVALID
