"""Testes de conformidade CTAP 2.1 — authenticatorCredentialManagement (0x0A)."""

import pytest
from fido2 import cbor
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from .ctap2_transport import CtapCmd, CtapError, SimulatorClient
from .test_client_pin import SimCtap2


class CredMgmtSession:
    """Simulador com PIN configurado e token de permissão `cm`.

    CTAP 2.1 §6.12: todo subcomando de Credential Management exige um
    pinUvAuthToken com permissão `cm` — inclusive quando nenhum PIN está
    configurado, pois as respostas expõem user handles/nomes e permitem
    exclusão de credenciais residentes.
    """

    def __init__(self) -> None:
        self.client = SimulatorClient()
        self.client.__enter__()
        # Reset para estado conhecido
        self.client.send_cbor(CtapCmd.RESET)

        self.pin = ClientPin(SimCtap2(self.client), protocol=PinProtocolV2())
        self.pin.set_pin("1234")
        self.token = self.pin.get_pin_token(
            "1234", permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT
        )

    def close(self) -> None:
        self.client.close()

    def signed_request(self, sub_command: int, params: dict | None = None) -> dict:
        """Request autenticado: MAC sobre `subCommand || subCommandParams`.

        O autenticador reconstrói a mensagem como `subCommand (1 byte)` +
        os bytes CBOR de `subCommandParams` exatamente como chegaram; o
        encoder do python-fido2 é determinístico (CBOR canônico do CTAP2),
        então codificar o dict separadamente produz os mesmos bytes.
        """
        message = bytes([sub_command])
        request = {0x01: sub_command, 0x03: 0x02}
        if params is not None:
            message += cbor.encode(params)
            request[0x02] = params
        request[0x04] = self.pin.protocol.authenticate(self.token, message)
        return request


@pytest.fixture
def cm_session():
    session = CredMgmtSession()
    try:
        yield session
    finally:
        session.close()


def test_credential_management_requires_pin_uv_auth_without_token(cm_session):
    """getCredsMetadata sem pinUvAuthParam é negado com PIN_REQUIRED (0x36)."""
    status, _ = cm_session.client.send_cbor(
        CtapCmd.CRED_MGMT, {"subCommand": 0x01}
    )
    assert status == CtapError.PIN_REQUIRED


def test_credential_management_metadata(cm_session):
    """Valida subcomando getCredsMetadata (0x01) autenticado por token."""
    request = cm_session.signed_request(0x01)
    status, resp = cm_session.client.send_cbor(CtapCmd.CRED_MGMT, request)
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
