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


def test_credential_management_returns_pin_not_set_when_no_pin():
    """CTAP 2.1 §6.8: Credential Management sem PIN configurado retorna PIN_NOT_SET (0x35)."""
    with SimulatorClient() as client:
        client.send_cbor(CtapCmd.RESET)
        status, _ = client.send_cbor(CtapCmd.CRED_MGMT, {0x01: 0x01})
        assert status == CtapError.PIN_NOT_SET


def test_credential_management_enumerate_rps_and_creds_with_python_fido2(cm_session):
    """Exercita a API de referência do python-fido2 (CredentialManagement)."""
    from fido2.ctap2.credman import CredentialManagement

    class FullSimCtap2(SimCtap2):
        def credential_mgmt(
            self,
            sub_cmd: int,
            sub_cmd_params: dict | None = None,
            pin_uv_protocol: int | None = None,
            pin_uv_param: bytes | None = None,
        ):
            req = {0x01: sub_cmd}
            if sub_cmd_params is not None:
                req[0x02] = sub_cmd_params
            if pin_uv_protocol is not None:
                req[0x03] = pin_uv_protocol
            if pin_uv_param is not None:
                req[0x04] = pin_uv_param
            status, response = self._client.send_cbor(CtapCmd.CRED_MGMT, req)
            if status != 0:
                raise CtapError(status)
            return response

    ctap = FullSimCtap2(cm_session.client)
    credman = CredentialManagement(ctap, cm_session.pin.protocol, cm_session.token)

    # 1. Verifica metadata inicial
    meta = credman.get_metadata()
    assert meta[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 0
    assert meta[CredentialManagement.RESULT.MAX_REMAINING_COUNT] > 0

    # 2. Cria credencial residente (rk: True)
    make_cred_req = {
        0x01: b"\x11" * 32,
        0x02: {"id": "example.com", "name": "Example Corp"},
        0x03: {"id": b"user-42", "name": "alice", "displayName": "Alice"},
        0x04: [{"type": "public-key", "alg": -8}],
        0x07: {"rk": True, "up": True},
    }
    status, _ = cm_session.client.send_cbor(CtapCmd.MAKE_CREDENTIAL, make_cred_req)
    assert status == CtapError.SUCCESS

    # 3. Enumerate RPs
    rps = credman.enumerate_rps()
    assert len(rps) == 1
    rp_entry = rps[0]
    assert CredentialManagement.RESULT.RP in rp_entry
    assert rp_entry[CredentialManagement.RESULT.RP]["id"] == "example.com"
    assert CredentialManagement.RESULT.RP_ID_HASH in rp_entry
    assert CredentialManagement.RESULT.TOTAL_RPS in rp_entry
    assert rp_entry[CredentialManagement.RESULT.TOTAL_RPS] == 1

    # 4. Enumerate Credentials para este RP
    rp_hash = rp_entry[CredentialManagement.RESULT.RP_ID_HASH]
    creds = credman.enumerate_creds(rp_hash)
    assert len(creds) == 1
    cred = creds[0]
    assert CredentialManagement.RESULT.USER in cred
    assert cred[CredentialManagement.RESULT.USER]["id"] == b"user-42"
    assert CredentialManagement.RESULT.CREDENTIAL_ID in cred
    assert CredentialManagement.RESULT.PUBLIC_KEY in cred
    # Valida formato COSE_Key da chave pública
    pub_key = cred[CredentialManagement.RESULT.PUBLIC_KEY]
    assert isinstance(pub_key, dict)
    assert pub_key.get(1) == 1  # kty: OKP
    assert pub_key.get(3) == -8  # alg: EdDSA

    # 5. Delete credential
    cred_id = cred[CredentialManagement.RESULT.CREDENTIAL_ID]
    credman.delete_cred(cred_id)

    # 6. Confirma que não há mais credenciais
    meta_after = credman.get_metadata()
    assert meta_after[CredentialManagement.RESULT.EXISTING_CRED_COUNT] == 0

