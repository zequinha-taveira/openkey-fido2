"""Testes de conformidade CTAP 2.1 — authenticatorGetAssertion (0x02)."""

import hashlib
import struct
import pytest
from .ctap2_transport import CtapCmd, CtapError, SimulatorClient


def extract_credential_id(auth_data: bytes) -> bytes:
    """Extrai o credentialId a partir do attestedCredentialData em authData."""
    # authData: rpIdHash (32) + flags (1) + signCount (4) + aaguid (16) + credIdLen (2) + credId
    assert len(auth_data) >= 55
    cred_id_len = struct.unpack(">H", auth_data[53:55])[0]
    return auth_data[55 : 55 + cred_id_len]


def test_get_assertion_lifecycle():
    """Valida ciclo completo: MakeCredential -> GetAssertion -> Incremento do signCount."""
    with SimulatorClient() as client:
        # 1. Reset para estado limpo
        status, _ = client.send_cbor(CtapCmd.RESET)
        assert status == CtapError.SUCCESS

        # 2. MakeCredential
        client_data_1 = b'{"type":"webauthn.create","challenge":"c1"}'
        cdh_1 = hashlib.sha256(client_data_1).digest()
        mc_req = {
            "clientDataHash": cdh_1,
            "rp": {"id": "test.example.com", "name": "Test RP"},
            "user": {"id": b"usr_42", "name": "bob@example.com"},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "excludeList": [],
            "options": {"rk": False, "uv": False, "up": True},
        }
        status, mc_resp = client.send_cbor(CtapCmd.MAKE_CREDENTIAL, mc_req)
        assert status == CtapError.SUCCESS
        auth_data_mc = mc_resp.get("authData") or mc_resp.get(0x02)
        cred_id = extract_credential_id(auth_data_mc)
        assert len(cred_id) > 0

        # 3. GetAssertion #1
        client_data_2 = b'{"type":"webauthn.get","challenge":"c2"}'
        cdh_2 = hashlib.sha256(client_data_2).digest()
        ga_req = {
            "rpId": "test.example.com",
            "clientDataHash": cdh_2,
            "credentials": [],
            "allowList": [{"type": "public-key", "id": cred_id}],
            "options": {"up": True, "uv": False},
        }
        status, ga_resp_1 = client.send_cbor(CtapCmd.GET_ASSERTION, ga_req)
        assert status == CtapError.SUCCESS
        auth_data_ga1 = ga_resp_1.get("authData") or ga_resp_1.get(0x02)
        sig_1 = ga_resp_1.get("signature") or ga_resp_1.get(0x03)
        assert len(auth_data_ga1) >= 37
        assert len(sig_1) > 0

        sign_count_1 = struct.unpack(">I", auth_data_ga1[33:37])[0]

        # 4. GetAssertion #2 (verificar incremento do sign count)
        status, ga_resp_2 = client.send_cbor(CtapCmd.GET_ASSERTION, ga_req)
        assert status == CtapError.SUCCESS
        auth_data_ga2 = ga_resp_2.get("authData") or ga_resp_2.get(0x02)
        sign_count_2 = struct.unpack(">I", auth_data_ga2[33:37])[0]

        assert sign_count_2 > sign_count_1


def test_get_assertion_no_credentials():
    """Valida que requisição com allowList inexistente retorna NO_CREDENTIALS."""
    with SimulatorClient() as client:
        # Reset para garantir banco vazio
        client.send_cbor(CtapCmd.RESET)

        ga_req = {
            "rpId": "unknown.example.com",
            "clientDataHash": hashlib.sha256(b"dummy").digest(),
            "credentials": [],
            "allowList": [{"type": "public-key", "id": b"nonexistent_cred_id"}],
            "options": {"up": True, "uv": False},
        }
        status, _ = client.send_cbor(CtapCmd.GET_ASSERTION, ga_req)
        assert status == CtapError.NO_CREDENTIALS

