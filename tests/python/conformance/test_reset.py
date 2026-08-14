"""Testes de conformidade CTAP 2.1 — authenticatorReset (0x07)."""

import hashlib
import pytest
from .ctap2_transport import CtapCmd, CtapError, SimulatorClient


def test_reset_clears_stored_credentials():
    """Valida que authenticatorReset remove todas as credenciais e restaura estado inicial."""
    with SimulatorClient() as client:
        # 1. Criar credencial
        cdh = hashlib.sha256(b"challenge_data").digest()
        mc_req = {
            "clientDataHash": cdh,
            "rp": {"id": "reset-test.com", "name": "Reset Test RP"},
            "user": {"id": b"user_reset", "name": "user@reset.com"},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "excludeList": [],
            "options": {"rk": False, "uv": False, "up": True},
        }
        status, mc_resp = client.send_cbor(CtapCmd.MAKE_CREDENTIAL, mc_req)
        assert status == CtapError.SUCCESS

        # 2. Reset
        status, _ = client.send_cbor(CtapCmd.RESET)
        assert status == CtapError.SUCCESS

        # 3. GetAssertion na credencial anterior deve retornar NO_CREDENTIALS
        auth_data = mc_resp.get("authData") or mc_resp.get(0x02)
        from .test_get_assertion import extract_credential_id

        cred_id = extract_credential_id(auth_data)

        ga_req = {
            "rpId": "reset-test.com",
            "clientDataHash": cdh,
            "credentials": [],
            "allowList": [{"type": "public-key", "id": cred_id}],
            "options": {"up": True, "uv": False},
        }
        status, _ = client.send_cbor(CtapCmd.GET_ASSERTION, ga_req)
        assert status == CtapError.NO_CREDENTIALS
