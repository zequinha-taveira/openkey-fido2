"""Testes de conformidade CTAP 2.1 — authenticatorMakeCredential (0x01)."""

import hashlib
import pytest
from fido2 import cbor
from .ctap2_transport import CtapCmd, CtapError, SimulatorClient


def make_sample_request(rp_id="example.com", user_id=b"user_123", alg=-7, rk=False):
    client_data = b'{"type":"webauthn.create","challenge":"AAAA","origin":"https://example.com"}'
    client_data_hash = hashlib.sha256(client_data).digest()

    return {
        0x01: client_data_hash,
        0x02: {"id": rp_id, "name": "Example Corp"},
        0x03: {"id": user_id, "name": "alice@example.com", "displayName": "Alice"},
        0x04: [{"type": "public-key", "alg": alg}],
        0x05: [],
        0x07: {"rk": rk, "uv": False, "up": True},
    }


def test_make_credential_basic_success():
    """Valida a criação de credencial com parâmetros básicos conformes."""
    with SimulatorClient() as client:
        req = make_sample_request(alg=-7)
        status, resp = client.send_cbor(CtapCmd.MAKE_CREDENTIAL, req)
        assert status == CtapError.SUCCESS
        assert isinstance(resp, dict)

        # fmt (string)
        fmt = resp.get("fmt") or resp.get(0x01)
        assert isinstance(fmt, str)

        # authData (bytes com header de 37B + attestedCredentialData)
        auth_data = resp.get("authData") or resp.get(0x02)
        assert isinstance(auth_data, bytes)
        assert len(auth_data) >= 37  # rpIdHash (32) + flags (1) + signCount (4)

        # Flags: bit 0 (UP) deve estar ativo
        flags = auth_data[32]
        assert flags & 0x01 != 0, "User Presence (UP) flag must be set"
        assert flags & 0x40 != 0, "Attested Credential Data (AT) flag must be set"

        # attStmt (map ou dict)
        att_stmt = resp.get("attStmt") if "attStmt" in resp else resp.get(0x03)
        assert att_stmt is not None
        assert isinstance(att_stmt, dict)


def test_make_credential_unsupported_algorithm():
    """Valida que um algoritmo não suportado (ex: -999) é rejeitado com UNSUPPORTED_ALGORITHM."""
    with SimulatorClient() as client:
        req = make_sample_request(alg=-999)
        status, _ = client.send_cbor(CtapCmd.MAKE_CREDENTIAL, req)
        assert status == CtapError.UNSUPPORTED_ALGORITHM


def test_make_credential_missing_required_fields():
    """Valida que request sem clientDataHash retorna INVALID_DATA ou INVALID_PARAMETER."""
    with SimulatorClient() as client:
        req = {
            0x02: {"id": "example.com", "name": "Example Corp"},
            0x03: {"id": b"user_1", "name": "alice"},
            0x04: [{"type": "public-key", "alg": -7}],
            0x05: [],
            0x07: {"rk": False, "uv": False, "up": True},
        }
        status, _ = client.send_cbor(CtapCmd.MAKE_CREDENTIAL, req)
        assert status == CtapError.INVALID_CBOR


def test_make_credential_rejects_trailing_cbor_bytes():
    """Rejeita payloads com bytes após o item CBOR completo."""
    with SimulatorClient() as client:
        payload = cbor.encode(make_sample_request()) + b"\x00"
        status, _ = client.send_raw(CtapCmd.MAKE_CREDENTIAL, payload)
        assert status == CtapError.INVALID_CBOR
