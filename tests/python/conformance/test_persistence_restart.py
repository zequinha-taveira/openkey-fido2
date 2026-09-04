"""Testes de persistência com reinício do simulador (wire format CTAP 2.1).

Cobrem, em formato binário cru, que credenciais, signCount, Reset e
large blobs sobrevivem (ou são corretamente apagados) entre reinícios
do processo do simulador.
"""

import contextlib
import hashlib
import shutil
import struct
import tempfile
import time
from pathlib import Path

import pytest

from .ctap2_transport import CtapCmd, CtapError, SimulatorClient


@contextlib.contextmanager
def _storage_tmpdir():
    """TemporaryDirectory com remoção resiliente no Windows.

    O processo do simulador pode reter o handle do arquivo de storage
    por alguns ms após o exit; sem retry, o `shutil.rmtree` do
    `TemporaryDirectory` falha intermitentemente com WinError 145.
    O `SimulatorClient` já garante exit (wait + kill) antes da saída
    deste contexto; o retry cobre apenas a latência residual de
    liberação do handle. Semântica idêntica ao TemporaryDirectory.
    """
    tmpdir = tempfile.mkdtemp()
    try:
        yield tmpdir
    finally:
        for attempt in range(5):
            try:
                shutil.rmtree(tmpdir)
                break
            except OSError:
                if attempt == 4:
                    raise
                time.sleep(0.05 * (attempt + 1))


def _make_credential(client, rp_id="persist.example.com", user_id=b"persist_user"):
    client_data = b'{"type":"webauthn.create","challenge":"persist"}'
    req = {
        "clientDataHash": hashlib.sha256(client_data).digest(),
        "rp": {"id": rp_id, "name": "Persist RP"},
        "user": {"id": user_id, "name": "alice@example.com"},
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "excludeList": [],
        "options": {"rk": False, "uv": False, "up": True},
    }
    status, resp = client.send_cbor(CtapCmd.MAKE_CREDENTIAL, req)
    assert status == CtapError.SUCCESS, status
    auth_data = resp.get("authData") or resp.get(0x02)
    cred_id_len = struct.unpack(">H", auth_data[53:55])[0]
    return auth_data[55 : 55 + cred_id_len]


def _get_assertion(client, cred_id, rp_id="persist.example.com"):
    client_data = b'{"type":"webauthn.get","challenge":"persist"}'
    req = {
        "rpId": rp_id,
        "clientDataHash": hashlib.sha256(client_data).digest(),
        "credentials": [],
        "allowList": [{"type": "public-key", "id": cred_id}],
        "options": {"up": True, "uv": False},
    }
    status, resp = client.send_cbor(CtapCmd.GET_ASSERTION, req)
    if status != CtapError.SUCCESS:
        return status, None
    auth_data = resp.get("authData") or resp.get(0x02)
    sign_count = struct.unpack(">I", auth_data[33:37])[0]
    return status, sign_count


def _config_field(resp):
    """Lê o campo `config` da resposta LargeBlobs, suportando chaves
    inteiras (CBOR) ou textuais sem perder valores vazios."""
    for key in (0x01, "config"):
        value = resp.get(key)
        if value is not None:
            return value
    return None


def test_credentials_survive_restart_wire():
    with _storage_tmpdir() as tmpdir:
        storage_path = Path(tmpdir) / "creds_persist.json"

        with SimulatorClient(storage_path=storage_path) as client:
            client.send_cbor(CtapCmd.RESET)
            cred_id = _make_credential(client)

        with SimulatorClient(storage_path=storage_path) as client:
            status, _ = _get_assertion(client, cred_id)
            assert status == CtapError.SUCCESS, status


def test_reset_clears_credentials_across_restart_wire():
    with _storage_tmpdir() as tmpdir:
        storage_path = Path(tmpdir) / "reset_persist.json"

        with SimulatorClient(storage_path=storage_path) as client:
            client.send_cbor(CtapCmd.RESET)
            cred_id = _make_credential(client)

        with SimulatorClient(storage_path=storage_path) as client:
            status, _ = _get_assertion(client, cred_id)
            assert status == CtapError.SUCCESS, status
            status, _ = client.send_cbor(CtapCmd.RESET)
            assert status == CtapError.SUCCESS

        with SimulatorClient(storage_path=storage_path) as client:
            status, _ = _get_assertion(client, cred_id)
            assert status == CtapError.NO_CREDENTIALS, status


def test_sign_counter_monotonic_across_restart_wire():
    with _storage_tmpdir() as tmpdir:
        storage_path = Path(tmpdir) / "sign_count_persist.json"

        with SimulatorClient(storage_path=storage_path) as client:
            client.send_cbor(CtapCmd.RESET)
            cred_id = _make_credential(client)
            status, count_before = _get_assertion(client, cred_id)
            assert status == CtapError.SUCCESS

        with SimulatorClient(storage_path=storage_path) as client:
            status, count_after = _get_assertion(client, cred_id)
            assert status == CtapError.SUCCESS
            assert count_after > count_before


def test_large_blobs_survive_restart():
    blob = b"large-blob-persistence-check"
    with _storage_tmpdir() as tmpdir:
        storage_path = Path(tmpdir) / "large_blobs_persist.json"

        with SimulatorClient(storage_path=storage_path) as client:
            client.send_cbor(CtapCmd.RESET)
            write_req = {"offset": 0, "set": blob, "length": len(blob)}
            status, _ = client.send_cbor(CtapCmd.LARGE_BLOBS, write_req)
            assert status == CtapError.SUCCESS, status

        with SimulatorClient(storage_path=storage_path) as client:
            read_req = {"offset": 0, "get": len(blob)}
            status, resp = client.send_cbor(CtapCmd.LARGE_BLOBS, read_req)
            assert status == CtapError.SUCCESS, status
            assert _config_field(resp) == blob


def test_reset_clears_large_blobs_across_restart():
    blob = b"large-blob-to-be-reset"
    with _storage_tmpdir() as tmpdir:
        storage_path = Path(tmpdir) / "large_blobs_reset.json"

        with SimulatorClient(storage_path=storage_path) as client:
            client.send_cbor(CtapCmd.RESET)
            write_req = {"offset": 0, "set": blob, "length": len(blob)}
            status, _ = client.send_cbor(CtapCmd.LARGE_BLOBS, write_req)
            assert status == CtapError.SUCCESS, status

        with SimulatorClient(storage_path=storage_path) as client:
            status, _ = client.send_cbor(CtapCmd.RESET)
            assert status == CtapError.SUCCESS

        with SimulatorClient(storage_path=storage_path) as client:
            read_req = {"offset": 0, "get": len(blob)}
            status, resp = client.send_cbor(CtapCmd.LARGE_BLOBS, read_req)
            assert status == CtapError.SUCCESS, status
            assert _config_field(resp) == b""
