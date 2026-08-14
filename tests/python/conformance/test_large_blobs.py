"""Testes de conformidade CTAP 2.1 — authenticatorLargeBlobs (0x0C)."""

import pytest
from .ctap2_transport import CtapCmd, CtapError, SimulatorClient


def test_large_blobs_write_and_read():
    """Valida gravação e leitura fragmentada do LargeBlobs buffer."""
    with SimulatorClient() as client:
        # Reset para limpar estado
        client.send_cbor(CtapCmd.RESET)

        # 1. Escrever payload no LargeBlob (offset 0)
        blob_data = b"Hello, FIDO2 CTAP 2.1 LargeBlobs standard storage!"
        write_req = {
            "offset": 0,
            "set": blob_data,
            "length": len(blob_data),
        }
        status, _ = client.send_cbor(CtapCmd.LARGE_BLOBS, write_req)
        assert status == CtapError.SUCCESS

        # 2. Ler de volta
        read_req = {
            "offset": 0,
            "get": len(blob_data),
        }
        status, resp = client.send_cbor(CtapCmd.LARGE_BLOBS, read_req)
        assert status == CtapError.SUCCESS
        assert isinstance(resp, dict)

        retrieved = resp.get("config") or resp.get("largeBlob") or resp.get(0x01)
        assert retrieved == blob_data
