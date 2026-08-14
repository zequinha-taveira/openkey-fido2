"""Testes da ponte CTAPHID (`tools/ctaphid_bridge.py`).

Cobre a parte pura (testável em qualquer plataforma) — parse/pack de pacotes,
fragmentação, remontagem, alocação de CID e o wrapping CBOR CTAP2 — e o
dispatch da ponte (`CtaphidBridge.handle_packet`) de ponta a ponta contra o
`fido2-simulator --raw-cbor` real, usando um UHID falso (`RecordingUhid`).

A parte UHID de verdade (/dev/uhid) é Linux-only e não é exercitada aqui.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS_DIR))

import ctaphid_bridge as bridge  # noqa: E402
from ctaphid_bridge import (  # noqa: E402
    CMD_CBOR,
    CMD_CANCEL,
    CMD_ERROR,
    CMD_INIT,
    CMD_PING,
    CMD_WINK,
    CTAPHID_BROADCAST_CID,
    ERR_INVALID_CMD,
    ERR_OTHER,
    Assembler,
    ChannelManager,
    CtaphidBridge,
    RecordingUhid,
    Simulator,
    ctap2_request_decode,
    ctap2_response_encode,
    fragment,
    pack_cont,
    pack_init,
    parse_packet,
    reassemble,
)


def test_parse_init_packet() -> None:
    raw = pack_init(0x11223344, CMD_PING, b"hello")
    pkt = parse_packet(raw)
    assert pkt.is_init
    assert pkt.cid == 0x11223344
    assert pkt.cmd == CMD_PING
    assert pkt.data == b"hello"


def test_parse_cont_packet() -> None:
    raw = pack_cont(0x11223344, 2, b"\xaa" * 59)
    pkt = parse_packet(raw)
    assert not pkt.is_init
    assert pkt.cid == 0x11223344
    assert pkt.cmd == 2  # seq
    assert len(pkt.data) == 59


def test_parse_packet_rejects_wrong_size() -> None:
    with pytest.raises(ValueError):
        parse_packet(b"\x00" * 63)


def test_fragment_single_packet() -> None:
    pkts = fragment(0xAABBCCDD, CMD_PING, b"abc")
    assert len(pkts) == 1
    assert len(pkts[0]) == 64
    pkt = parse_packet(pkts[0])
    assert pkt.is_init and pkt.cid == 0xAABBCCDD and pkt.data == b"abc"


def test_fragment_multi_packet_roundtrip() -> None:
    payload = bytes(range(256))  # 256 bytes -> 1 INIT + ceil((256-57)/59) CONT
    pkts = fragment(0x55667788, CMD_CBOR, payload)
    assert len(pkts) > 1

    asm = Assembler()
    completed = None
    for pkt in pkts:
        msg = asm.process(pkt)
        if msg is not None:
            completed = msg
    assert completed is not None
    cid, cmd, data = completed
    assert cid == 0x55667788
    assert cmd == CMD_CBOR
    assert data == payload


def test_assembler_rejects_out_of_order_seq() -> None:
    payload = b"\x01" * 200
    pkts = fragment(0x11112222, CMD_CBOR, payload)
    asm = Assembler()
    assert asm.process(pkts[0]) is None  # INIT multipart
    assert asm.process(pkts[2]) is None  # seq 1 antes do seq 0 -> reset/drop
    assert asm.process(pkts[1]) is None  # estado resetado, CONT sem INIT -> drop


def test_assembler_cancel_aborts() -> None:
    payload = b"\x02" * 200
    pkts = fragment(0x33334444, CMD_CBOR, payload)
    asm = Assembler()
    asm.process(pkts[0])
    cancel = pack_init(0x33334444, CMD_CANCEL, b"")
    msg = asm.process(cancel)
    assert msg == (0x33334444, CMD_CANCEL, b"")


def test_channel_manager_allocates_unique_cids() -> None:
    mgr = ChannelManager()
    c1 = mgr.allocate()
    c2 = mgr.allocate()
    assert c1 != c2
    assert c1 not in (0x00000000, 0xFFFFFFFF)
    assert c2 not in (0x00000000, 0xFFFFFFFF)


def test_channel_manager_init_response() -> None:
    mgr = ChannelManager()
    resp = mgr.build_init_response(b"\x01\x02\x03\x04\x05\x06\x07\x08")
    assert len(resp) == 17
    assert resp[0:8] == b"\x01\x02\x03\x04\x05\x06\x07\x08"
    assert resp[12] == 2  # versão CTAPHID


def test_ctap2_request_decode() -> None:
    from fido2 import cbor

    payload = cbor.encode({1: 0x01, 2: {"rp": {"id": "example.com"}}})
    cmd, params = ctap2_request_decode(payload)
    assert cmd == 0x01
    assert cbor.decode(params) == {"rp": {"id": "example.com"}}


def test_ctap2_response_encode_success() -> None:
    from fido2 import cbor

    resp = cbor.encode({"versions": ["U2F_V2", "FIDO_2_0"]})
    out = ctap2_response_encode(0x00, resp)
    assert cbor.decode(out) == {1: {"versions": ["U2F_V2", "FIDO_2_0"]}}


def test_ctap2_response_encode_error() -> None:
    from fido2 import cbor

    out = ctap2_response_encode(0x2E, b"")
    assert cbor.decode(out) == {1: 0x2E}


def test_report_descriptor_fido_usage_page() -> None:
    assert bridge.FIDO_REPORT_DESCRIPTOR[0:3] == b"\x06\xd0\xf1"
    assert len(bridge.FIDO_REPORT_DESCRIPTOR) == 34


def test_dispatch_helper_cbor_to_simulator_format() -> None:
    """O payload CBOR CTAPHID `{1: cmd, 2: params}` vira (cmd, params_cbor)."""
    from fido2 import cbor

    payload = cbor.encode({1: 0x04})  # getInfo sem params
    cmd, params = ctap2_request_decode(payload)
    assert cmd == 0x04
    assert params == b""


# ---------------------------------------------------------------------------
# Dispatch da ponte (CtaphidBridge.handle_packet) de ponta a ponta
# ---------------------------------------------------------------------------


def test_bridge_dispatch_init_handshake() -> None:
    uhid = RecordingUhid()
    bridge_obj = CtaphidBridge(uhid, None)  # sim não é usado no INIT
    bridge_obj.handle_packet(
        pack_init(CTAPHID_BROADCAST_CID, CMD_INIT, bytes(8), total_len=8)
    )
    msg = reassemble(uhid.sent)
    assert msg is not None
    cid, cmd, payload = msg
    assert cid == CTAPHID_BROADCAST_CID
    assert cmd == CMD_INIT
    assert len(payload) == 17
    assert payload[12] == 2  # versão do protocolo CTAPHID
    assert payload[16] & 0x04  # CAPABILITY_CBOR


def test_bridge_dispatch_ping_echo() -> None:
    uhid = RecordingUhid()
    bridge_obj = CtaphidBridge(uhid, None)  # sim não é usado no PING
    bridge_obj.handle_packet(pack_init(0x11223344, CMD_PING, b"hello"))
    assert reassemble(uhid.sent) == (0x11223344, CMD_PING, b"hello")


def test_bridge_dispatch_unknown_command() -> None:
    uhid = RecordingUhid()
    bridge_obj = CtaphidBridge(uhid, None)  # sim não é usado em comando desconhecido
    bridge_obj.handle_packet(pack_init(0x11223344, 0x77, b""))
    assert reassemble(uhid.sent) == (0x11223344, CMD_ERROR, bytes([ERR_INVALID_CMD]))


def test_bridge_dispatch_cbor_non_map_payload() -> None:
    from fido2 import cbor

    uhid = RecordingUhid()
    bridge_obj = CtaphidBridge(uhid, None)  # sim não é usado: o decode falha antes
    # Payload CBOR válido mas não-mapa: o dispatch falha e responde ERR_OTHER.
    bridge_obj.handle_packet(
        pack_init(0x11223344, CMD_CBOR, cbor.encode([1, 2, 3]))
    )
    msg = reassemble(uhid.sent)
    assert msg is not None
    cid, cmd, payload = msg
    assert (cid, cmd) == (0x11223344, CMD_CBOR)
    assert cbor.decode(payload) == {1: ERR_OTHER}


def test_bridge_dispatch_cbor_getinfo_roundtrip() -> None:
    from fido2 import cbor

    try:
        sim = Simulator(None)
    except FileNotFoundError as exc:
        pytest.skip(f"fido2-simulator não encontrado: {exc}")
    try:
        uhid = RecordingUhid()
        bridge_obj = CtaphidBridge(uhid, sim)
        getinfo = cbor.encode({1: 0x04})
        for pkt in fragment(0x11223344, CMD_CBOR, getinfo):
            bridge_obj.handle_packet(pkt)
        msg = reassemble(uhid.sent)
        assert msg is not None
        cid, cmd, payload = msg
        assert (cid, cmd) == (0x11223344, CMD_CBOR)
        decoded = cbor.decode(payload)
        assert isinstance(decoded.get(1), dict), "GetInfo via dispatch não retornou mapa CBOR"
    finally:
        sim.close()
