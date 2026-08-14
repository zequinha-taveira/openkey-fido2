#!/usr/bin/env python3
"""Virtual CTAPHID Bridge — conecta o `fido2-simulator --raw-cbor` a um
dispositivo USB-HID virtual (Linux UHID), permitindo que navegadores e o
FIDO Conformance Tool usem o firmware diretamente.

Fluxo:

    Browser / FIDO Conformance Tool
        │  CTAPHID (pacotes HID de 64 bytes, usage page 0xF1D0)
        ▼
    /dev/uhid  (dispositivo HID virtual criado por este script)
        │  UHID_OUTPUT (host → device) / UHID_INPUT (device → host)
        ▼
    CtaphidBridge  (framing CTAPHID + wrapping CBOR CTAP2)
        │  protocolo binário `--raw-cbor` do simulador
        ▼
    fido2-simulator --raw-cbor

Requerimentos: Linux com /dev/uhid (kernel com CONFIG_UHID). A framing
CTAPHID e o wrapping CBOR são puros e testáveis em qualquer plataforma
(`tests/python/test_ctaphid_bridge.py`).
"""

from __future__ import annotations

import argparse
import os
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from fido2 import cbor

# --------------------------------------------------------------------------
# Framing CTAPHID (CTAP 2.1 §8.2) — puro e testável
# --------------------------------------------------------------------------

CTAPHID_PACKET_SIZE = 64
CTAPHID_INIT_PAYLOAD = 57
CTAPHID_CONT_PAYLOAD = 59
CTAPHID_MAX_PAYLOAD = 57 + 128 * 59
CTAPHID_BROADCAST_CID = 0xFFFFFFFF

CMD_INIT = 0x06
CMD_PING = 0x01
CMD_MSG = 0x03
CMD_LOCK = 0x04
CMD_WINK = 0x08
CMD_CBOR = 0x10
CMD_CANCEL = 0x11
CMD_KEEPALIVE = 0x3B
CMD_ERROR = 0x3F

ERR_INVALID_CMD = 0x01
ERR_OTHER = 0x7F

# Descritor de report HID FIDO (usage page 0xF1D0): 2 reports de 64 bytes.
FIDO_REPORT_DESCRIPTOR = bytes(
    [
        0x06, 0xD0, 0xF1,  # Usage Page (FIDO Alliance)
        0x09, 0x01,        # Usage (U2F/CTAPHID)
        0xA1, 0x01,        # Collection (Application)
        0x09, 0x20,        # Usage (Data In)
        0x15, 0x00,        # Logical Minimum (0)
        0x26, 0xFF, 0x00,  # Logical Maximum (255)
        0x75, 0x08,        # Report Size (8)
        0x95, 0x40,        # Report Count (64)
        0x81, 0x02,        # Input (Data, Var, Abs)
        0x09, 0x21,        # Usage (Data Out)
        0x15, 0x00,        # Logical Minimum (0)
        0x26, 0xFF, 0x00,  # Logical Maximum (255)
        0x75, 0x08,        # Report Size (8)
        0x95, 0x40,        # Report Count (64)
        0x91, 0x02,        # Output (Data, Var, Abs)
        0xC0,              # End Collection
    ]
)


@dataclass
class Packet:
    """Um pacote CTAPHID decodificado (INIT ou CONT)."""

    is_init: bool
    cid: int
    cmd: int          # comando (INIT) ou número de sequência (CONT)
    data: bytes

    def __post_init__(self) -> None:
        if len(self.data) > CTAPHID_MAX_PAYLOAD:
            raise ValueError("payload CTAPHID excede o limite")


def parse_packet(raw: bytes) -> Packet:
    """Decodifica um pacote CTAPHID de 64 bytes."""
    if len(raw) != CTAPHID_PACKET_SIZE:
        raise ValueError(f"pacote deve ter {CTAPHID_PACKET_SIZE} bytes, veio {len(raw)}")
    cid = int.from_bytes(raw[0:4], "big")
    cmd_byte = raw[4]
    if cmd_byte & 0x80:
        cmd = cmd_byte & 0x7F
        bcnt = int.from_bytes(raw[5:7], "big")
        data = raw[7 : 7 + min(bcnt, CTAPHID_INIT_PAYLOAD)]
        return Packet(True, cid, cmd, data)
    seq = cmd_byte & 0x7F
    return Packet(False, cid, seq, raw[5:CTAPHID_PACKET_SIZE])


def pack_init(cid: int, cmd: int, data: bytes, total_len: int | None = None) -> bytes:
    if total_len is None:
        total_len = len(data)
    out = bytearray(CTAPHID_PACKET_SIZE)
    out[0:4] = cid.to_bytes(4, "big")
    out[4] = 0x80 | (cmd & 0x7F)
    out[5:7] = total_len.to_bytes(2, "big")
    out[7 : 7 + len(data)] = data[:CTAPHID_INIT_PAYLOAD]
    return bytes(out)


def pack_cont(cid: int, seq: int, data: bytes) -> bytes:
    out = bytearray(CTAPHID_PACKET_SIZE)
    out[0:4] = cid.to_bytes(4, "big")
    out[4] = seq & 0x7F
    out[5 : 5 + len(data)] = data
    return bytes(out)


def fragment(cid: int, cmd: int, payload: bytes) -> list[bytes]:
    """Segmenta uma mensagem em pacotes CTAPHID de 64 bytes."""
    if len(payload) > CTAPHID_MAX_PAYLOAD:
        raise ValueError("payload excede o máximo CTAPHID")
    pkts = [pack_init(cid, cmd, payload[:CTAPHID_INIT_PAYLOAD], total_len=len(payload))]
    offset = CTAPHID_INIT_PAYLOAD
    seq = 0
    while offset < len(payload):
        chunk = payload[offset : offset + CTAPHID_CONT_PAYLOAD]
        pkts.append(pack_cont(cid, seq, chunk))
        offset += CTAPHID_CONT_PAYLOAD
        seq = (seq + 1) & 0x7F
    return pkts


class Assembler:
    """Remonta pacotes CTAPHID em mensagens completas (cid, cmd, payload)."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._active = False
        self._cid = 0
        self._cmd = 0
        self._total = 0
        self._buf = bytearray()
        self._next_seq = 0

    def process(self, raw: bytes) -> tuple[int, int, bytes] | None:
        pkt = parse_packet(raw)
        if pkt.is_init:
            bcnt = int.from_bytes(raw[5:7], "big")
            if bcnt > CTAPHID_MAX_PAYLOAD:
                self.reset()
                return None
            if pkt.cmd == CMD_CANCEL:
                self.reset()
                return (pkt.cid, CMD_CANCEL, b"")
            if bcnt <= CTAPHID_INIT_PAYLOAD:
                # mensagem de pacote único
                self.reset()
                return (pkt.cid, pkt.cmd, pkt.data[:bcnt])
            # mensagem multipart: aguarda pacotes CONT
            self._active = True
            self._cid = pkt.cid
            self._cmd = pkt.cmd
            self._total = bcnt
            self._buf = bytearray(pkt.data)
            self._next_seq = 0
            return None
        # Pacote CONT
        if not self._active or pkt.cid != self._cid or pkt.cmd != self._next_seq:
            self.reset()
            return None
        remaining = self._total - len(self._buf)
        chunk = pkt.data[: min(remaining, CTAPHID_CONT_PAYLOAD)]
        self._buf.extend(chunk)
        self._next_seq = (self._next_seq + 1) & 0x7F
        if len(self._buf) >= self._total:
            out = (self._cid, self._cmd, bytes(self._buf))
            self.reset()
            return out
        return None


class ChannelManager:
    """Alocação de Channel IDs e handshake CTAPHID_INIT."""

    def __init__(self) -> None:
        self.next_cid = 0x00010001

    def allocate(self) -> int:
        while True:
            cid = self.next_cid
            self.next_cid += 1
            if cid not in (0x00000000, CTAPHID_BROADCAST_CID):
                return cid

    def build_init_response(self, nonce: bytes) -> bytes:
        cid = self.allocate()
        resp = bytearray(17)
        resp[0:8] = nonce[:8].ljust(8, b"\x00")
        resp[8:12] = cid.to_bytes(4, "big")
        resp[12] = 2  # versão do protocolo CTAPHID
        resp[13] = 0  # major
        resp[14] = 1  # minor
        resp[15] = 0  # build
        resp[16] = 0x04 | 0x01 | 0x08  # CBOR | WINK | NMSG
        return bytes(resp)


# --------------------------------------------------------------------------
# Wrapping CBOR CTAP2 (CTAP 2.1 §6.1)
# --------------------------------------------------------------------------


def ctap2_request_decode(payload: bytes) -> tuple[int, bytes]:
    """Converte o payload CTAPHID CBOR `{1: cmd, 2: params, ...}` em
    `(cmd, params_cbor)`."""
    if not payload:
        return (0xFF, b"")
    msg = cbor.decode(payload)
    cmd = msg.get(1, 0xFF)
    params = msg.get(2)
    params_cbor = cbor.encode(params) if params is not None else b""
    return (cmd, params_cbor)


def ctap2_response_encode(status: int, resp_data: bytes) -> bytes:
    """Converte `(status, resp_cbor)` do simulador no payload CBOR CTAP2
    `{1: <resposta ou código de erro>}`."""
    if status == 0x00:
        inner = cbor.decode(resp_data) if resp_data else {}
        return cbor.encode({1: inner})
    return cbor.encode({1: status})


# --------------------------------------------------------------------------
# UHID (Linux only)
# --------------------------------------------------------------------------

UHID_DESTROY = 0
UHID_START = 1
UHID_STOP = 2
UHID_OPEN = 3
UHID_CLOSE = 4
UHID_OUTPUT = 5
UHID_INPUT = 7
UHID_CREATE2 = 11


class UhidDevice:
    """Dispositivo HID virtual via /dev/uhid (Linux)."""

    def __init__(
        self,
        report_descriptor: bytes,
        name: str = "openkey-fido2",
        vid: int = 0x1209,
        pid: int = 0x0001,
    ) -> None:
        self.fd = os.open("/dev/uhid", os.O_RDWR)
        self.report_descriptor = report_descriptor
        self.name = name
        self.vid = vid
        self.pid = pid

    def _create2_packet(self) -> bytes:
        # Layout de `struct uhid_create2_req` (linux/uhid.h), com o alinhamento
        # natural do C (padding de 1 byte antes de rd_size e 2 antes de vendor).
        name = self.name.encode("ascii")[:127].ljust(128, b"\x00")
        phys = b"openkey-fido2".ljust(64, b"\x00")
        uniq = b"openkey-0001".ljust(64, b"\x00")
        rd_data = self.report_descriptor.ljust(4096, b"\x00")
        return (
            struct.pack("<B", UHID_CREATE2)
            + name
            + phys
            + uniq
            + b"\x00"  # padding para alinhar __u16
            + struct.pack("<H", len(self.report_descriptor))
            + struct.pack("<H", 0x0003)  # bus = USB
            + b"\x00\x00"  # padding para alinhar __u32
            + struct.pack("<IIII", self.vid, self.pid, 0x0001, 0x0000)
            + rd_data
        )

    def create(self) -> None:
        os.write(self.fd, self._create2_packet())

    def destroy(self) -> None:
        os.write(self.fd, struct.pack("<I", UHID_DESTROY))
        os.close(self.fd)

    def read_event(self) -> tuple[int, bytes]:
        """Lê um evento UHID. Retorna (type, payload)."""
        type_bytes = os.read(self.fd, 4)
        if not type_bytes:
            raise EOFError("uhid fechado")
        (ev_type,) = struct.unpack("<I", type_bytes)
        payload = b""
        if ev_type in (UHID_OUTPUT,):
            payload = os.read(self.fd, CTAPHID_PACKET_SIZE)
        return ev_type, payload

    def send_input(self, data: bytes) -> None:
        """Envia um input report (IN) de 64 bytes ao host."""
        os.write(self.fd, struct.pack("<I", UHID_INPUT) + data)


# --------------------------------------------------------------------------
# Cliente do simulador (protocolo --raw-cbor)
# --------------------------------------------------------------------------


class Simulator:
    """Cliente binário mínimo para `fido2-simulator --raw-cbor`."""

    def __init__(self, sim_path: str | None = None) -> None:
        if sim_path is None:
            sim_path = self._find_simulator()
        self._proc = subprocess.Popen(
            [sim_path, "--raw-cbor"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            bufsize=0,
        )

    @staticmethod
    def _find_simulator() -> str:
        repo_root = Path(__file__).resolve().parents[1]
        for c in (
            repo_root / "target" / "debug" / "fido2-simulator.exe",
            repo_root / "target" / "debug" / "fido2-simulator",
            repo_root / "target" / "release" / "fido2-simulator.exe",
            repo_root / "target" / "release" / "fido2-simulator",
        ):
            if c.is_file():
                return str(c)
        raise FileNotFoundError("fido2-simulator não encontrado; rode 'cargo build -p fido2-simulator'")

    def _read_exact(self, n: int) -> bytes:
        chunks: list[bytes] = []
        while n > 0:
            chunk = self._proc.stdout.read(n)
            if not chunk:
                raise EOFError("simulador fechou a conexão")
            chunks.append(chunk)
            n -= len(chunk)
        return b"".join(chunks)

    def send_raw(self, cmd: int, payload: bytes) -> tuple[int, bytes]:
        total = 1 + len(payload)
        self._proc.stdin.write(struct.pack(">H", total) + bytes([cmd]) + payload)
        self._proc.stdin.flush()
        (resp_len,) = struct.unpack(">H", self._read_exact(2))
        status = self._read_exact(1)[0]
        data = self._read_exact(resp_len - 1) if resp_len > 1 else b""
        return status, data

    def close(self) -> None:
        if self._proc.poll() is None:
            if self._proc.stdin:
                try:
                    self._proc.stdin.close()
                except OSError:
                    pass
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()


# --------------------------------------------------------------------------
# Bridge
# --------------------------------------------------------------------------


class CtaphidBridge:
    """Ponte entre o /dev/uhid e o simulador `--raw-cbor`."""

    def __init__(self, uhid: UhidDevice, sim: Simulator) -> None:
        self.uhid = uhid
        self.sim = sim
        self.assembler = Assembler()
        self.channels = ChannelManager()

    def run(self) -> None:
        self.uhid.create()
        try:
            while True:
                ev_type, data = self.uhid.read_event()
                if ev_type == UHID_OUTPUT:
                    self.handle_packet(data)
                # UHID_START/STOP/OPEN/CLOSE não exigem ação.
        finally:
            self.uhid.destroy()
            self.sim.close()

    def handle_packet(self, raw: bytes) -> None:
        """Processa um pacote CTAPHID de 64 bytes vindo do host."""
        try:
            msg = self.assembler.process(raw)
        except ValueError:
            return
        if msg is None:
            return
        cid, cmd, payload = msg
        if cmd == CMD_INIT:
            self._send(cid, CMD_INIT, self.channels.build_init_response(payload))
        elif cmd == CMD_PING:
            self._send(cid, CMD_PING, payload)
        elif cmd == CMD_WINK:
            self._send(cid, CMD_WINK, b"")
        elif cmd == CMD_LOCK:
            self._send(cid, CMD_LOCK, b"")
        elif cmd == CMD_CANCEL:
            self._send(cid, CMD_CANCEL, b"")
        elif cmd == CMD_CBOR:
            self._handle_cbor(cid, payload)
        elif cmd == CMD_MSG:
            self._handle_cbor(cid, payload)
        else:
            self._send(cid, CMD_ERROR, bytes([ERR_INVALID_CMD]))

    def _handle_cbor(self, cid: int, payload: bytes) -> None:
        try:
            ctap_cmd, params = ctap2_request_decode(payload)
            status, resp_data = self.sim.send_raw(ctap_cmd, params)
            response = ctap2_response_encode(status, resp_data)
        except Exception:
            response = cbor.encode({1: ERR_OTHER})
        self._send(cid, CMD_CBOR, response)

    def _send(self, cid: int, cmd: int, payload: bytes) -> None:
        for pkt in fragment(cid, cmd, payload):
            self.uhid.send_input(pkt)


# --------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------


class RecordingUhid:
    """UHID falso que grava os input reports (64 bytes) enviados pela ponte.

    Permite exercitar o dispatch de `CtaphidBridge.handle_packet` sem
    `/dev/uhid` — usado pelo self-test e pelos testes em
    `tests/python/test_ctaphid_bridge.py`.
    """

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def send_input(self, data: bytes) -> None:
        self.sent.append(data)


def reassemble(packets: list[bytes]) -> tuple[int, int, bytes] | None:
    """Remonta pacotes CTAPHID e retorna a última mensagem completa como
    `(cid, cmd, payload)`.

    Retorna `None` se nenhuma mensagem foi concluída. Mensagens anteriores são
    descartadas — suficiente para as respostas single-response dos testes.
    """
    asm = Assembler()
    result: tuple[int, int, bytes] | None = None
    for pkt in packets:
        msg = asm.process(pkt)
        if msg is not None:
            result = msg
    return result


def self_test(simulator_path: str | None) -> int:
    """Valida o pipeline completo da ponte sem UHID: fragmentação/remontagem
    CTAPHID, handshake CTAPHID_INIT, round-trip CBOR GetInfo contra o
    simulador real e o dispatch de `handle_packet` de ponta a ponta via UHID
    falso. Roda em qualquer plataforma."""
    # 1. Roundtrip de fragmentação/remontagem multi-pacote.
    payload = bytes(range(256))
    pkts = fragment(0x11223344, CMD_CBOR, payload)
    assert len(pkts) > 1, "payload de 256 bytes deve gerar múltiplos pacotes"
    asm = Assembler()
    result = None
    for pkt in pkts:
        r = asm.process(pkt)
        if r is not None:
            result = r
    assert result is not None and result[2] == payload, "roundtrip de fragmentação falhou"
    print("[ok] fragmentação/remontagem CTAPHID (multi-pacote)")

    # 2. Handshake INIT + CBOR GetInfo via simulador.
    sim = Simulator(simulator_path)
    try:
        channels = ChannelManager()
        asm = Assembler()

        # INIT (broadcast CID, nonce de 8 bytes).
        init_pkt = pack_init(CTAPHID_BROADCAST_CID, CMD_INIT, bytes(8), total_len=8)
        msg = asm.process(init_pkt)
        assert msg is not None, "sem mensagem do INIT"
        _, cmd, nonce = msg
        assert cmd == CMD_INIT

        init_resp = channels.build_init_response(nonce)
        assert len(init_resp) == 17
        assigned = int.from_bytes(init_resp[8:12], "big")
        assert assigned not in (0x00000000, CTAPHID_BROADCAST_CID), "CID inválido"
        assert init_resp[12] == 2, "versão do protocolo CTAPHID deve ser 2"
        assert init_resp[16] & 0x04, "CAPABILITY_CBOR ausente"
        print(f"[ok] CTAPHID_INIT → CID 0x{assigned:08x}, caps 0x{init_resp[16]:02x}")

        # CBOR GetInfo (opcode 0x04, sem parâmetros).
        getinfo = cbor.encode({1: 0x04})
        ctap_cmd, params = ctap2_request_decode(getinfo)
        assert ctap_cmd == 0x04
        status, resp_data = sim.send_raw(ctap_cmd, params)
        assert status == 0x00, f"GetInfo retornou status 0x{status:02x}"
        decoded = cbor.decode(ctap2_response_encode(status, resp_data))
        assert isinstance(decoded.get(1), dict), "GetInfo não retornou um mapa CBOR"
        print(f"[ok] CTAPHID_CBOR GetInfo → status 0x00, {len(resp_data)} bytes de CBOR")

        # 3. Dispatch de ponta a ponta via UHID falso (handle_packet).
        uhid = RecordingUhid()
        bridge = CtaphidBridge(uhid, sim)

        bridge.handle_packet(
            pack_init(CTAPHID_BROADCAST_CID, CMD_INIT, bytes(8), total_len=8)
        )
        msg = reassemble(uhid.sent)
        assert msg is not None, "dispatch INIT não produziu resposta"
        cid, cmd, init_resp = msg
        assert cid == CTAPHID_BROADCAST_CID and cmd == CMD_INIT, "dispatch INIT falhou"
        assert len(init_resp) == 17 and init_resp[12] == 2, "resposta INIT inválida"
        assert init_resp[16] & 0x04, "CAPABILITY_CBOR ausente na resposta INIT"
        print("[ok] dispatch CTAPHID_INIT via handle_packet")

        uhid.sent.clear()
        bridge.handle_packet(pack_init(0x11223344, CMD_CBOR, cbor.encode({1: 0x04})))
        msg = reassemble(uhid.sent)
        assert msg is not None, "dispatch CBOR não produziu resposta"
        cid, cmd, getinfo_resp = msg
        assert (cid, cmd) == (0x11223344, CMD_CBOR), "dispatch CBOR falhou"
        decoded = cbor.decode(getinfo_resp)
        assert isinstance(decoded.get(1), dict), "GetInfo via dispatch não retornou mapa CBOR"
        print("[ok] dispatch CTAPHID_CBOR GetInfo via handle_packet → simulador")
    finally:
        sim.close()

    print("self-test concluído com sucesso.")
    return 0


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--simulator", type=str, default=None, help="caminho para o fido2-simulator"
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="valida o pipeline da ponte (framing + INIT + CBOR) sem UHID",
    )
    parser.add_argument("--vid", type=lambda v: int(v, 0), default=0x1209)
    parser.add_argument("--pid", type=lambda v: int(v, 0), default=0x0001)
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test(args.simulator)

    if not os.path.exists("/dev/uhid"):
        print(
            "erro: /dev/uhid não encontrado. Este script requer Linux com "
            "CONFIG_UHID (UHID é Linux-only).",
            file=sys.stderr,
        )
        return 1

    uhid = UhidDevice(FIDO_REPORT_DESCRIPTOR, vid=args.vid, pid=args.pid)
    sim = Simulator(args.simulator)
    bridge = CtaphidBridge(uhid, sim)
    print("CTAPHID bridge ativo. Use o FIDO Conformance Tool ou um navegador.")
    bridge.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
