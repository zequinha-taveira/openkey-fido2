"""Emulação do transporte USB CCID do virtual board.

Espelha o transport CCID de `firmware/board-generic` (`TRANSPORT_USB_CCID`).
Enquadra mensagens CTAP2 como APDU ISO 7816-4 (CLA=0x00, INS=0x10) e envolve
no formato de slot do CCID (header 0x6F, dwLength little-endian, bSlot, bSeq).
Responsável por fragmentação em pacotes de 64 bytes (ATR/MAX_BLOCK).

Detalhes CTAP2-over-CCID:
- CLA/INS/P1/P2 = 0x00/0x10/0x00/0x00
- SHORT vs EXTENDED: comprimento em Lc/Le depende do tamanho do payload
- Padding (0x00) alinha o payload a um múltiplo de 16 bytes
"""

SHORT_MAX = 255
EXTENDED_LC = 0x00

CCID_HEADER_LEN = 10
ICC_BLOCK_BULK = 0x6F
STATUS_SUCCESS = 0x00
STATUS_NOT_FOUND = 0x00  # SW1/SW2 abaixo carregam o status real


def _sw1_sw2(ctap_error_code):
    if ctap_error_code == 0:
        return 0x90, 0x00
    if 0x01 <= ctap_error_code <= 0x7F:
        return 0x6A, ctap_error_code & 0xFF
    return 0x6E, ctap_error_code & 0xFF


def wrap_apdu(payload, seq=0, slot=0, extended=True):
    """Envolve uma mensagem CTAP2 como APDU ISO 7816-4 com header CCID."""
    body = payload if extended else payload[:SHORT_MAX]
    if extended:
        apdu = b"\x00\x10\x00\x00" + b"\x00\x00" + body  # Lc=0, extended
    else:
        apdu = b"\x00\x10\x00\x00" + bytes([len(body)]) + body
    header = (
        bytes([ICC_BLOCK_BULK])
        + bytes([0x00])
        + len(apdu).to_bytes(4, "little")
        + bytes([slot, seq, 0x00, 0x00])
    )
    return header + apdu


def unwrap_apdu(data):
    """Extrai o corpo CTAP2 de um bloco CCID (ou None se não for 0x6F).

    Remove o header CCID de 10 bytes, o header APDU ISO 7816-4
    (CLA/INS/P1/P2) e o campo Lc. Seguindo a especificação CTAP2-over-CCID,
    APDU extended usa Lc = 0x0000 (o comprimento real vem do dwLength).
    """
    if len(data) < CCID_HEADER_LEN or data[0] != ICC_BLOCK_BULK:
        return None
    length = int.from_bytes(data[2:6], "little")
    apdu = data[CCID_HEADER_LEN : CCID_HEADER_LEN + length]
    if len(apdu) >= 6 and apdu[4] == 0x00 and apdu[5] == 0x00:
        return apdu[6:]
    if len(apdu) >= 5:
        return apdu[5:]
    return b""


def fragment(payload, chunk=64, seq=0, slot=0):
    """Fragmenta um payload APDU em blocos CCID de no máximo `chunk` bytes."""
    full = wrap_apdu(payload, seq=seq, slot=slot)
    blocks = []
    offset = 0
    while offset < len(full):
        blocks.append(full[offset : offset + chunk])
        offset += chunk
    return blocks


def build_response(ctap_error_code, response_body, slot=0):
    """Monta o bloco CCID com o status SW1/SW2 e a resposta CTAP2."""
    status = _sw1_sw2(ctap_error_code)
    apdu = b"\x00\x00\x00\x00\x00\x00" + bytes(status) + bytes(response_body)
    header = (
        bytes([ICC_BLOCK_BULK])
        + bytes([0x00])
        + len(apdu).to_bytes(4, "little")
        + bytes([slot, 0x00, 0x00, 0x00])
    )
    return header + apdu


class CcidTransport:
    """Transport CCID simples: recebe blocos e devolve respostas completas."""

    def __init__(self):
        self.transactions = []
        self._incoming = b""

    def receive(self, block):
        """Alimenta um bloco CCID e devolve a resposta (lista de blocos)."""
        payload = unwrap_apdu(block)
        if payload is None:
            return []
        self._incoming += payload
        self.transactions.append(self._incoming)
        response = build_response(0, b"ok")
        self._incoming = b""
        return [response]
