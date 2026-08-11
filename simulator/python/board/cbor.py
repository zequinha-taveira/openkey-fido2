"""Codec CBOR mínimo (stdlib-only) usado pelo virtual board.

Suporta o subconjunto do CBOR usado nas mensagens CTAP2 deste workspace:
inteiros (major 0/1), byte strings (2), text strings (3), arrays (4),
mapas (5) e valores simples (7: bool/null). Strings indefinite-length
também são aceitas na decodificação.
"""


class CborError(ValueError):
    pass


def _read_uint(data, info, pos):
    if info < 24:
        return info, pos
    nbytes = 1 << (info - 24)
    if pos + nbytes > len(data):
        raise CborError("uint truncado")
    return int.from_bytes(data[pos : pos + nbytes], "big"), pos + nbytes


def _decode(data, pos):
    if pos >= len(data):
        raise CborError("fim do stream")
    b = data[pos]
    pos += 1
    major = b >> 5
    info = b & 0x1F

    if info == 31:
        if major not in (2, 3, 4, 5):
            raise CborError(f"indefinite-length inválida para major {major}")
        if major == 2:
            chunks = []
            while True:
                if pos >= len(data):
                    raise CborError("bstr indefinite truncado")
                if data[pos] == 0xFF:
                    pos += 1
                    break
                item, pos = _decode(data, pos)
                if not isinstance(item, bytes):
                    raise CborError("item não-bstr em bstr indefinite")
                chunks.append(item)
            return b"".join(chunks), pos
        if major == 3:
            chunks = []
            while True:
                if pos >= len(data):
                    raise CborError("tstr indefinite truncado")
                if data[pos] == 0xFF:
                    pos += 1
                    break
                item, pos = _decode(data, pos)
                if not isinstance(item, str):
                    raise CborError("item não-tstr em tstr indefinite")
                chunks.append(item)
            return "".join(chunks), pos
        if major == 4:
            items = []
            while True:
                if pos >= len(data):
                    raise CborError("array indefinite truncado")
                if data[pos] == 0xFF:
                    pos += 1
                    break
                item, pos = _decode(data, pos)
                items.append(item)
            return items, pos
        items = {}
        while True:
            if pos >= len(data):
                raise CborError("map indefinite truncado")
            if data[pos] == 0xFF:
                pos += 1
                break
            key, pos = _decode(data, pos)
            value, pos = _decode(data, pos)
            items[key] = value
        return items, pos

    if major in (0, 1):
        value, pos = _read_uint(data, info, pos)
        return (value if major == 0 else -1 - value), pos

    if major in (2, 3):
        length, pos = _read_uint(data, info, pos)
        raw = data[pos : pos + length]
        if len(raw) < length:
            raise CborError("string truncada")
        return (raw if major == 2 else raw.decode("utf-8")), pos + length

    if major == 4:
        length, pos = _read_uint(data, info, pos)
        items = []
        for _ in range(length):
            item, pos = _decode(data, pos)
            items.append(item)
        return items, pos

    if major == 5:
        length, pos = _read_uint(data, info, pos)
        items = {}
        for _ in range(length):
            key, pos = _decode(data, pos)
            value, pos = _decode(data, pos)
            items[key] = value
        return items, pos

    if major == 7:
        if info == 20:
            return False, pos
        if info == 21:
            return True, pos
        if info in (22, 23):
            return None, pos
        if info == 24:
            if pos >= len(data):
                raise CborError("simple value truncado")
            return data[pos], pos + 1
        raise CborError(f"valor simples não suportado: {info}")

    raise CborError(f"major type não suportado: {major}")


def decode(data):
    value, pos = _decode(bytes(data), 0)
    if pos != len(data):
        raise CborError(f"bytes sobrando após o valor: {len(data) - pos}")
    return value


def _encode_length(major, length):
    if length < 24:
        return bytes([(major << 5) | length])
    if length < 256:
        return bytes([(major << 5) | 24, length])
    if length < 65536:
        return bytes([(major << 5) | 25]) + length.to_bytes(2, "big")
    return bytes([(major << 5) | 26]) + length.to_bytes(4, "big")


def encode(value):
    if value is None:
        return b"\xf6"
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if isinstance(value, int):
        return _encode_length(0, value) if value >= 0 else _encode_length(1, -1 - value)
    if isinstance(value, bytes):
        return _encode_length(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _encode_length(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _encode_length(4, len(value)) + b"".join(encode(item) for item in value)
    if isinstance(value, dict):
        return _encode_length(5, len(value)) + b"".join(
            encode(key) + encode(item) for key, item in value.items()
        )
    raise TypeError(f"tipo não suportado pelo codec CBOR: {type(value)!r}")
