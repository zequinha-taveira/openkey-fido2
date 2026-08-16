import hashlib
import struct
import subprocess
from fido2 import cbor

sim = subprocess.Popen(
    [r"C:\openkey-fido2\target\debug\fido2-simulator.exe", "--raw-cbor"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)

def send(cmd, payload=None):
    encoded = b"" if payload is None else cbor.encode(payload)
    body = bytes([cmd]) + encoded
    sim.stdin.write(struct.pack(">H", len(body)) + body)
    sim.stdin.flush()
    n = struct.unpack(">H", sim.stdout.read(2))[0]
    status = sim.stdout.read(1)[0]
    data = sim.stdout.read(n - 1)
    return status, (cbor.decode(data) if data else None), data.hex()

client_hash = hashlib.sha256(b"client-data").digest()
string_request = {
    "clientDataHash": client_hash,
    "rp": {"id": "example.com", "name": "Example"},
    "user": {"id": b"user-1", "name": "alice"},
    "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
    "excludeList": [],
    "options": {"rk": False, "uv": False, "up": True},
}
integer_request = {
    1: client_hash,
    2: {"id": "example.com", "name": "Example"},
    3: {"id": b"user-1", "name": "alice"},
    4: [{"type": "public-key", "alg": -7}],
    5: [],
    7: {"rk": False, "uv": False, "up": True},
}
for label, request in (("string-key request", string_request), ("integer-key request", integer_request)):
    status, response, raw = send(0x01, request)
    print(label)
    print("  status=0x%02x" % status)
    print("  response=%r" % response)
    print("  raw_response=%s" % raw[:120])

unsupported = dict(integer_request)
unsupported[4] = [{"type": "public-key", "alg": -999}]
status, response, raw = send(0x01, unsupported)
print("unsupported algorithm status=0x%02x (expected CTAP2 0x26)" % status)

status, info, raw = send(0x04, None)
print("getInfo status=0x%02x keys=%r" % (status, list(info) if isinstance(info, dict) else info))

sim.stdin.close()
sim.terminate()
sim.wait(timeout=2)
