"""Testes de conformidade CTAP 2.1 — authenticatorClientPIN (0x06).

Dirige o simulador com o cliente de referência `fido2.ctap2.pin.ClientPin`
(python-fido2 2.2.1), cobrindo os protocolos 1 e 2:

- set_pin / get_pin_retries / get_pin_token (0x05) / change_pin
- get_pin_token com permissions + rpId (subcomando 0x09)
- códigos de erro CTAP2 (PIN_INVALID 0x31, PIN_AUTH_INVALID 0x33,
  PIN_AUTH_BLOCKED 0x34, PIN_NOT_SET 0x35, PIN_POLICY_VIOLATION 0x37,
  UNAUTHORIZED_PERMISSION 0x40)
"""

from typing import Any

import importlib.util

import pytest
from fido2.ctap2.base import CtapError, Info
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2

from .ctap2_transport import CtapCmd, SimulatorClient

HAS_FIDO2 = importlib.util.find_spec("fido2") is not None
pytestmark = pytest.mark.skipif(not HAS_FIDO2, reason="python-fido2 não instalado")


class SimCtap2:
    """Subconjunto da API `fido2.ctap2.Ctap2` necessário pelo ClientPin."""

    def __init__(self, client: SimulatorClient) -> None:
        status, info_map = client.send_cbor(CtapCmd.GET_INFO)
        assert status == 0x00, f"getInfo falhou: 0x{status:02x}"
        self.info: Info = Info.from_dict(info_map)
        self._client = client

    def client_pin(
        self,
        pin_uv_protocol: int,
        sub_cmd: int,
        key_agreement=None,
        pin_uv_param: bytes | None = None,
        new_pin_enc: bytes | None = None,
        pin_hash_enc: bytes | None = None,
        permissions: int | None = None,
        permissions_rpid: str | None = None,
        **kwargs,
    ) -> dict[int, Any]:
        args: list[Any] = [
            arg
            for arg in (
                pin_uv_protocol,
                sub_cmd,
                key_agreement,
                pin_uv_param,
                new_pin_enc,
                pin_hash_enc,
                None,
                None,
                permissions,
                permissions_rpid,
            )
            if arg is not None
        ]
        status, resp = self._client.send_cbor(CtapCmd.CLIENT_PIN, args)
        if status != 0x00:
            raise CtapError(status)
        assert isinstance(resp, dict)
        return resp


def make_client_pin(protocol=None) -> tuple[ClientPin, SimulatorClient]:
    client = SimulatorClient()
    ctap = SimCtap2(client)
    pin = ClientPin(ctap, protocol=protocol)
    return pin, client


@pytest.fixture(autouse=True)
def fresh_simulator():
    client = SimulatorClient()
    yield client
    client.close()


def test_get_info_advertises_pin_capabilities():
    with SimulatorClient() as client:
        status, info = client.send_cbor(CtapCmd.GET_INFO)
        assert status == 0x00
        assert 0x06 in info, "pinUvAuthProtocols ausente"
        assert sorted(info[0x06]) == [1, 2]
        options = info.get(0x04, {})
        assert options.get("clientPin") is False
        assert options.get("pinUvAuthToken") is True
        assert "uv" not in options or options.get("uv") is not True

        # CTAP 2.0 / 2.1 §6.4: torna-se True assim que um PIN é definido.
        pin = ClientPin(SimCtap2(client), protocol=PinProtocolV2())
        pin.set_pin("1234")
        status, info_after = client.send_cbor(CtapCmd.GET_INFO)
        assert status == 0x00
        assert info_after.get(0x04, {}).get("clientPin") is True


def test_set_pin_and_retries_protocol_2():
    pin, client = make_client_pin(protocol=PinProtocolV2())
    with client:
        pin.set_pin("1234")
        retries, power_cycle = pin.get_pin_retries()
        assert retries == 8
        assert power_cycle is None


def test_set_pin_and_retries_protocol_1():
    pin, client = make_client_pin(protocol=PinProtocolV1())
    with client:
        pin.set_pin("1234")
        retries, power_cycle = pin.get_pin_retries()
        assert retries == 8
        assert power_cycle is None


def test_full_flow_protocol_2():
    pin, client = make_client_pin(protocol=PinProtocolV2())
    with client:
        pin.set_pin("1234")

        token = pin.get_pin_token("1234")
        assert isinstance(token, bytes)
        assert len(token) == 32

        pin.change_pin("1234", "5678")
        token = pin.get_pin_token("5678")
        assert len(token) == 32

        with pytest.raises(CtapError) as exc:
            pin.get_pin_token("1234")
        assert exc.value.code == CtapError.ERR.PIN_INVALID


def test_full_flow_protocol_1():
    pin, client = make_client_pin(protocol=PinProtocolV1())
    with client:
        pin.set_pin("1234")

        token = pin.get_pin_token("1234")
        assert isinstance(token, bytes)
        assert len(token) in (16, 32)

        pin.change_pin("1234", "5678")
        token = pin.get_pin_token("5678")
        assert len(token) in (16, 32)


def test_get_pin_token_with_permissions_protocol_2():
    """Subcomando 0x09 (getPinUvAuthTokenUsingPinWithPermissions)."""
    pin, client = make_client_pin(protocol=PinProtocolV2())
    with client:
        pin.set_pin("1234")

        permissions = ClientPin.PERMISSION.MAKE_CREDENTIAL | ClientPin.PERMISSION.GET_ASSERTION
        token = pin.get_pin_token("1234", permissions=permissions, permissions_rpid="example.com")
        assert isinstance(token, bytes)
        assert len(token) == 32


def test_get_pin_token_with_mc_ga_requires_rpid():
    """Subcomando 0x09 com permissões mc|ga e sem rpId: MISSING_PARAMETER.

    Sem rpId o token autorizaria MakeCredential/GetAssertion para qualquer RP;
    o CTAP 2.1 §6.5.5.7 exige o parâmetro quando essas permissões estão
    presentes (comportamento do dispositivo virtual do Chromium).
    """
    from hashlib import sha256

    pin, client = make_client_pin(protocol=PinProtocolV2())
    with client:
        pin.set_pin("1234")

        key_agreement, shared_secret = pin._get_shared_secret()
        pin_hash_enc = pin.protocol.encrypt(shared_secret, sha256(b"1234").digest()[:16])
        permissions = ClientPin.PERMISSION.MAKE_CREDENTIAL | ClientPin.PERMISSION.GET_ASSERTION
        status, _ = client.send_cbor(
            CtapCmd.CLIENT_PIN,
            # Array posicional: [protocolo, subcomando, keyAgreement,
            # pinHashEnc, permissions] — rpId omitido.
            [
                2,
                ClientPin.CMD.GET_TOKEN_USING_PIN,
                key_agreement,
                pin_hash_enc,
                permissions,
            ],
        )
        assert status == CtapError.ERR.MISSING_PARAMETER


def test_wrong_pin_errors_and_blocking():
    pin, client = make_client_pin(protocol=PinProtocolV2())
    with client:
        pin.set_pin("1234")

        # 1ª e 2ª tentativas incorretas: PIN_INVALID (0x31), com decremento.
        for expected_retries in (7, 6):
            with pytest.raises(CtapError) as exc:
                pin.get_pin_token("0000")
            assert exc.value.code == CtapError.ERR.PIN_INVALID
            retries, _ = pin.get_pin_retries()
            assert retries == expected_retries

        # 3ª tentativa incorreta consecutiva: PIN_AUTH_BLOCKED (0x34).
        with pytest.raises(CtapError) as exc:
            pin.get_pin_token("0000")
        assert exc.value.code == CtapError.ERR.PIN_AUTH_BLOCKED

        # getPinRetries reporta powerCycleState.
        retries, power_cycle = pin.get_pin_retries()
        assert power_cycle is True

        # Mesmo com o PIN correto, o bloqueio persiste até power cycle.
        with pytest.raises(CtapError) as exc:
            pin.get_pin_token("1234")
        assert exc.value.code == CtapError.ERR.PIN_AUTH_BLOCKED


def test_retries_reset_on_success():
    pin, client = make_client_pin(protocol=PinProtocolV2())
    with client:
        pin.set_pin("1234")
        for _ in range(2):
            with pytest.raises(CtapError):
                pin.get_pin_token("0000")
        retries, _ = pin.get_pin_retries()
        assert retries == 6
        pin.get_pin_token("1234")
        retries, _ = pin.get_pin_retries()
        assert retries == 8


def test_set_pin_when_already_set():
    pin, client = make_client_pin(protocol=PinProtocolV2())
    with client:
        pin.set_pin("1234")
        with pytest.raises(CtapError) as exc:
            pin.set_pin("9999")
        assert exc.value.code == CtapError.ERR.PIN_AUTH_INVALID


def test_set_pin_policy_violation():
    """PIN < 4 bytes deve ser rejeitado com PIN_POLICY_VIOLATION (0x37).

    O python-fido2 valida o comprimento do PIN no lado do cliente; o request
    é montado à mão para exercitar a validação do autenticador.
    """
    client = SimulatorClient()
    with client:
        pin = ClientPin(SimCtap2(client), protocol=PinProtocolV2())
        key_agreement, shared_secret = pin._get_shared_secret()
        new_pin_enc = pin.protocol.encrypt(shared_secret, b"12".ljust(64, b"\x00"))
        pin_auth = pin.protocol.authenticate(shared_secret, new_pin_enc)
        status, _ = client.send_cbor(
            CtapCmd.CLIENT_PIN, [2, ClientPin.CMD.SET_PIN, key_agreement, pin_auth, new_pin_enc]
        )
        assert status == CtapError.ERR.PIN_POLICY_VIOLATION


def test_get_pin_token_without_pin():
    pin, client = make_client_pin(protocol=PinProtocolV2())
    with client:
        with pytest.raises(CtapError) as exc:
            pin.get_pin_token("1234")
        assert exc.value.code == CtapError.ERR.PIN_NOT_SET


def test_unauthorized_permission_rejected():
    pin, client = make_client_pin(protocol=PinProtocolV2())
    with client:
        pin.set_pin("1234")
        with pytest.raises(CtapError) as exc:
            pin.get_pin_token(
                "1234", permissions=ClientPin.PERMISSION.BIO_ENROLL, permissions_rpid="example.com"
            )
        assert exc.value.code == CtapError.ERR.UNAUTHORIZED_PERMISSION


def test_get_uv_token_without_uv_rejected():
    """Sem built-in UV, getPinUvAuthTokenUsingUvWithPermissions (0x06) falha."""
    pin, client = make_client_pin(protocol=PinProtocolV2())
    with client:
        pin.set_pin("1234")
        with pytest.raises(CtapError) as exc:
            pin.get_uv_token(ClientPin.PERMISSION.MAKE_CREDENTIAL, "example.com")
        assert exc.value.code == CtapError.ERR.UV_BLOCKED


def test_unsupported_protocol_rejected():
    client = SimulatorClient()
    with client:
        status, _ = client.send_cbor(CtapCmd.CLIENT_PIN, [3, ClientPin.CMD.GET_KEY_AGREEMENT])
        assert status == CtapError.ERR.INVALID_PARAMETER


def test_tampered_pin_auth_rejected_without_consuming_retries():
    """pinAuth inválido retorna PIN_AUTH_INVALID sem consumir retries."""
    from hashlib import sha256

    client = SimulatorClient()
    with client:
        pin = ClientPin(SimCtap2(client), protocol=PinProtocolV2())
        pin.set_pin("1234")

        # Replica o request changePIN com pinAuth adulterado (32 bytes zero).
        key_agreement, shared_secret = pin._get_shared_secret()
        new_pin_enc = pin.protocol.encrypt(shared_secret, b"5678".ljust(64, b"\x00"))
        pin_hash_enc = pin.protocol.encrypt(shared_secret, sha256(b"1234").digest()[:16])
        status, _ = client.send_cbor(
            CtapCmd.CLIENT_PIN,
            [
                2,
                ClientPin.CMD.CHANGE_PIN,
                key_agreement,
                b"\x00" * 32,
                new_pin_enc,
                pin_hash_enc,
            ],
        )
        assert status == CtapError.ERR.PIN_AUTH_INVALID

        retries, _ = pin.get_pin_retries()
        assert retries == 8


def test_pin_uv_auth_param_is_enforced_for_make_and_get_assertion():
    """Valida MAC, permissões e binding do RP em MakeCredential/GetAssertion."""
    pin, client = make_client_pin(protocol=PinProtocolV2())
    with client:
        pin.set_pin("1234")
        permissions = ClientPin.PERMISSION.MAKE_CREDENTIAL | ClientPin.PERMISSION.GET_ASSERTION
        token = pin.get_pin_token("1234", permissions=permissions, permissions_rpid="example.com")

        client_data_hash = b"\x42" * 32
        pin_uv_param = pin.protocol.authenticate(token, client_data_hash)
        make_request = {
            0x01: client_data_hash,
            0x02: {"id": "example.com", "name": "Example"},
            0x03: {"id": b"user-1"},
            0x04: [{"type": "public-key", "alg": -7}],
            0x05: [],
            0x07: {"rk": False, "uv": False, "up": True},
            0x08: pin_uv_param,
            0x09: 2,
        }
        status, response = client.send_cbor(CtapCmd.MAKE_CREDENTIAL, make_request)
        assert status == 0x00
        auth_data = response[0x02]
        credential_id_length = int.from_bytes(auth_data[53:55], "big")
        credential_id = auth_data[55 : 55 + credential_id_length]
        assert auth_data[32] & 0x04

        assertion_hash = b"\x24" * 32
        assertion_request = {
            0x01: "example.com",
            0x02: assertion_hash,
            0x03: [{"type": "public-key", "id": credential_id}],
            0x05: {"up": True, "uv": False},
            0x06: pin.protocol.authenticate(token, assertion_hash),
            0x07: 2,
        }
        status, response = client.send_cbor(CtapCmd.GET_ASSERTION, assertion_request)
        assert status == 0x00
        assert response[0x02][32] & 0x04

        assertion_request[0x06] = b"\x00" * 32
        status, _ = client.send_cbor(CtapCmd.GET_ASSERTION, assertion_request)
        assert status == CtapError.ERR.PIN_AUTH_INVALID
