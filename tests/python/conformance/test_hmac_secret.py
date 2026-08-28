"""Testes de conformidade CTAP 2.1 §12.5 — extensão `hmac-secret`.

Fluxo completo do lado da plataforma contra o simulador em modo raw CBOR,
usando os primitivos criptográficos de referência do python-fido2
(`fido2.ctap2.pin.ClientPin` / `PinProtocolV1` / `PinProtocolV2`):

- MakeCredential com `"hmac-secret": true` — resposta booleana.
- GetAssertion com o mapa `{1: keyAgreement, 2: saltEnc, 3: saltAuth,
  4: pinUvAuthProtocol}` — a plataforma deriva o segredo compartilhado por
  ECDH P-256 + KDF do protocolo PIN/UV, cifra os salts, verifica a saída
  decifrando-a com o mesmo segredo e confere determinismo/tamanho.
"""

import hashlib
import importlib.util
import os

import pytest
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2

from .ctap2_transport import CtapCmd, CtapError, SimulatorClient

HAS_FIDO2 = importlib.util.find_spec("fido2") is not None
pytestmark = pytest.mark.skipif(not HAS_FIDO2, reason="python-fido2 não instalado")

SALT_LEN = 32


class SimCtap2:
    """Subconjunto da API `fido2.ctap2.Ctap2` necessário pelo ClientPin."""

    def __init__(self, client: SimulatorClient) -> None:
        status, info_map = client.send_cbor(CtapCmd.GET_INFO)
        assert status == 0x00, f"getInfo falhou: 0x{status:02x}"
        from fido2.ctap2.base import Info

        self.info = Info.from_dict(info_map)
        self._client = client

    def client_pin(
        self,
        pin_uv_protocol,
        sub_cmd,
        key_agreement=None,
        pin_uv_param=None,
        new_pin_enc=None,
        pin_hash_enc=None,
        permissions=None,
        permissions_rpid=None,
        **kwargs,
    ):
        # Ordem posicional da spec (CTAP 2.1 §6.5): protocol, subCommand,
        # keyAgreement(0x03), pinUvAuthParam(0x04), newPinEnc(0x05),
        # pinHashEnc(0x06), permissions(0x09), rpId(0x0A).
        args = [
            arg
            for arg in (
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
        status, resp = self._client.send_cbor(
            CtapCmd.CLIENT_PIN, [pin_uv_protocol, sub_cmd, *args]
        )
        if status != 0x00:
            from fido2.ctap2.base import CtapError as Err

            raise Err(status)
        return resp


def get_shared_secret(client, protocol):
    """getKeyAgreement + ECDH: devolve (key_agreement, shared_secret)."""
    ctap = SimCtap2(client)
    pin = ClientPin(ctap, protocol)
    return pin._get_shared_secret()


def make_credential_request(extensions):
    client_data = b'{"type":"webauthn.create","challenge":"AAAA"}'
    return {
        0x01: hashlib.sha256(client_data).digest(),
        0x02: {"id": "example.com", "name": "Example Corp"},
        0x03: {"id": b"user_123", "name": "alice@example.com"},
        0x04: [{"type": "public-key", "alg": -7}],
        0x05: [],
        0x06: extensions,
        0x07: {"rk": False, "uv": False, "up": True},
    }


def get_assertion_request(extensions=None, credential_id=b"", uv=False):
    client_data = b'{"type":"webauthn.get","challenge":"BBBB"}'
    request = {
        "rpId": "example.com",
        "clientDataHash": hashlib.sha256(client_data).digest(),
        "allowList": [{"type": "public-key", "id": credential_id}],
        "options": {"up": True, "uv": uv},
    }
    if extensions is not None:
        request["extensions"] = extensions
    return request


def build_hmac_extension(protocol, shared_secret, key_agreement, salts):
    """Monta `{1: ka, 2: saltEnc, 3: saltAuth, 4: protocolo}` conforme §12.5."""
    salt_enc = protocol.encrypt(shared_secret, salts)
    salt_auth = protocol.authenticate(shared_secret, salt_enc)
    return {
        1: key_agreement,
        2: salt_enc,
        3: salt_auth,
        4: protocol.VERSION,
    }


def make_credential_with_hmac(client):
    status, resp = client.send_cbor(
        CtapCmd.MAKE_CREDENTIAL, make_credential_request({"hmac-secret": True})
    )
    assert status == CtapError.SUCCESS, f"MakeCredential falhou: 0x{status:02x}"
    extensions = resp.get(0x06) or resp.get(0x04) or resp.get("extensions")
    assert extensions is not None, f"extensões ausentes na resposta: {list(resp)}"
    assert extensions["hmac-secret"] is True
    auth_data = resp.get("authData") or resp.get(0x02)
    # attestedCredentialData: rpIdHash(32) + flags(1) + signCount(4)
    # + aaguid(16) + credIdLen(2) + credId
    cred_len = int.from_bytes(auth_data[53:55], "big")
    return auth_data[55 : 55 + cred_len]


def hmac_output(
    client,
    protocol,
    shared_secret,
    key_agreement,
    salts,
    credential_id,
    uv=True,
    pin_token=None,
):
    extension = build_hmac_extension(protocol, shared_secret, key_agreement, salts)
    request = get_assertion_request({"hmac-secret": extension}, credential_id, uv=uv)
    if pin_token is not None:
        # Autentica a operação com o pinUvAuthToken (CTAP 2.1 §6.5.8):
        # MAC sobre o clientDataHash + versão do protocolo.
        request["pinUvAuthParam"] = protocol.authenticate(
            pin_token, request["clientDataHash"]
        )
        request["pinUvAuthProtocol"] = protocol.VERSION
    status, resp = client.send_cbor(CtapCmd.GET_ASSERTION, request)
    assert status == CtapError.SUCCESS, f"GetAssertion falhou: 0x{status:02x}"
    out_extensions = resp.get(0x06) or resp.get("extensions")
    encrypted = out_extensions["hmac-secret"]
    assert isinstance(encrypted, bytes)
    return protocol.decrypt(shared_secret, encrypted)


@pytest.mark.parametrize("protocol_class", [PinProtocolV1, PinProtocolV2])
def test_hmac_secret_full_platform_flow(protocol_class):
    """MakeCredential booleano + GetAssertion com um e dois salts."""
    protocol = protocol_class()
    with SimulatorClient() as client:
        client.send_cbor(CtapCmd.RESET)
        credential_id = make_credential_with_hmac(client)

        # Um salt: saída = HMAC-SHA-256(CredRandom, salt1) cifrado (32 bytes).
        key_agreement, shared_secret = get_shared_secret(client, protocol)
        salt1 = os.urandom(SALT_LEN)
        output = hmac_output(
            client, protocol, shared_secret, key_agreement, salt1, credential_id
        )
        assert len(output) == SALT_LEN

        # Dois salts: saída = output1 || output2 (64 bytes).
        key_agreement, shared_secret = get_shared_secret(client, protocol)
        salt2 = os.urandom(SALT_LEN)
        output = hmac_output(
            client, protocol, shared_secret, key_agreement, salt1 + salt2, credential_id
        )
        assert len(output) == 2 * SALT_LEN


@pytest.mark.parametrize("protocol_class", [PinProtocolV1, PinProtocolV2])
def test_hmac_secret_deterministic_per_salt(protocol_class):
    """Mesmo salt → mesma saída; salt diferente → saída diferente."""
    protocol = protocol_class()
    with SimulatorClient() as client:
        client.send_cbor(CtapCmd.RESET)
        credential_id = make_credential_with_hmac(client)

        salt = os.urandom(SALT_LEN)
        other = os.urandom(SALT_LEN)

        key_agreement, shared_secret = get_shared_secret(client, protocol)
        first = hmac_output(
            client, protocol, shared_secret, key_agreement, salt, credential_id
        )

        key_agreement, shared_secret = get_shared_secret(client, protocol)
        second = hmac_output(
            client, protocol, shared_secret, key_agreement, salt, credential_id
        )

        key_agreement, shared_secret = get_shared_secret(client, protocol)
        third = hmac_output(
            client, protocol, shared_secret, key_agreement, other, credential_id
        )

        assert first == second
        assert first != third


@pytest.mark.parametrize("protocol_class", [PinProtocolV1, PinProtocolV2])
def test_hmac_secret_selects_cred_random_by_uv_bit(protocol_class):
    """§12.5 com bit UV verdadeiro: CredRandomWithUV somente quando a
    operação é autenticada por pinUvAuthToken; sem autenticação (mesmo
    pedindo `uv`), a saída deriva de CredRandomWithoutUV."""
    protocol = protocol_class()
    with SimulatorClient() as client:
        client.send_cbor(CtapCmd.RESET)
        credential_id = make_credential_with_hmac(client)

        salt = os.urandom(SALT_LEN)

        # Sem token e sem PIN configurado: o pedido `uv` não verifica
        # ninguém — a resposta não pode alegar verificação.
        key_agreement, shared_secret = get_shared_secret(client, protocol)
        without_uv = hmac_output(
            client, protocol, shared_secret, key_agreement, salt, credential_id, uv=True
        )

        # Configura PIN e obtém pinUvAuthToken (permissões mc|ga).
        ctap = SimCtap2(client)
        pin = ClientPin(ctap, protocol)
        pin.set_pin("1234")
        token = pin.get_pin_token("1234")

        # Mesma asserção autenticada pelo token: verificação real.
        key_agreement, shared_secret = get_shared_secret(client, protocol)
        with_uv = hmac_output(
            client,
            protocol,
            shared_secret,
            key_agreement,
            salt,
            credential_id,
            uv=True,
            pin_token=token,
        )

        assert with_uv != without_uv


def test_hmac_secret_fresh_nonce_protocol_2():
    """Requisições idênticas produzem ciphertexts distintos (IV aleatório)."""
    protocol = PinProtocolV2()
    with SimulatorClient() as client:
        client.send_cbor(CtapCmd.RESET)
        credential_id = make_credential_with_hmac(client)

        salt = os.urandom(SALT_LEN)
        ciphertexts = []
        plaintexts = []
        for _ in range(2):
            key_agreement, shared_secret = get_shared_secret(client, protocol)
            extension = build_hmac_extension(protocol, shared_secret, key_agreement, salt)
            request = get_assertion_request({"hmac-secret": extension}, credential_id)
            status, resp = client.send_cbor(CtapCmd.GET_ASSERTION, request)
            assert status == CtapError.SUCCESS
            encrypted = (resp.get(0x06) or resp.get("extensions"))["hmac-secret"]
            ciphertexts.append(encrypted)
            plaintexts.append(protocol.decrypt(shared_secret, encrypted))

        assert ciphertexts[0] != ciphertexts[1]
        assert plaintexts[0] == plaintexts[1]


@pytest.mark.parametrize("protocol_class", [PinProtocolV1, PinProtocolV2])
def test_hmac_secret_tampered_salt_auth_rejected(protocol_class):
    """§12.5: verify(sharedSecret, saltEnc, saltAuth) falho → PIN_AUTH_INVALID."""
    protocol = protocol_class()
    with SimulatorClient() as client:
        client.send_cbor(CtapCmd.RESET)
        credential_id = make_credential_with_hmac(client)

        key_agreement, shared_secret = get_shared_secret(client, protocol)
        salt = os.urandom(SALT_LEN)
        extension = build_hmac_extension(protocol, shared_secret, key_agreement, salt)
        tampered_tag = bytearray(extension[3])
        tampered_tag[0] ^= 0xFF
        extension[3] = bytes(tampered_tag)

        request = get_assertion_request({"hmac-secret": extension}, credential_id)
        status, _ = client.send_cbor(CtapCmd.GET_ASSERTION, request)
        assert status == CtapError.PIN_AUTH_INVALID


@pytest.mark.parametrize("protocol_class", [PinProtocolV1, PinProtocolV2])
def test_hmac_secret_invalid_salt_length_rejected(protocol_class):
    """§12.5: plaintext não 32/64 bytes → CTAP1_ERR_INVALID_PARAMETER."""
    protocol = protocol_class()
    with SimulatorClient() as client:
        client.send_cbor(CtapCmd.RESET)
        credential_id = make_credential_with_hmac(client)

        key_agreement, shared_secret = get_shared_secret(client, protocol)
        extension = build_hmac_extension(
            protocol, shared_secret, key_agreement, os.urandom(48)
        )
        request = get_assertion_request({"hmac-secret": extension}, credential_id)
        status, _ = client.send_cbor(CtapCmd.GET_ASSERTION, request)
        assert status == CtapError.INVALID_PARAMETER


def test_hmac_secret_wrong_key_material_rejected():
    """saltEnc/saltAuth sob segredo que o autenticador não compartilha falham."""
    protocol = PinProtocolV1()
    with SimulatorClient() as client:
        client.send_cbor(CtapCmd.RESET)
        credential_id = make_credential_with_hmac(client)

        # Acordo "órfão": sem getKeyAgreement prévio o autenticador não tem a
        # chave efêmera correspondente — a verificação não pode passar.
        ctap = SimCtap2(client)
        pin = ClientPin(ctap, protocol)
        key_agreement, shared_secret = pin._get_shared_secret()
        # Consome a chave anunciada com um getKeyAgreement extra.
        get_shared_secret(client, protocol)

        salt = os.urandom(SALT_LEN)
        extension = build_hmac_extension(protocol, shared_secret, key_agreement, salt)
        request = get_assertion_request({"hmac-secret": extension}, credential_id)
        status, _ = client.send_cbor(CtapCmd.GET_ASSERTION, request)
        assert status == CtapError.PIN_AUTH_INVALID


def make_two_credentials_with_hmac(client):
    """Duas credenciais residentes, mesmo RP, usuários distintos (§12.5)."""
    credential_ids = []
    for user_id in (b"user_chain_1", b"user_chain_2"):
        client_data = b'{"type":"webauthn.create","challenge":"AAAA"}'
        request = {
            0x01: hashlib.sha256(client_data).digest(),
            0x02: {"id": "example.com", "name": "Example Corp"},
            0x03: {"id": user_id, "name": "alice@example.com"},
            0x04: [{"type": "public-key", "alg": -7}],
            0x05: [],
            0x06: {"hmac-secret": True},
            0x07: {"rk": True, "uv": False, "up": True},
        }
        status, resp = client.send_cbor(CtapCmd.MAKE_CREDENTIAL, request)
        assert status == CtapError.SUCCESS, f"MakeCredential falhou: 0x{status:02x}"
        extensions = resp.get(0x06) or resp.get(0x04) or resp.get("extensions")
        assert extensions is not None and extensions["hmac-secret"] is True
        auth_data = resp.get("authData") or resp.get(0x02)
        cred_len = int.from_bytes(auth_data[53:55], "big")
        credential_ids.append(auth_data[55 : 55 + cred_len])
    return credential_ids


@pytest.mark.parametrize("protocol_class", [PinProtocolV1, PinProtocolV2])
def test_hmac_secret_chained_get_next_assertion(protocol_class):
    """Asserções encadeadas (ADR-0022): o GetNextAssertion devolve a saída
    `HMAC(CredRandom_da_segunda_credencial, salt)` cifrada sob o MESMO segredo
    compartilhado da asserção inicial — a plataforma não repete o acordo de
    chaves no meio da transação. Cada resposta recebe cifra fresca e a sessão
    termina com a cadeia (GetNextAssertion extra → NO_CREDENTIALS)."""
    protocol = protocol_class()
    with SimulatorClient() as client:
        client.send_cbor(CtapCmd.RESET)
        credential_ids = make_two_credentials_with_hmac(client)
        assert len(set(credential_ids)) == 2

        # Asserção inicial por descoberta de RP (sem allowList): a cadeia
        # contém as duas credenciais.
        key_agreement, shared_secret = get_shared_secret(client, protocol)
        salt = os.urandom(SALT_LEN)
        extension = build_hmac_extension(protocol, shared_secret, key_agreement, salt)
        ga_request = {
            "rpId": "example.com",
            "clientDataHash": hashlib.sha256(
                b'{"type":"webauthn.get","challenge":"BBBB"}'
            ).digest(),
            "allowList": [],
            "options": {"up": True, "uv": False},
            "extensions": {"hmac-secret": extension},
        }
        status, first = client.send_cbor(CtapCmd.GET_ASSERTION, ga_request)
        assert status == CtapError.SUCCESS, f"GetAssertion falhou: 0x{status:02x}"
        assert (first.get(0x05) or first.get("numberOfCredentials")) == 2
        ext_first = (first.get(0x06) or first.get("extensions"))["hmac-secret"]
        assert isinstance(ext_first, bytes)
        assert len(protocol.decrypt(shared_secret, ext_first)) == SALT_LEN

        # GetNextAssertion: saída presente e decifrável pelo MESMO segredo.
        status, second = client.send_cbor(CtapCmd.GET_NEXT_ASSERTION)
        assert status == CtapError.SUCCESS, f"GetNextAssertion falhou: 0x{status:02x}"
        assert (second.get(0x01) or second.get("credential"))["id"] in credential_ids
        ext_second = (second.get(0x06) or second.get("extensions"))["hmac-secret"]
        assert isinstance(ext_second, bytes)
        # IV fresco por resposta: ciphertexts diferem embora os plaintexts
        # tenham o mesmo tamanho (32B, um salt).
        assert ext_first != ext_second
        assert len(protocol.decrypt(shared_secret, ext_second)) == SALT_LEN

        # Cadeia esgotada: a transação terminou com a última asserção.
        status, _ = client.send_cbor(CtapCmd.GET_NEXT_ASSERTION)
        assert status == CtapError.NO_CREDENTIALS
