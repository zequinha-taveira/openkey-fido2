"""Ponte de alto nível para o autenticador virtual (`openkey-core`).

O módulo `openkey_core` (pyo3/maturin) expõe `VirtualAuthenticator`, que roda
o mesmo núcleo Rust (`EmbeddedAuthenticator`) que compila para firmware real.
Esta ponte fala CTAP2 real sobre CBOR:

* encoda os requests com `fido2.cbor.encode`;
* decodifica as respostas com os helpers de `fido2.webauthn`
  (`AttestationObject`, `AuthenticatorData`) ou devolve o dict cru.

Permite que testes em pytest exercitem o firmware sem passar pelo simulador
de linha, mantendo o mesmo wire format.
"""

from dataclasses import dataclass, field

from fido2 import cbor
from fido2.webauthn import AttestationObject, AuthenticatorData, sha256

try:
    import openkey_core as _openkey_core
except ImportError as _exc:  # pragma: no cover - mensagem amigável p/ CI
    raise ImportError(
        "módulo 'openkey_core' não encontrado. Compile o wheel com: "
        "`python -m maturin build --manifest-path python\\openkey_core\\Cargo.toml "
        "--interpreter python` e instale com `pip install`."
    ) from _exc


class CMD:
    """Códigos de comando CTAP2 (mesmos valores do enumerador Rust)."""

    MAKE_CREDENTIAL = 0x01
    GET_ASSERTION = 0x02
    GET_INFO = 0x04
    CLIENT_PIN = 0x06
    RESET = 0x07


CTAP2_ERROR_NAMES = {
    0x00: "SUCCESS",
    0x01: "INVALID_COMMAND",
    0x02: "INVALID_PARAMETER",
    0x03: "INVALID_LENGTH",
    0x04: "INVALID_SEQUENCE",
    0x05: "TIMEOUT",
    0x06: "CHANNEL_BUSY",
    0x19: "CREDENTIAL_EXCLUDED",
    0x26: "UNSUPPORTED_ALGORITHM",
    0x2E: "NO_CREDENTIALS",
    0x27: "OPERATION_DENIED",
    0x31: "PIN_INVALID",
    0x32: "PIN_BLOCKED",
    0x33: "PIN_AUTH_INVALID",
    0x34: "PIN_AUTH_BLOCKED",
    0x35: "PIN_NOT_SET",
    0x36: "PUAT_REQUIRED",
    0x37: "PIN_POLICY_VIOLATION",
    0x38: "PIN_TOKEN_EXPIRED",
    0x39: "REQUEST_TOO_LARGE",
}


# Chaves inteiras CTAP2 (wire format) → nomes de campo da API de alto nível.
_RESPONSE_KEYS: dict[int, dict[int, str]] = {
    CMD.MAKE_CREDENTIAL: {0x01: "fmt", 0x02: "authData", 0x03: "attStmt", 0x06: "extensions"},
    CMD.GET_ASSERTION: {
        0x01: "credential",
        0x02: "authData",
        0x03: "signature",
        0x04: "user",
        0x05: "numberOfCredentials",
        0x06: "extensions",
    },
    CMD.GET_INFO: {
        0x01: "versions",
        0x02: "extensions",
        0x03: "aaguid",
        0x04: "options",
        0x0A: "algorithms",
    },
}


def _convert_response_keys(cmd: int, response):
    """Converte chaves inteiras do wire format CTAP2 para nomes de campo."""
    key_map = _RESPONSE_KEYS.get(cmd, {})
    if isinstance(response, dict):
        return {key_map.get(k, k): v for k, v in response.items()}
    return response


def _compact(data):
    """Remove recursivamente valores `None` (o encoder do fido2 os rejeita)."""
    if isinstance(data, dict):
        return {k: _compact(v) for k, v in data.items() if v is not None}
    if isinstance(data, list):
        return [_compact(v) for v in data if v is not None]
    return data


class Ctap2ResponseError(Exception):
    """Erro CTAP2 devolvido pelo autenticador virtual.

    :ivar code: código numérico CTAP2 (ex.: 0x0E = NO_CREDENTIALS).
    :ivar name: nome amigável do código, quando conhecido.
    """

    def __init__(self, code: int, name: str | None = None):
        self.code = code
        self.name = name
        super().__init__(f"CTAP2 error 0x{code:02X}{' (' + name + ')' if name else ''}")


@dataclass(frozen=True)
class Assertion:
    """Resposta de `getAssertion` já decodificada.

    :ivar auth_data: authenticatorData (37 bytes para assertion sem
        extensões; `counter` é o sign counter).
    :ivar signature: assinatura sobre `authData || clientDataHash`.
    :ivar credential_id: ID da credencial selecionada.
    :ivar user_handle: user handle da credencial.
    :ivar extensions: mapa de saídas de extensões, se houver.
    """

    auth_data: AuthenticatorData
    signature: bytes
    credential_id: bytes
    user_handle: bytes
    extensions: dict | None = None

    def verify(self, public_key, client_data_hash: bytes) -> None:
        """Verifica a assinatura com a chave pública da credencial.

        O base de assinatura WebAuthn é `authenticatorData || clientDataHash`.
        Lança se a assinatura for inválida.
        """
        signed = bytes(self.auth_data) + bytes(client_data_hash)
        public_key.verify(signed, bytes(self.signature))


class VirtualAuthenticator:
    """Autenticador virtual CTAP2, como visto pelo protocolo.

    Embrulha a classe nativa `openkey_core.VirtualAuthenticator` e
    codifica/decodifica o CBOR dos requests e respostas CTAP2.
    """

    def __init__(
        self,
        aaguid: bytes | None = None,
        product_name: str | None = None,
    ):
        self._native = _openkey_core.VirtualAuthenticator(
            aaguid=bytes(aaguid) if aaguid is not None else None,
            product_name=product_name,
        )

    def process_command(self, cmd: int, request=None):
        """Envia um comando CTAP2 e devolve a resposta decodificada.

        :param cmd: código do comando CTAP2 (veja `CMD`).
        :param request: dict/list para encodar em CBOR, bytes já codificados
            ou None para comandos sem payload.
        :raises Ctap2ResponseError: quando o autenticador responde erro.
        """
        if request is None:
            data = b""
        elif isinstance(request, (bytes, bytearray)):
            data = bytes(request)
        else:
            data = cbor.encode(_compact(request))
        status, response = self._native.process_command(cmd, data)
        if status != 0:
            raise Ctap2ResponseError(status, name=CTAP2_ERROR_NAMES.get(status))
        if not response:
            return None
        return _convert_response_keys(cmd, cbor.decode(response))

    # ---- comandos de alto nível ----------------------------------------

    def get_info(self) -> dict:
        """Retorna o resultado cru de `getInfo`."""
        return self.process_command(CMD.GET_INFO)

    def make_credential(
        self,
        *,
        rp_id: str,
        user_id: bytes,
        client_data_hash: bytes,
        user_name: str | None = None,
        user_display_name: str | None = None,
        algorithms: list[dict] | None = None,
        exclude_list: list[dict] | None = None,
        options: dict | None = None,
        extensions: dict | None = None,
    ) -> AttestationObject:
        """Executa `makeCredential` e devolve o AttestationObject (CBOR).

        Defaults: algoritmo EdDSA (-8), `excludeList` vazio e
        `options = {"rk": False, "uv": False, "up": True}`.
        """
        request = {
            0x01: bytes(client_data_hash),
            0x02: {"id": rp_id},
            0x03: {
                "id": bytes(user_id),
                "name": user_name,
                "displayName": user_display_name,
            },
            0x04: algorithms
            or [{"type": "public-key", "alg": -8}],
            0x05: [
                {"type": "public-key", "id": bytes(d["id"])}
                for d in (exclude_list or [])
            ],
            0x07: options or {"rk": False, "uv": False, "up": True},
            0x06: extensions,
        }
        response = self.process_command(CMD.MAKE_CREDENTIAL, request)
        return AttestationObject(cbor.encode(response))

    def get_assertion(
        self,
        *,
        rp_id: str,
        client_data_hash: bytes,
        allow_list: list[dict] | None = None,
        options: dict | None = None,
        extensions: dict | None = None,
    ) -> Assertion:
        """Executa `getAssertion` e devolve a resposta decodificada."""
        request = {
            0x01: rp_id,
            0x02: bytes(client_data_hash),
            0x03: [
                {"type": "public-key", "id": bytes(d["id"])}
                for d in (allow_list or [])
            ],
            0x05: options or {"up": True, "uv": False},
            0x04: extensions,
        }
        response = self.process_command(CMD.GET_ASSERTION, request)
        return Assertion(
            auth_data=AuthenticatorData(bytes(response["authData"])),
            signature=bytes(response["signature"]),
            credential_id=bytes(response["credential"]["id"]),
            user_handle=bytes(response["user"]["id"]),
            extensions=response.get("extensions"),
        )

    def reset(self) -> None:
        """Executa `reset`, apagando todas as credenciais."""
        self.process_command(CMD.RESET)

    def set_presence_pressed(self, pressed: bool) -> None:
        """Simula o botão de user presence (ex.: BOOTSEL do RP2350).

        Quando `False`, comandos com `up` (MakeCredential/GetAssertion)
        retornam `OPERATION_DENIED` (0x13), como um botão físico solto.
        """
        self._native.set_presence_pressed(pressed)

    @staticmethod
    def rp_id_hash(rp_id: str) -> bytes:
        """SHA-256 do RP ID, como usado no authenticatorData."""
        return sha256(rp_id.encode("utf-8"))
