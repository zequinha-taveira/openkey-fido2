"""Testes de simulação de user presence (botão BOOTSEL do RP2350).

O núcleo Rust aplica o check de `up` (toque físico) em MakeCredential e
GetAssertion. A ponte `openkey_core` expõe `set_presence_pressed` para
simular press/release do botão:

  - sem botão (default): usuário considerado presente;
  - botão solto + `up: true`  -> OPERATION_DENIED (0x13);
  - botão pressionado + `up: true` -> sucesso;
  - `up: false` dispensa o check, independente do botão.
"""

import pytest
from fido2.webauthn import sha256

from virtualauthenticator import Ctap2ResponseError, VirtualAuthenticator

TEST_RP_ID = "example.com"
ERR_OPERATION_DENIED = 0x13


@pytest.fixture
def auth() -> VirtualAuthenticator:
    return VirtualAuthenticator(product_name="openkey-presence-test")


def register(auth, *, user_id: bytes = b"user-1", up: bool = True):
    return auth.make_credential(
        rp_id=TEST_RP_ID,
        user_id=user_id,
        client_data_hash=sha256(b"register"),
        options={"rk": False, "uv": False, "up": up},
    )


def login(auth, credential_id: bytes, *, up: bool = True):
    return auth.get_assertion(
        rp_id=TEST_RP_ID,
        client_data_hash=sha256(b"login"),
        allow_list=[{"type": "public-key", "id": credential_id}],
        options={"up": up, "uv": False},
    )


# ---- MakeCredential ------------------------------------------------------


def test_up_default_considera_usuario_presente(auth):
    # Sem tocar no botão, a presença é assumida (compatível com o default).
    att = register(auth, up=True)
    assert att.auth_data.is_user_present()


def test_up_negado_quando_botao_nao_pressionado(auth):
    auth.set_presence_pressed(False)
    with pytest.raises(Ctap2ResponseError) as exc:
        register(auth, up=True)
    assert exc.value.code == ERR_OPERATION_DENIED
    assert exc.value.name == "OPERATION_DENIED"


def test_up_permitido_quando_botao_pressionado(auth):
    auth.set_presence_pressed(True)
    att = register(auth, up=True)
    assert att.auth_data.is_user_present()


def test_up_false_dispensa_check_de_presenca(auth):
    auth.set_presence_pressed(False)
    att = register(auth, up=False)
    assert not att.auth_data.is_user_present()


# ---- GetAssertion --------------------------------------------------------


def test_assertion_up_negado_sem_botao(auth):
    att = register(auth)
    credential_id = att.auth_data.credential_data.credential_id

    auth.set_presence_pressed(False)
    with pytest.raises(Ctap2ResponseError) as exc:
        login(auth, credential_id, up=True)
    assert exc.value.code == ERR_OPERATION_DENIED


def test_assertion_up_ok_com_botao_pressionado(auth):
    att = register(auth)
    credential_id = att.auth_data.credential_data.credential_id

    auth.set_presence_pressed(True)
    assertion = login(auth, credential_id, up=True)
    assert assertion.credential_id == credential_id


def test_assertion_up_false_dispensa_check_de_presenca(auth):
    att = register(auth)
    credential_id = att.auth_data.credential_data.credential_id

    auth.set_presence_pressed(False)
    assertion = login(auth, credential_id, up=False)
    assert assertion.credential_id == credential_id
