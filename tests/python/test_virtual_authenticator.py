"""Testes do autenticador virtual (crate `openkey-core`) via CTAP2 real.

Depende do wheel `openkey_core` instalado (ver `virtualauthenticator.py`) e
da lib `fido2` para encodar/decodificar CBOR e verificar assinaturas.
"""

import pytest
from fido2.webauthn import AuthenticatorData, sha256

from virtualauthenticator import (
    CMD,
    CTAP2_ERROR_NAMES,
    Assertion,
    Ctap2ResponseError,
    VirtualAuthenticator,
)

TEST_AAGUID = bytes(range(16))
TEST_RP_ID = "example.com"


@pytest.fixture
def auth() -> VirtualAuthenticator:
    return VirtualAuthenticator(aaguid=TEST_AAGUID, product_name="openkey-virtual-test")


def register(
    auth: VirtualAuthenticator,
    *,
    user_id: bytes = b"user-1",
    rp_id: str = TEST_RP_ID,
    alg: int = -8,
    exclude_list: list[dict] | None = None,
    options: dict | None = None,
    extensions: dict | None = None,
):
    client_data_hash = sha256(b"register")
    return auth.make_credential(
        rp_id=rp_id,
        user_id=user_id,
        client_data_hash=client_data_hash,
        algorithms=[{"type": "public-key", "alg": alg}],
        exclude_list=exclude_list,
        options=options,
        extensions=extensions,
    )


def assert_login(auth: VirtualAuthenticator, credential_id: bytes) -> Assertion:
    client_data_hash = sha256(b"login")
    return auth.get_assertion(
        rp_id=TEST_RP_ID,
        client_data_hash=client_data_hash,
        allow_list=[{"type": "public-key", "id": credential_id}],
    )


# ---- GetInfo ------------------------------------------------------------


def test_get_info_retorna_versoes_e_aaguid(auth):
    info = auth.get_info()
    assert "2.0" in info["versions"]
    assert "2.1" in info["versions"]
    assert info["aaguid"] == TEST_AAGUID


def test_get_info_lista_algoritmos_suportados(auth):
    info = auth.get_info()
    algs = {a["alg"] for a in info["algorithms"]}
    assert -7 in algs  # ES256
    assert -8 in algs  # EdDSA
    assert all(a["type"] == "public-key" for a in info["algorithms"])


# ---- MakeCredential ------------------------------------------------------


def test_make_credential_produz_attestation_object(auth):
    att = register(auth)
    assert att.fmt == "none"
    assert att.auth_data.is_attested()
    assert att.auth_data.rp_id_hash == auth.rp_id_hash(TEST_RP_ID)
    assert bytes(att.auth_data.credential_data.aaguid) == TEST_AAGUID
    assert len(att.auth_data.credential_data.credential_id) == 16


def test_make_credential_eddsa_por_default(auth):
    att = register(auth)
    key = att.auth_data.credential_data.public_key
    assert key.ALGORITHM == -8  # EdDSA


def test_make_credential_es256(auth):
    att = register(auth, alg=-7)
    key = att.auth_data.credential_data.public_key
    assert key.ALGORITHM == -7  # ES256


def test_flags_up_e_uv_refletem_options(auth):
    att_up = register(auth, options={"rk": False, "uv": False, "up": True})
    assert att_up.auth_data.is_user_present()
    assert not att_up.auth_data.is_user_verified()

    att_uv = register(
        auth, user_id=b"user-2", options={"rk": False, "uv": True, "up": False}
    )
    assert att_uv.auth_data.is_user_verified()
    assert not att_uv.auth_data.is_user_present()


def test_exclude_list_rejeita_credencial_existente(auth):
    att = register(auth)
    with pytest.raises(Ctap2ResponseError) as exc:
        register(
            auth,
            user_id=b"user-2",
            exclude_list=[
                {"type": "public-key", "id": att.auth_data.credential_data.credential_id}
            ],
        )
    assert exc.value.code == 0x19  # CREDENTIAL_EXCLUDED
    assert exc.value.name == "CREDENTIAL_EXCLUDED"


def test_algoritmo_nao_suportado(auth):
    with pytest.raises(Ctap2ResponseError) as exc:
        register(auth, alg=-65535)  # RS1 não é suportado
    assert exc.value.code == 0x26  # UNSUPPORTED_ALGORITHM


def test_cred_blob_roundtrip(auth):
    blob = b"openkey-blob"
    response = auth.process_command(
        CMD.MAKE_CREDENTIAL,
        {
            "clientDataHash": sha256(b"register"),
            "rp": {"id": TEST_RP_ID},
            "user": {"id": b"user-1"},
            "pubKeyCredParams": [{"type": "public-key", "alg": -8}],
            "excludeList": [],
            "options": {"rk": False, "uv": False, "up": True},
            "extensions": {"credBlob": blob},
        },
    )
    assert response["extensions"]["credBlob"] == blob

    credential_id = AuthenticatorData(bytes(response["authData"])).credential_data.credential_id
    assertion = auth.get_assertion(
        rp_id=TEST_RP_ID,
        client_data_hash=sha256(b"login"),
        allow_list=[{"type": "public-key", "id": credential_id}],
        extensions={"credBlob": b""},
    )
    assert assertion.extensions["credBlob"] == blob


# ---- GetAssertion --------------------------------------------------------


def test_assertion_eddsa_verifica_assinatura(auth):
    att = register(auth)
    credential_id = att.auth_data.credential_data.credential_id
    client_data_hash = sha256(b"login")
    assertion = auth.get_assertion(
        rp_id=TEST_RP_ID,
        client_data_hash=client_data_hash,
        allow_list=[{"type": "public-key", "id": credential_id}],
    )
    assert assertion.credential_id == credential_id
    assert assertion.user_handle == b"user-1"
    assertion.verify(att.auth_data.credential_data.public_key, client_data_hash)


def test_assertion_es256_verifica_assinatura(auth):
    att = register(auth, alg=-7)
    client_data_hash = sha256(b"login")
    assertion = auth.get_assertion(
        rp_id=TEST_RP_ID,
        client_data_hash=client_data_hash,
        allow_list=[
            {"type": "public-key", "id": att.auth_data.credential_data.credential_id}
        ],
    )
    assertion.verify(att.auth_data.credential_data.public_key, client_data_hash)


def test_assertion_rejeita_assinatura_incorreta(auth):
    att = register(auth)
    client_data_hash = sha256(b"login")
    assertion = auth.get_assertion(
        rp_id=TEST_RP_ID,
        client_data_hash=client_data_hash,
        allow_list=[
            {"type": "public-key", "id": att.auth_data.credential_data.credential_id}
        ],
    )
    with pytest.raises(Exception):
        assertion.verify(att.auth_data.credential_data.public_key, sha256(b"outra-coisa"))


def test_sign_counter_incrementa_a_cada_assertion(auth):
    att = register(auth)
    credential_id = att.auth_data.credential_data.credential_id
    first = assert_login(auth, credential_id)
    second = assert_login(auth, credential_id)
    assert first.auth_data.counter == 1
    assert second.auth_data.counter == 2


def test_allow_list_seleciona_credencial_especifica(auth):
    att1 = register(auth, user_id=b"user-1")
    att2 = register(auth, user_id=b"user-2")
    assertion = auth.get_assertion(
        rp_id=TEST_RP_ID,
        client_data_hash=sha256(b"login"),
        allow_list=[
            {"type": "public-key", "id": att1.auth_data.credential_data.credential_id}
        ],
    )
    assert assertion.credential_id == att1.auth_data.credential_data.credential_id
    assert assertion.user_handle == b"user-1"
    assert assertion.credential_id != att2.auth_data.credential_data.credential_id


def test_assertion_sem_credenciais_devolve_no_credentials(auth):
    with pytest.raises(Ctap2ResponseError) as exc:
        auth.get_assertion(rp_id=TEST_RP_ID, client_data_hash=sha256(b"login"))
    assert exc.value.code == 0x2E  # NO_CREDENTIALS
    assert exc.value.name == "NO_CREDENTIALS"


# ---- Reset e comandos inválidos ------------------------------------------


def test_reset_limpa_todas_as_credenciais(auth):
    att = register(auth)
    auth.reset()
    with pytest.raises(Ctap2ResponseError) as exc:
        assert_login(auth, att.auth_data.credential_data.credential_id)
    assert exc.value.code == 0x2E


def test_comando_desconhecido_devolve_invalid_command(auth):
    with pytest.raises(Ctap2ResponseError) as exc:
        auth.process_command(0xFF)  # comando não existente
    assert exc.value.code == 0x01  # INVALID_COMMAND


def test_tabela_de_erros_cobre_codigos_usados(auth):
    for code in (0x01, 0x19, 0x26, 0x2E, 0x35):
        assert code in CTAP2_ERROR_NAMES
