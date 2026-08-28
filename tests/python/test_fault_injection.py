"""InjeÃ§Ã£o deliberada de falhas com atribuiÃ§Ã£o exata da camada que falhou.

Em vez de procurar padrÃµes estÃ¡ticos no cÃ³digo, cada teste provoca um erro
concreto no fio (wire) contra o simulador e exige o cÃ³digo de status que
identifica univocamente a camada que rejeitou a operaÃ§Ã£o:

    FRAMING/TRANSPORTE  â†’ nenhum status (descarte silencioso ou EOF)
    DESPACHO CTAP2      â†’ 0x01 InvalidCommand   (ctap2.rs process_command)
    CODEC CBOR          â†’ 0x12 InvalidCbor     (decode_cbor dos requests)
    VALIDAÃ‡ÃƒO DE REQUESTâ†’ 0x26/0x19/0x02       (handlers semÃ¢nticos)
    ESTADO AUTENTICADOR â†’ 0x30/0x2E/0x31/0x35  (storage/sessÃ£o/transaÃ§Ãµes)

Cada teste roda primeiro um CONTROLE POSITIVO: o mesmo comando sem a falha
deve ter sucesso. Assim, quando a rejeiÃ§Ã£o acontece, ela vem da falha
injetada â€” nÃ£o de um estado prÃ©vio quebrado. Se o cÃ³digo observado difere
do esperado, a mensagem de erro aponta a camada que realmente falhou.

Requisito: simulador compilado (`cargo build -p fido2-simulator`).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from fido2 import cbor

from conformance.ctap2_transport import CtapCmd, CtapError, SimulatorClient
from diagnostics.json_client import JsonSimulator
from diagnostics.model import Layer, name as _name, layer_of as _layer_of

WORKSPACE_ROOT = Path(__file__).resolve().parents[2]


def expect_success(client: SimulatorClient, cmd: int, payload, label: str):
    """Controle positivo: sem a falha injetada, o comando deve ter sucesso."""
    status, _ = client.send_cbor(cmd, payload)
    assert status == CtapError.SUCCESS, (
        f"[{label}] controle positivo QUEBROU: esperado SUCCESS(0x00), "
        f"obtido {status}({_name(status)}) â†’ {_layer_of(status)}. "
        f"A falha nÃ£o veio da injeÃ§Ã£o; o caminho feliz estÃ¡ comprometido."
    )


def expect_fault(client: SimulatorClient, cmd: int, payload, code: int, layer: Layer, label: str):
    """Injeta a falha e exige o cÃ³digo/camada exatos.

    Em caso de divergÃªncia, a mensagem aponta qual camada rejeitou de fato.
    """
    status, _ = client.send_cbor(cmd, payload)
    assert status == code, (
        f"[{label}] CAMADA ERRADA REJEITOU A FALHA: esperado {layer.value} "
        f"com cÃ³digo 0x{code:02X} ({_name(code)}); obtido 0x{status:02X} "
        f"({_name(status)}) â†’ {_layer_of(status)}."
    )


def sample_make_credential(rp_id="fault.example", alg=-7, user_id=b"fault_user"):
    client_data = b'{"type":"webauthn.create","challenge":"RkFVTFQ","origin":"https://fault.example"}'
    return {
        0x01: hashlib.sha256(client_data).digest(),
        0x02: {"id": rp_id, "name": "Fault Corp"},
        0x03: {"id": user_id, "name": "bob@fault.example", "displayName": "Bob"},
        0x04: [{"type": "public-key", "alg": alg}],
        0x05: [],
        0x07: {"rk": False, "uv": False, "up": True},
    }


def sample_get_assertion(rp_id="fault.example", client_data_hash=None):
    if client_data_hash is None:
        client_data_hash = hashlib.sha256(b"assertion").digest()
    return {
        0x01: rp_id,
        0x02: client_data_hash,
        0x05: {"up": True, "uv": False},
    }


# ---------------------------------------------------------------------------
# Camada 1 â€” FRAMING/TRANSPORTE
# ---------------------------------------------------------------------------


def test_framing_zero_length_frame_is_discarded_without_response():
    """Frame de comprimento zero Ã© descartado pelo framing SEM gerar status."""
    with SimulatorClient() as client:
        # InjeÃ§Ã£o: header declara total_len == 0 â†’ run_raw_cbor faz `continue`.
        client.send_frame(b"\x00\x00")

        # Nenhuma resposta deve ter sido produzida para o frame vazio: o
        # prÃ³ximo comando vÃ¡lido recebe A PRIMEIRA (e Ãºnica) resposta.
        expect_success(client, CtapCmd.GET_INFO, None, "framing/frame-vazio")


def test_framing_truncated_frame_never_produces_status_byte():
    """Frame truncado trava o read_exact: EOF sem qualquer byte de status."""
    with SimulatorClient() as client:
        # InjeÃ§Ã£o: promete 16 bytes de corpo mas envia apenas 4.
        client.send_frame(b"\x00\x10" + b"\x04\x00\x00\x00")
        client.close_stdin()

        assert client.wait_exited(timeout=5) is not None, (
            "[framing/truncado] simulador deveria encerrar ao atingir EOF "
            "no meio de um frame; ficou vivo."
        )
        with pytest.raises(EOFError):
            client._read_exact(1)
        # Nenhuma camada acima do framing chegou a rodar: nÃ£o existe status.


# ---------------------------------------------------------------------------
# Camada 2 â€” DESPACHO CTAP2
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("opcode", [0x10, 0x20, 0x3F, 0x50, 0x7D, 0xFE])
def test_dispatch_unknown_opcode_rejected_as_invalid_command(opcode):
    """Opcode fora da tabela Ã© rejeitado antes de qualquer decodificaÃ§Ã£o."""
    with SimulatorClient() as client:
        expect_fault(
            client,
            opcode,
            None,
            CtapError.INVALID_COMMAND,
            Layer.DISPATCH,
            f"dispatch/opcode-desconhecido-0x{opcode:02X}",
        )


def test_dispatch_precedes_codec_garbage_payload_still_invalid_command():
    """Payload invÃ¡lido em opcode desconhecido â†’ 0x01, nunca 0x12 do codec."""
    with SimulatorClient() as client:
        expect_fault(
            client,
            0x7D,
            b"\xff\xff\xff",  # bytes que o codec CBOR rejeitaria
            CtapError.INVALID_COMMAND,
            Layer.DISPATCH,
            "dispatch/precede-codec",
        )


# ---------------------------------------------------------------------------
# Camada 3 â€” CODEC CBOR
# ---------------------------------------------------------------------------


def test_codec_empty_payload_rejected_as_invalid_cbor():
    """MakeCredential sem payload algum falha na decodificaÃ§Ã£o, nÃ£o no handler."""
    with SimulatorClient() as client:
        expect_fault(
            client,
            CtapCmd.MAKE_CREDENTIAL,
            b"",
            CtapError.INVALID_CBOR,
            Layer.CODEC,
            "codec/payload-vazio",
        )


def test_codec_break_token_rejected_as_invalid_cbor():
    """Token indefinido CBOR (0xFF) sozinho Ã© payload malformado."""
    with SimulatorClient() as client:
        expect_fault(
            client,
            CtapCmd.MAKE_CREDENTIAL,
            b"\xff",
            CtapError.INVALID_CBOR,
            Layer.CODEC,
            "codec/break-token",
        )


def test_codec_truncated_cbor_rejected_as_invalid_cbor():
    """Request vÃ¡lida cortada ao meio nÃ£o decodifica (item incompleto)."""
    valid = cbor.encode(sample_make_credential())
    with SimulatorClient() as client:
        expect_fault(
            client,
            CtapCmd.MAKE_CREDENTIAL,
            valid[: len(valid) // 2],
            CtapError.INVALID_CBOR,
            Layer.CODEC,
            "codec/cbor-truncado",
        )


def test_codec_wrong_top_level_type_rejected_as_invalid_cbor():
    """Inteiro no lugar do mapa do request nÃ£o decodifica para a struct."""
    with SimulatorClient() as client:
        expect_fault(
            client,
            CtapCmd.MAKE_CREDENTIAL,
            cbor.encode(7),
            CtapError.INVALID_CBOR,
            Layer.CODEC,
            "codec/tipo-top-level-errado",
        )


def test_codec_missing_required_field_fails_at_codec_layer():
    """clientDataHash ausente â†’ 0x12: campo obrigatÃ³rio Ã© exigido na desserializaÃ§Ã£o.

    AtribuiÃ§Ã£o importante: a exigÃªncia de campos obrigatÃ³rios vive no CODEC
    (serde via decode_cbor), e nÃ£o na validaÃ§Ã£o semÃ¢ntica do handler.
    """
    incomplete = sample_make_credential()
    del incomplete[0x01]  # clientDataHash
    with SimulatorClient() as client:
        expect_fault(
            client,
            CtapCmd.MAKE_CREDENTIAL,
            incomplete,
            CtapError.INVALID_CBOR,
            Layer.CODEC,
            "codec/campo-obrigatorio-ausente",
        )


# ---------------------------------------------------------------------------
# Camada 4 â€” VALIDAÃ‡ÃƒO DE REQUEST
# ---------------------------------------------------------------------------


def test_validation_unsupported_algorithm_rejected_after_decode():
    """CBOR vÃ¡lido com algoritmo -999 passa codec e falha na validaÃ§Ã£o (0x26)."""
    with SimulatorClient() as client:
        expect_success(client, CtapCmd.MAKE_CREDENTIAL, sample_make_credential(alg=-7), "validacao/algoritmo-controle")
        expect_fault(
            client,
            CtapCmd.MAKE_CREDENTIAL,
            sample_make_credential(alg=-999),
            CtapError.UNSUPPORTED_ALGORITHM,
            Layer.VALIDATION,
            "validacao/algoritmo-nao-suportado",
        )


def test_validation_exclude_list_collision_rejected_with_0x19():
    """excludeList citando credencial existente do mesmo RP â†’ CredentialExists."""
    with SimulatorClient() as client:
        first_status, first = client.send_cbor(CtapCmd.MAKE_CREDENTIAL, sample_make_credential())
        assert first_status == CtapError.SUCCESS, (
            f"[validacao/exclude-list] controle positivo quebrou: {first_status}"
        )

        request = sample_make_credential()
        request[0x05] = [{"type": "public-key", "id": b"credencial-inexistente"}]
        # ID desconhecido nÃ£o colide: sucesso.
        expect_success(client, CtapCmd.MAKE_CREDENTIAL, request, "validacao/exclude-list-id-novo")

        # ColisÃ£o real exige a credencial criada no controle inicial.
        collision = sample_make_credential()
        stored_id = _extract_credential_id(first)
        if stored_id is not None:
            collision[0x05] = [{"type": "public-key", "id": stored_id}]
            expect_fault(
                client,
                CtapCmd.MAKE_CREDENTIAL,
                collision,
                0x19,
                Layer.VALIDATION,
                "validacao/exclude-list-colisao",
            )


def _extract_credential_id(make_credential_response) -> bytes | None:
    auth_data = make_credential_response.get(0x02)
    if not isinstance(auth_data, bytes) or len(auth_data) < 55:
        return None
    cred_len = int.from_bytes(auth_data[53:55], "big")
    return auth_data[55 : 55 + cred_len]


# ---------------------------------------------------------------------------
# Camada 5 â€” ESTADO DO AUTENTICADOR
# ---------------------------------------------------------------------------


def test_state_get_next_assertion_without_transaction_is_not_allowed():
    """GetNextAssertion sem transaÃ§Ã£o aberta por GetAssertion â†’ 0x30 NOT_ALLOWED.

    RegressÃ£o: antes retornava 0x05, que a tabela CTAP define como
    CTAP1_ERR_TIMEOUT â€” hosts reais interpretariam como timeout de transporte.
    """
    with SimulatorClient() as client:
        expect_success(client, CtapCmd.GET_INFO, None, "estado/gna-controle")
        expect_fault(
            client,
            CtapCmd.GET_NEXT_ASSERTION,
            None,
            CtapError.NOT_ALLOWED,
            Layer.STATE,
            "estado/gna-sem-transacao",
        )


def test_state_enumerate_rps_next_without_initial_is_not_allowed():
    """EnumerateRPsNext sem EnumerateRPsInitial prÃ©vio â†’ 0x30 NOT_ALLOWED."""
    with SimulatorClient() as client:
        expect_fault(
            client,
            CtapCmd.ENUMERATE_RPS_NEXT,
            None,
            CtapError.NOT_ALLOWED,
            Layer.STATE,
            "estado/rps-next-sem-initial",
        )


def test_state_enumerate_rps_initial_on_empty_storage_is_no_credentials():
    """EnumeraÃ§Ã£o inicial sem nenhum RP armazenado â†’ 0x2E."""
    with SimulatorClient() as client:
        expect_fault(
            client,
            CtapCmd.ENUMERATE_RPS_INITIAL,
            None,
            CtapError.NO_CREDENTIALS,
            Layer.STATE,
            "estado/rps-initial-storage-vazio",
        )


def test_state_get_assertion_unknown_rp_is_no_credentials_then_succeeds():
    """RP fantasma â†’ 0x2E; apÃ³s criar credencial no RP, o MESMO request passa."""
    ghost_rp = "ghost.example"
    with SimulatorClient() as client:
        expect_fault(
            client,
            CtapCmd.GET_ASSERTION,
            sample_get_assertion(rp_id=ghost_rp),
            CtapError.NO_CREDENTIALS,
            Layer.STATE,
            "estado/ga-rp-fantasma",
        )

        mc = sample_make_credential(rp_id=ghost_rp)
        expect_success(client, CtapCmd.MAKE_CREDENTIAL, mc, "estado/ga-pos-criacao")
        expect_success(client, CtapCmd.GET_ASSERTION, sample_get_assertion(rp_id=ghost_rp), "estado/ga-pos-criacao")


# ---------------------------------------------------------------------------
# RegressÃ£o de cÃ³digos no fio (interop com hosts reais)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cmd,label",
    [
        (CtapCmd.GET_NEXT_ASSERTION, "gna-sem-transacao"),
        (CtapCmd.ENUMERATE_RPS_NEXT, "rps-next-sem-initial"),
    ],
)
def test_wire_never_leaks_ctap1_transport_codes_for_state_errors(cmd, label):
    """Falhas de estado NUNCA usam 0x04/0x05 (INVALID_SEQ/TIMEOUT da CTAP1).

    Hosts reais (python-fido2, Chrome, libfido2) leem esses valores como
    erros da camada de transporte; a camada STATE deve sinalizar 0x30.
    """
    with SimulatorClient() as client:
        status, _ = client.send_cbor(cmd, None)
        assert status not in (0x04, 0x05), (
            f"[regressao/{label}] cÃ³digo 0x{status:02X} colide com a tabela "
            f"CTAP1 de transporte ({_name(status)}); esperado 0x30 NOT_ALLOWED."
        )
        expect_fault(client, cmd, None, CtapError.NOT_ALLOWED, Layer.STATE, f"regressao/{label}")


def test_paramless_commands_tolerate_trailing_payload():
    """Comandos sem parÃ¢metros ignoram payload extra (comportamento leniente).

    Documenta a semÃ¢ntica atual observada na sonda: GetInfo/Reset/Selection
    nÃ£o rejeitam bytes residuais. Se algum dia virar erro estrito, este teste
    deve ser atualizado junto â€” hoje hosts nÃ£o dependem disso.
    """
    with SimulatorClient() as client:
        for cmd in (CtapCmd.GET_INFO, CtapCmd.RESET, CtapCmd.SELECTION):
            status, _ = client.send_raw(cmd, b"\xff\xff")
            assert status == CtapError.SUCCESS, (
                f"[leniencia/opcode-0x{cmd:02X}] esperado SUCCESS apesar de "
                f"payload residual; obtido 0x{status:02X} ({_name(status)})."
            )


# ---------------------------------------------------------------------------
# Estado do PIN via operaÃ§Ã£o JSON de conveniÃªncia do simulador
# ---------------------------------------------------------------------------


SUB_GET_PIN_RETRIES = 0x01
SUB_GET_PIN_TOKEN = 0x05


def test_state_pin_token_without_set_pin_is_pin_not_set():
    """getPINToken sem PIN configurado â†’ 0x35 PinNotSet (camada de estado)."""
    sim = JsonSimulator()
    try:
        result = sim.client_pin(SUB_GET_PIN_TOKEN, pin=b"1234")
        assert result.get("ok") is False, (
            f"[estado/pin-nao-configurado] esperado falha, obtido: {result}"
        )
        assert result.get("code") == 0x35, (
            f"[estado/pin-nao-configurado] CAMADA ERRADA: esperado 0x35 "
            f"(PinNotSet, {Layer.STATE.value}); obtido "
            f"0x{result.get('code', 0):02X} ({_name(result.get('code', 0))})."
        )
    finally:
        sim.close()


def test_state_wrong_pin_decrements_retries_exactly_once():
    """PIN errado â†’ 0x31 E decremento persistente de retries (mutaÃ§Ã£o de estado)."""
    sim = JsonSimulator()
    try:
        setup = sim.client_pin(0x03, pin=b"1234")  # setPIN
        assert setup.get("ok") is True, f"[estado/pin-errado] setPIN falhou: {setup}"

        before = sim.client_pin(SUB_GET_PIN_RETRIES)
        assert before.get("retries") == 8, (
            f"[estado/pin-errado] controle positivo: retries inicial deveria ser 8: {before}"
        )

        wrong = sim.client_pin(SUB_GET_PIN_TOKEN, pin=b"9999")
        assert wrong.get("ok") is False and wrong.get("code") == 0x31, (
            f"[estado/pin-errado] CAMADA ERRADA: esperado 0x31 (PinInvalid, "
            f"{Layer.STATE.value}); obtido: {wrong}"
        )

        after = sim.client_pin(SUB_GET_PIN_RETRIES)
        assert after.get("retries") == before["retries"] - 1, (
            f"[estado/pin-errado] falha da camada STATE deveria decrementar "
            f"retries exatamente uma vez: antes={before}, depois={after}"
        )
    finally:
        sim.close()
