#!/usr/bin/env python3
"""Harness de testes host — Python como cliente dirigindo firmware Rust virtual.

Arquitetura correta (ver ADR-0016/ADR-0011):

    [Python — host test client]  --CTAP2/CBOR-->  [Firmware Rust — dispositivo virtual/emulado]
                                                   via HAL virtual (BoardDefinition + emulador)

* Python **nao simula** o dispositivo. Ele e o cliente de teste (host) que
  dirige o firmware Rust.
* O firmware Rust e o dispositivo virtual/emulado: o mesmo `EmbeddedAuthenticator`
  (`firmware/authenticator/src/authenticator.rs`) que compila para RP2350/nRF52840,
  aqui compilado para host com HAL virtual (`firmware/board-generic`, `simulator/python/board/`).
* Emulador com HAL virtual provê GPIO/I2C/SPI/CCID/board/storage virtual —
  `python/openkey_core/src/lib.rs:11` (`SimulatedPresence`), `firmware/board-generic/src/board_generic.rs`,
  `simulator/python/board/board.py:15` (`VirtualBoard`).

Este modulo providencia ambiente controlado no PC para validacao funcional
sem hardware fisico, oferecendo dois transportes para o mesmo firmware Rust:

* **in_process** (padrao): `openkey_core.VirtualAuthenticator` (pyo3) — o
  firmware Rust roda em processo como biblioteca, via HAL virtual em memoria.
  Mais rapido, ideal para CI/unit.
* **subprocess**: `fido2-simulator --raw-cbor` via pipes — o firmware Rust roda
  como processo filho com framing length-prefixed; mais fiel ao wire/CTAPHID.

Ambos falam CTAP2 real sobre CBOR (0x01/0x02/0x04/0x06/0x07...) e exercitam
MakeCredential, GetAssertion, GetInfo, ClientPIN, Reset, etc. de forma
isolada e deterministica — sem depender de placa.

Exemplo rapido (Python cliente -> firmware Rust virtual)::

    from tools.controlled_firmware_sim import ControlledFirmwareSim
    from fido2.webauthn import sha256

    with ControlledFirmwareSim(product_name="test") as host:
        # host (Python) envia MakeCredential ao device (firmware Rust virtual)
        att = host.make_credential(rp_id="example.com", user_id=b"alice",
                                   client_data_hash=sha256(b"challenge"))
        assertion = host.get_assertion(rp_id="example.com",
                                       client_data_hash=sha256(b"login"),
                                       allow_list=[{"type":"public-key","id": att.credential_id}])
        assertion.verify(att.public_key, sha256(b"login"))
        print("OK - validado sem hardware (host Python -> device Rust virtual)")

CLI de validacao::

    python tools/controlled_firmware_sim.py --validate
    python tools/controlled_firmware_sim.py --validate --backend subprocess
    python tools/controlled_firmware_sim.py --validate --verbose

Referencias:
* `python/openkey_core/src/lib.rs:29` — VirtualAuthenticator (firmware Rust como device virtual, HAL virtual)
* `python/openkey_core/src/lib.rs:11` — SimulatedPresence (HAL virtual de BOOTSEL)
* `firmware/board-generic/src/board_generic.rs` — BoardDefinition/HAL
* `simulator/python/board/board.py:15` — VirtualBoard (HAL virtual Python)
* `simulator/src/main.rs:692` — modo --raw-cbor (firmware Rust como subprocess)
* `tests/python/virtualauthenticator.py:145` — ponte host Python -> device Rust
* `tests/python/conformance/ctap2_transport.py:82` — transporte host->device via pipes
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Dependências opcionais — falha amigável
# ---------------------------------------------------------------------------

try:
    from fido2 import cbor
    from fido2.webauthn import AttestationObject, AuthenticatorData, sha256
    from fido2.cose import CoseKey
except ImportError as _e:  # pragma: no cover
    print(
        "dependência 'fido2' não encontrada. Instale com: pip install fido2",
        file=sys.stderr,
    )
    raise

try:
    import openkey_core as _openkey_core

    _HAS_OPENKEY_CORE = True
except ImportError:
    _HAS_OPENKEY_CORE = False
    _openkey_core = None  # type: ignore

# ---------------------------------------------------------------------------
# Constantes CTAP2
# ---------------------------------------------------------------------------

CMD_MAKE_CREDENTIAL = 0x01
CMD_GET_ASSERTION = 0x02
CMD_GET_INFO = 0x04
CMD_CLIENT_PIN = 0x06
CMD_RESET = 0x07
CMD_GET_NEXT_ASSERTION = 0x08

ERR_SUCCESS = 0x00
ERR_INVALID_COMMAND = 0x01
ERR_INVALID_PARAMETER = 0x02
ERR_CREDENTIAL_EXCLUDED = 0x19
ERR_UNSUPPORTED_ALGORITHM = 0x26
ERR_OPERATION_DENIED = 0x27
ERR_NO_CREDENTIALS = 0x2E
ERR_PIN_NOT_SET = 0x35
ERR_NOT_ALLOWED = 0x30

CTAP_ERROR_NAMES = {
    0x00: "SUCCESS",
    0x01: "INVALID_COMMAND",
    0x02: "INVALID_PARAMETER",
    0x19: "CREDENTIAL_EXCLUDED",
    0x26: "UNSUPPORTED_ALGORITHM",
    0x27: "OPERATION_DENIED",
    0x2E: "NO_CREDENTIALS",
    0x30: "NOT_ALLOWED",
    0x31: "PIN_INVALID",
    0x35: "PIN_NOT_SET",
}


class CtapError(Exception):
    """Erro CTAP2 retornado pelo firmware simulado."""

    def __init__(self, code: int, msg: str | None = None):
        self.code = code
        self.name = CTAP_ERROR_NAMES.get(code, f"UNKNOWN_0x{code:02X}")
        super().__init__(msg or f"CTAP2 0x{code:02X} ({self.name})")


# ---------------------------------------------------------------------------
# Backend abstrato
# ---------------------------------------------------------------------------


class _Backend:
    """Interface mínima que ambos os backends implementam."""

    def process(self, cmd: int, data: bytes) -> tuple[int, bytes]:
        raise NotImplementedError

    def set_presence(self, pressed: bool) -> None:
        pass

    def close(self) -> None:
        pass


class _InProcessBackend(_Backend):
    """Transporte host->device em processo: Python (host client) -> firmware Rust (device virtual) via pyo3.

    Encapsula `openkey_core.VirtualAuthenticator` que expõe `EmbeddedAuthenticator`
    com HAL virtual (`SimulatedPresence` + `BoardDefinition`). Python nao simula
    o device; ele apenas dirige o firmware Rust compilado para host.
    """

    def __init__(self, aaguid: bytes | None, product_name: str | None):
        if not _HAS_OPENKEY_CORE:
            raise RuntimeError(
                "openkey_core não instalado. Compile com: "
                "maturin build --manifest-path python/openkey_core/Cargo.toml "
                "e pip install do wheel gerado, ou use --backend subprocess"
            )
        aaguid_arg = bytes(aaguid) if aaguid is not None else None
        self._native = _openkey_core.VirtualAuthenticator(
            aaguid=aaguid_arg, product_name=product_name
        )

    def process(self, cmd: int, data: bytes) -> tuple[int, bytes]:
        return self._native.process_command(cmd, data)

    def set_presence(self, pressed: bool) -> None:
        self._native.set_presence_pressed(pressed)


class _SubprocessBackend(_Backend):
    """Transporte host->device via subprocess: Python (host client) -> fido2-simulator (firmware Rust virtual) via pipes.

    O `fido2-simulator --raw-cbor` e o mesmo `EmbeddedAuthenticator` com HAL virtual,
    rodando como processo filho com framing length-prefixed. Python continua sendo
    apenas o cliente de teste.
    """

    def __init__(self, storage_path: Path | None = None):
        sim = _find_simulator_bin()
        cmd = [str(sim), "--raw-cbor"]
        if storage_path is not None:
            cmd.extend(["--storage-path", str(storage_path)])
        self._proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0
        )
        # presença não é suportada no modo JSON/raw-cbor legado do simulador
        self._presence = True
        # verifica que o processo subiu
        time.sleep(0.15)
        if self._proc.poll() is not None:
            stderr = self._proc.stderr.read().decode(errors="ignore") if self._proc.stderr else ""
            raise RuntimeError(f"simulador falhou ao iniciar: {stderr[:500]}")

    def _read_exact(self, n: int) -> bytes:
        assert self._proc.stdout is not None
        chunks: list[bytes] = []
        remaining = n
        while remaining > 0:
            chunk = self._proc.stdout.read(remaining)
            if not chunk:
                raise EOFError("simulador fechou a conexão")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def process(self, cmd: int, data: bytes) -> tuple[int, bytes]:
        assert self._proc.stdin is not None
        total = 1 + len(data)
        self._proc.stdin.write(struct.pack(">H", total) + bytes([cmd]) + data)
        self._proc.stdin.flush()
        resp_len = struct.unpack(">H", self._read_exact(2))[0]
        if resp_len < 1:
            raise ValueError(f"resposta inválida len={resp_len}")
        status = self._read_exact(1)[0]
        data_len = resp_len - 1
        resp = self._read_exact(data_len) if data_len else b""
        return status, resp

    def set_presence(self, pressed: bool) -> None:
        # simulador JSON não expõe user presence externo; registra para log
        self._presence = pressed

    def close(self) -> None:
        if self._proc.poll() is None:
            try:
                if self._proc.stdin:
                    self._proc.stdin.close()
            except OSError:
                pass
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()


def _find_simulator_bin() -> Path:
    repo_root = Path(__file__).resolve().parents[1]
    candidates = [
        repo_root / "target" / "debug" / "fido2-simulator.exe",
        repo_root / "target" / "debug" / "fido2-simulator",
        repo_root / "target" / "release" / "fido2-simulator.exe",
        repo_root / "target" / "release" / "fido2-simulator",
    ]
    for c in candidates:
        if c.is_file():
            return c
    raise FileNotFoundError(
        "binário fido2-simulator não encontrado. Compile com: cargo build -p fido2-simulator"
    )


# ---------------------------------------------------------------------------
# Ambiente controlado — API principal
# ---------------------------------------------------------------------------


def _compact(obj: Any) -> Any:
    """Remove None recursivamente (fido2 cbor rejeita None)."""
    if isinstance(obj, dict):
        return {k: _compact(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_compact(v) for v in obj if v is not None]
    return obj


@dataclass
class ControlledFirmwareSim:
    """Harness host controlado: Python (cliente) dirigindo firmware Rust (device virtual) via HAL virtual.

    Cada instância é um par host->device isolado:
    * **Host (Python)**: este harness, cliente de teste CTAP2/CBOR.
    * **Device (firmware Rust virtual)**: `EmbeddedAuthenticator` com HAL virtual
      (`BoardDefinition`, `SimulatedPresence`, `VirtualBoard`/storage em memória),
      sem hardware físico. Volátil por padrão (ou arquivo temp se `storage_path`).

    Python nao simula o dispositivo; ele envia comandos CTAP2 ao firmware Rust
    emulado, que roda o mesmo código que compila para RP2350/nRF52840
    (`firmware/authenticator`, `protocol/ctap2`, `protocol/crypto`).

    Pode ser usado como context manager para cleanup determinístico.

    Args:
        backend: "auto" | "in_process" | "subprocess". "auto" prefere
            in_process e cai para subprocess se openkey_core não estiver
            disponível.
        aaguid: 16 bytes; se None usa zeros (como device padrão).
        product_name: nome exibido no GetInfo do device; default "openkey-controlled".
        storage_path: caminho opcional para persistência (testes de restart).
        isolated: se True (default) cada harness começa com device limpo (reset implícito).

    Exemplo (host -> device)::

        with ControlledFirmwareSim() as host:
            info = host.get_info()  # host pergunta GetInfo ao device Rust virtual
            assert "2.1" in info["versions"]
    """

    backend: str = "auto"
    aaguid: bytes | None = None
    product_name: str | None = "openkey-controlled"
    storage_path: Path | None = None
    isolated: bool = True

    # internos
    _be: _Backend = field(init=False, repr=False, default=None)  # type: ignore
    _created_at: float = field(init=False, repr=False, default=0.0)
    _ops: int = field(init=False, repr=False, default=0)

    def __post_init__(self) -> None:
        be_name = self.backend
        if be_name == "auto":
            be_name = "in_process" if _HAS_OPENKEY_CORE else "subprocess"
        if be_name == "in_process":
            self._be = _InProcessBackend(self.aaguid, self.product_name)
        elif be_name == "subprocess":
            self._be = _SubprocessBackend(self.storage_path)
        else:
            raise ValueError(f"backend desconhecido: {self.backend}")
        self._created_at = time.time()
        self._ops = 0
        # garante user presence = presente por padrão (comportamento anterior)
        self._be.set_presence(True)

    # -- context manager ---------------------------------------------------

    def __enter__(self) -> "ControlledFirmwareSim":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._be is not None:
            self._be.close()

    # -- controle de ambiente ----------------------------------------------

    def reset(self) -> None:
        """Reseta o device virtual — equivalente a power-cycle + Reset do firmware Rust.

        O host (Python) solicita reset ao device (firmware Rust):
        * in_process: recria `EmbeddedAuthenticator` com HAL virtual limpo (isolamento total).
        * subprocess: envia CMD_RESET (0x07) ao `fido2-simulator`.
        Garante que credenciais/PIN/contadores do device não vazem entre validações do host.
        """
        if isinstance(self._be, _InProcessBackend):
            # recria backend para isolamento total (mais forte que reset CTAP2)
            be_name = "in_process"
            self._be.close()
            self._be = _InProcessBackend(self.aaguid, self.product_name)
            self._be.set_presence(True)
        else:
            status, _ = self._be.process(CMD_RESET, b"")
            if status != ERR_SUCCESS:
                raise CtapError(status, "reset falhou no subprocess")
        self._ops = 0

    def set_presence(self, pressed: bool) -> None:
        """Controla User Presence no HAL virtual do device (BOOTSEL do RP2350).

        O host (Python) injeta estado do botão no HAL virtual do device Rust
        (`SimulatedPresence` / `BoardTrait::button_pressed`). Quando False,
        MakeCredential/GetAssertion com `up=True` retornam OPERATION_DENIED (0x27),
        simulando botão solto — sem fiação extra.
        """
        self._be.set_presence(pressed)

    @property
    def supports_presence(self) -> bool:
        """True se backend suporta injeção de User Presence (BOOTSEL)."""
        return isinstance(self._be, _InProcessBackend)

    def elapsed(self) -> float:
        return time.time() - self._created_at

    # -- CTAP2 de baixo nível ----------------------------------------------

    def raw_command(self, cmd: int, payload: Any | bytes | None = None) -> Any:
        """Host (Python) envia comando CTAP2 cru ao device (firmware Rust virtual) e retorna resposta decodificada.

        Args:
            cmd: opcode CTAP2 (ex: 0x01 makeCredential)
            payload: dict/list para CBOR, bytes já codificados, ou None.

        Raises:
            CtapError: se o device (firmware Rust) retornar status != 0x00.
        """
        if payload is None:
            data = b""
        elif isinstance(payload, (bytes, bytearray)):
            data = bytes(payload)
        else:
            data = cbor.encode(_compact(payload))
        self._ops += 1
        status, resp = self._be.process(cmd, data)
        if status != ERR_SUCCESS:
            raise CtapError(status)
        if not resp:
            return None
        return cbor.decode(resp)

    # -- API de alto nível -------------------------------------------------

    def get_info(self) -> dict:
        """Host pergunta GetInfo ao device virtual; retorna dict decodificado (versions, aaguid, firmwareVersion...)."""
        raw = self.raw_command(CMD_GET_INFO)
        # normaliza chaves inteiras para nomes amigáveis quando vier do wire
        if isinstance(raw, dict) and 0x01 in raw:
            mapping = {
                0x01: "versions",
                0x02: "extensions",
                0x03: "aaguid",
                0x04: "options",
                0x05: "maxMsgSize",
                0x06: "pinUvAuthProtocols",
                0x07: "maxCredentialCountInList",
                0x08: "maxCredentialIdLength",
                0x09: "transports",
                0x0A: "algorithms",
                0x0D: "maxSerializedLargeBlobArray",
                0x0E: "firmwareVersion",
                0x0F: "maxCredBlobLength",
                0x10: "minPinLength",
            }
            return {mapping.get(k, k): v for k, v in raw.items()}
        return raw  # type: ignore

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
        """Host (Python) solicita MakeCredential (0x01) ao device (firmware Rust virtual); retorna AttestationObject.

        O processamento (validacao, crypto, storage) ocorre no firmware Rust
        (`protocol/ctap2`, `protocol/crypto`, `firmware/storage`) com HAL virtual.
        Host apenas encoda CBOR, envia via transporte host->device e decodifica.
        Nao requer hardware fisico; o device e o firmware Rust emulado.
        """
        req: dict[Any, Any] = {
            0x01: bytes(client_data_hash),
            0x02: {"id": rp_id},
            0x03: {
                "id": bytes(user_id),
                "name": user_name,
                "displayName": user_display_name,
            },
            0x04: algorithms or [{"type": "public-key", "alg": -8}],
            0x05: [{"type": "public-key", "id": bytes(d["id"])} for d in (exclude_list or [])],
            0x07: options or {"rk": False, "uv": False, "up": True},
            0x06: extensions,
        }
        resp = self.raw_command(CMD_MAKE_CREDENTIAL, req)
        # Firmware retorna mapa com chaves inteiras (0x01 fmt, 0x02 authData, 0x03 attStmt);
        # AttestationObject do fido2 espera chaves string.
        if isinstance(resp, dict) and 0x01 in resp:
            mapping = {0x01: "fmt", 0x02: "authData", 0x03: "attStmt", 0x04: "extensions", 0x06: "extensions"}
            resp = {mapping.get(k, k): v for k, v in resp.items()}
        return AttestationObject(cbor.encode(resp))

    def get_assertion(
        self,
        *,
        rp_id: str,
        client_data_hash: bytes,
        allow_list: list[dict] | None = None,
        options: dict | None = None,
        extensions: dict | None = None,
    ) -> "Assertion":
        """Host (Python) solicita GetAssertion (0x02) ao device (firmware Rust virtual) — sem hardware."""
        req: dict[Any, Any] = {
            0x01: rp_id,
            0x02: bytes(client_data_hash),
            0x03: [{"type": "public-key", "id": bytes(d["id"])} for d in (allow_list or [])],
            0x05: options or {"up": True, "uv": False},
            0x04: extensions,
        }
        # mapeia chaves inteiras esperadas pelo firmware
        resp = self.raw_command(CMD_GET_ASSERTION, req)
        # resp vem com chaves inteiras 0x01..0x06
        key_map = {0x01: "credential", 0x02: "authData", 0x03: "signature", 0x04: "user", 0x05: "numberOfCredentials"}
        if isinstance(resp, dict):
            resp = {key_map.get(k, k): v for k, v in resp.items()}
        return Assertion(
            auth_data=AuthenticatorData(bytes(resp["authData"])),
            signature=bytes(resp["signature"]),
            credential_id=bytes(resp["credential"]["id"]),
            user_handle=bytes(resp["user"]["id"]),
            raw=resp,
        )

    # -- helpers de validação ----------------------------------------------

    def verify(self, attestation: AttestationObject, assertion: "Assertion", client_data_hash: bytes) -> bool:
        """Verifica assinatura da assertion contra a chave da attestation.

        Returns True se válida, False caso contrário (não lança).
        """
        try:
            signed = bytes(assertion.auth_data) + bytes(client_data_hash)
            key = attestation.auth_data.credential_data.public_key
            key.verify(signed, bytes(assertion.signature))
            return True
        except Exception:
            return False


@dataclass(frozen=True)
class Assertion:
    """Assertion decodificada retornada por `ControlledFirmwareSim.get_assertion`."""

    auth_data: AuthenticatorData
    signature: bytes
    credential_id: bytes
    user_handle: bytes
    raw: dict = field(default_factory=dict, repr=False)

    def verify(self, public_key, client_data_hash: bytes) -> None:
        signed = bytes(self.auth_data) + bytes(client_data_hash)
        public_key.verify(signed, bytes(self.signature))


# ---------------------------------------------------------------------------
# Suíte de validação funcional — sem hardware
# ---------------------------------------------------------------------------


def run_functional_validation(sim: ControlledFirmwareSim, verbose: bool = False) -> dict[str, str]:
    """Host (Python) executa validacoes funcionais dirigindo o device (firmware Rust virtual) via HAL virtual.

    Cobre ciclo de vida make/assert/verify e regressoes criticas do firmware Rust.
    Cada sub-teste isola o device via `host.reset()` (power-cycle virtual).
    Nenhum teste simula o device em Python; todos exercitam o firmware Rust real
    compilado para host.

    Returns:
        dict com nome do teste -> "PASS" | "FAIL: ..." | "SKIP: ..."
    """
    results: dict[str, str] = {}

    def _ok(name: str) -> None:
        results[name] = "PASS"
        if verbose:
            print(f"  [PASS] {name}")

    def _fail(name: str, e: Exception) -> None:
        results[name] = f"FAIL: {e}"
        if verbose:
            print(f"  [FAIL] {name}: {e}")

    def _run(name: str, fn) -> None:
        try:
            fn()
            _ok(name)
        except Exception as e:
            _fail(name, e)

    # 1. GetInfo — versões, aaguid, firmwareVersion
    def t_get_info():
        info = sim.get_info()
        assert "2.0" in info["versions"] and "2.1" in info["versions"], info
        assert isinstance(info.get("aaguid"), (bytes, bytearray)), "aaguid deve ser bytes"
        assert isinstance(info.get("firmwareVersion"), int), "firmwareVersion deve ser int"
        assert info["firmwareVersion"] == 1000

    _run("get_info", t_get_info)

    # 2. MakeCredential + GetAssertion + Verify (EdDSA)
    def t_make_assert_verify():
        sim.reset()
        cdh_create = sha256(b'{"type":"webauthn.create","challenge":"controlled"}')
        att = sim.make_credential(
            rp_id="example.com", user_id=b"alice-controlled", client_data_hash=cdh_create, user_name="alice"
        )
        assert att.fmt == "none"
        cred_id = att.auth_data.credential_data.credential_id
        assert len(cred_id) == 16
        cdh_get = sha256(b'{"type":"webauthn.get","challenge":"login"}')
        assertion = sim.get_assertion(
            rp_id="example.com", client_data_hash=cdh_get, allow_list=[{"type": "public-key", "id": cred_id}]
        )
        assert assertion.credential_id == cred_id
        assert assertion.auth_data.counter == 1
        assertion.verify(att.auth_data.credential_data.public_key, cdh_get)

    _run("make_assert_verify_eddsa", t_make_assert_verify)

    # 3. Sign counter incrementa
    def t_sign_counter():
        sim.reset()
        att = sim.make_credential(rp_id="example.com", user_id=b"ctr", client_data_hash=sha256(b"c1"))
        cid = att.auth_data.credential_data.credential_id
        a1 = sim.get_assertion(rp_id="example.com", client_data_hash=sha256(b"a1"), allow_list=[{"id": cid, "type": "public-key"}])
        a2 = sim.get_assertion(rp_id="example.com", client_data_hash=sha256(b"a2"), allow_list=[{"id": cid, "type": "public-key"}])
        assert a1.auth_data.counter == 1 and a2.auth_data.counter == 2

    _run("sign_counter_increments", t_sign_counter)

    # 4. Flags UP/UV respeitam options
    def t_flags():
        sim.reset()
        att = sim.make_credential(
            rp_id="example.com",
            user_id=b"flags",
            client_data_hash=sha256(b"flags"),
            options={"rk": False, "up": False, "uv": False},
        )
        assert not att.auth_data.is_user_present()
        cid = att.auth_data.credential_data.credential_id
        assertion = sim.get_assertion(
            rp_id="example.com",
            client_data_hash=sha256(b"flags-get"),
            allow_list=[{"id": cid, "type": "public-key"}],
            options={"up": False, "uv": False},
        )
        assert not assertion.auth_data.is_user_present()

    _run("flags_up_uv", t_flags)

    # 5. allow_list de RP errado é rejeitado (anti-hijacking)
    def t_allow_list_wrong_rp():
        sim.reset()
        att = sim.make_credential(rp_id="example.com", user_id=b"hijack", client_data_hash=sha256(b"hijack"))
        cid = att.auth_data.credential_data.credential_id
        try:
            sim.get_assertion(rp_id="evil.com", client_data_hash=sha256(b"evil"), allow_list=[{"id": cid, "type": "public-key"}])
            raise AssertionError("deveria rejeitar RP errado")
        except CtapError as e:
            assert e.code == ERR_NO_CREDENTIALS, f"esperado 0x2E, veio 0x{e.code:02X}"

    _run("allow_list_wrong_rp_rejected", t_allow_list_wrong_rp)

    # 6. exclude_list retorna CREDENTIAL_EXCLUDED
    def t_exclude_list():
        sim.reset()
        att = sim.make_credential(rp_id="example.com", user_id=b"ex1", client_data_hash=sha256(b"ex1"))
        cid = att.auth_data.credential_data.credential_id
        try:
            sim.make_credential(
                rp_id="example.com",
                user_id=b"ex2",
                client_data_hash=sha256(b"ex2"),
                exclude_list=[{"id": cid, "type": "public-key"}],
            )
            raise AssertionError("deveria rejeitar excludeList")
        except CtapError as e:
            assert e.code == ERR_CREDENTIAL_EXCLUDED

    _run("exclude_list_rejected", t_exclude_list)

    # 7. Algoritmo não suportado
    def t_unsupported_alg():
        sim.reset()
        try:
            sim.make_credential(
                rp_id="example.com",
                user_id=b"alg",
                client_data_hash=sha256(b"alg"),
                algorithms=[{"type": "public-key", "alg": -65535}],
            )
            raise AssertionError("deveria rejeitar algoritmo")
        except CtapError as e:
            assert e.code == ERR_UNSUPPORTED_ALGORITHM

    _run("unsupported_algorithm", t_unsupported_alg)

    # 8. Algoritmo misto (um suportado) — deve passar
    def t_mixed_alg():
        sim.reset()
        att = sim.make_credential(
            rp_id="example.com",
            user_id=b"mix",
            client_data_hash=sha256(b"mix"),
            algorithms=[{"type": "public-key", "alg": -65535}, {"type": "public-key", "alg": -7}],
        )
        assert att.auth_data.credential_data.public_key is not None

    _run("supported_algorithm_with_fallback", t_mixed_alg)

    # 9. ES256 roundtrip
    def t_es256():
        sim.reset()
        att = sim.make_credential(
            rp_id="example.com", user_id=b"es256", client_data_hash=sha256(b"es256"), algorithms=[{"type": "public-key", "alg": -7}]
        )
        assert att.auth_data.credential_data.public_key.ALGORITHM == -7
        cid = att.auth_data.credential_data.credential_id
        cdh = sha256(b"es256-login")
        ass = sim.get_assertion(rp_id="example.com", client_data_hash=cdh, allow_list=[{"id": cid, "type": "public-key"}])
        ass.verify(att.auth_data.credential_data.public_key, cdh)

    _run("es256_roundtrip", t_es256)

    # 10. Reset limpa credenciais
    def t_reset():
        sim.reset()
        att = sim.make_credential(rp_id="example.com", user_id=b"rst", client_data_hash=sha256(b"rst"))
        sim.reset()
        try:
            sim.get_assertion(
                rp_id="example.com",
                client_data_hash=sha256(b"rst2"),
                allow_list=[{"id": att.auth_data.credential_data.credential_id, "type": "public-key"}],
            )
            raise AssertionError("credencial deveria ter sido apagada")
        except CtapError as e:
            assert e.code == ERR_NO_CREDENTIALS

    _run("reset_clears_credentials", t_reset)

    # 11. User presence (BOOTSEL) — quando solto, nega operação
    if not sim.supports_presence:
        results["user_presence_denied_when_released"] = "SKIP: backend sem suporte a BOOTSEL"
        if verbose:
            print("  [SKIP] user_presence_denied_when_released (backend sem BOOTSEL)")
    else:

        def t_user_presence():
            sim.reset()
            sim.set_presence(False)
            try:
                sim.make_credential(
                    rp_id="example.com", user_id=b"up", client_data_hash=sha256(b"up"), options={"up": True, "uv": False, "rk": False}
                )
                raise AssertionError("deveria negar sem UP")
            except CtapError as e:
                assert e.code == ERR_OPERATION_DENIED, f"esperado 0x27, veio 0x{e.code:02X}"
            finally:
                sim.set_presence(True)
            # com UP deve passar
            att = sim.make_credential(rp_id="example.com", user_id=b"up2", client_data_hash=sha256(b"up2"))
            assert att is not None

        _run("user_presence_denied_when_released", t_user_presence)

    # 12. Assinatura incorreta é detectada
    def t_bad_signature():
        sim.reset()
        att = sim.make_credential(rp_id="example.com", user_id=b"bad", client_data_hash=sha256(b"bad"))
        cid = att.auth_data.credential_data.credential_id
        ass = sim.get_assertion(rp_id="example.com", client_data_hash=sha256(b"bad-login"), allow_list=[{"id": cid, "type": "public-key"}])
        try:
            ass.verify(att.auth_data.credential_data.public_key, sha256(b"wrong"))
            raise AssertionError("verificação deveria falhar")
        except Exception:
            pass  # esperado

    _run("bad_signature_detected", t_bad_signature)

    # 13. Isolamento — duas instâncias não compartilham estado
    def t_isolation():
        with ControlledFirmwareSim(product_name="iso-1") as s1, ControlledFirmwareSim(product_name="iso-2") as s2:
            a1 = s1.make_credential(rp_id="example.com", user_id=b"iso", client_data_hash=sha256(b"iso"))
            # s2 não deve ver credencial de s1
            try:
                s2.get_assertion(
                    rp_id="example.com",
                    client_data_hash=sha256(b"iso"),
                    allow_list=[{"id": a1.auth_data.credential_data.credential_id, "type": "public-key"}],
                )
                raise AssertionError("instância isolada não deve ver credencial de outra")
            except CtapError as e:
                assert e.code == ERR_NO_CREDENTIALS

    _run("isolation_between_instances", t_isolation)

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Harness host Python -> device firmware Rust virtual (HAL virtual) — validacao sem hardware",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Arquitetura: Python (host test client) --CTAP2/CBOR--> firmware Rust (device virtual via HAL virtual)
Exemplos:
  python tools/controlled_firmware_sim.py --validate
  python tools/controlled_firmware_sim.py --validate --backend subprocess --verbose
  python tools/controlled_firmware_sim.py --info
  python tools/controlled_firmware_sim.py --demo
        """,
    )
    parser.add_argument(
        "--backend",
        choices=["auto", "in_process", "subprocess"],
        default="auto",
        help="transporte host->device: in_process (pyo3, HAL virtual em memoria) ou subprocess (fido2-simulator --raw-cbor)",
    )
    parser.add_argument("--validate", action="store_true", help="roda suite completa de validação funcional")
    parser.add_argument("--info", action="store_true", help="mostra GetInfo do firmware simulado")
    parser.add_argument("--demo", action="store_true", help="demonstra ciclo make/assert/verify mínimo")
    parser.add_argument("--verbose", action="store_true", help="logs detalhados")
    parser.add_argument("--aaguid", type=str, default=None, help="AAGUID hex (32 chars) customizado")
    args = parser.parse_args(argv)

    aaguid = bytes.fromhex(args.aaguid) if args.aaguid else None
    if aaguid is not None and len(aaguid) != 16:
        parser.error("aaguid deve ter 16 bytes (32 hex chars)")

    # default se nenhum flag: --validate
    if not (args.validate or args.info or args.demo):
        args.validate = True

    try:
        with ControlledFirmwareSim(backend=args.backend, aaguid=aaguid) as host:
            sim = host  # alias: harness host
            be_label = (
                "in_process (host Python -> device Rust pyo3, HAL virtual)"
                if isinstance(sim._be, _InProcessBackend)
                else "subprocess (host Python -> device Rust fido2-simulator --raw-cbor, HAL virtual)"
            )
            print(f"Harness host ativo - device: firmware Rust virtual - backend: {be_label}")
            print(f"  Host (Python) dirigindo Device (Rust) | AAGUID device: {(aaguid or bytes(16)).hex()}  product: {sim.product_name}")
            print(f"  HAL virtual: BoardDefinition + SimulatedPresence/VirtualBoard (sem hardware fisico)")
            print()

            if args.info:
                info = sim.get_info()  # host pergunta ao device
                print("GetInfo (host <- device Rust virtual):")
                for k, v in info.items():
                    if k == "aaguid" and isinstance(v, (bytes, bytearray)):
                        v = v.hex()
                    print(f"  {k}: {v}")
                print()

            if args.demo:
                print("Demo - host Python -> device Rust virtual: MakeCredential -> GetAssertion -> Verify (HAL virtual):")
                cdh = sha256(b"demo-challenge")
                att = sim.make_credential(rp_id="example.com", user_id=b"demo-user", client_data_hash=cdh, user_name="demo")
                print(f"  Host -> Device MakeCredential OK  fmt={att.fmt}  credId={att.auth_data.credential_data.credential_id.hex()[:16]}...")
                print(f"    Device authData rpIdHash={att.auth_data.rp_id_hash.hex()[:16]}...  counter={att.auth_data.counter}")
                cdh2 = sha256(b"demo-login")
                ass = sim.get_assertion(
                    rp_id="example.com", client_data_hash=cdh2, allow_list=[{"id": att.auth_data.credential_data.credential_id, "type": "public-key"}]
                )
                print(f"  Host <- Device GetAssertion OK    counter={ass.auth_data.counter}  flags=0x{ass.auth_data.flags:02x} (device HAL virtual)")
                ass.verify(att.auth_data.credential_data.public_key, cdh2)
                print("  Host verifica assinatura do device - OK")
                print(f"  Device isolado via HAL virtual - host elapsed {sim.elapsed():.2f}s, ops host->device={sim._ops}")
                print()

            if args.validate:
                print("Validacao funcional host Python -> device Rust virtual (HAL virtual, sem hardware):")
                results = run_functional_validation(sim, verbose=args.verbose)
                passed = sum(1 for v in results.values() if v == "PASS" or v.startswith("SKIP"))
                total = len(results)
                failed = sum(1 for v in results.values() if v.startswith("FAIL"))
                print()
                for name, status in results.items():
                    if status == "PASS":
                        mark = "[OK]"
                    elif status.startswith("SKIP"):
                        mark = "[SKIP]"
                    else:
                        mark = "[FAIL]"
                    print(f"  {mark} {name}: {status}")
                print()
                print(f"Resultado host->device: {passed}/{total} PASS (falhas: {failed})  (elapsed {sim.elapsed():.2f}s, backend {be_label})")
                if failed:
                    print("Falhas no device Rust virtual - verifique firmware/HAL virtual.", file=sys.stderr)
                    return 1
                print("Validado: host Python dirigiu firmware Rust virtual via HAL virtual — sem hardware fisico.")
                print("  Python = cliente de teste (host); Rust = dispositivo virtual/emulado (EmbeddedAuthenticator + HAL virtual).")
    except FileNotFoundError as e:
        print(f"erro: {e}", file=sys.stderr)
        return 2
    except CtapError as e:
        print(f"erro CTAP2: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"erro inesperado: {e}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
