"""Transporte binário para o simulador openkey-fido2 em modo `--raw-cbor`."""

from __future__ import annotations

import os
import struct
import subprocess
from pathlib import Path
from typing import Any

from fido2 import cbor


class CtapCmd:
    """Opcodes padrão CTAP 2.1."""

    MAKE_CREDENTIAL = 0x01
    GET_ASSERTION = 0x02
    GET_INFO = 0x04
    CLIENT_PIN = 0x06
    RESET = 0x07
    GET_NEXT_ASSERTION = 0x08
    BIO_ENROLL = 0x09
    CRED_MGMT = 0x0A
    SELECTION = 0x0B
    LARGE_BLOBS = 0x0C
    AUTHNR_CONFIG = 0x0D
    ENUMERATE_RPS_INITIAL = 0x3B
    ENUMERATE_RPS_NEXT = 0x3C


class CtapError:
    """Códigos de erro CTAP2."""

    SUCCESS = 0x00
    INVALID_COMMAND = 0x01
    INVALID_PARAMETER = 0x02
    INVALID_LENGTH = 0x03
    INVALID_SEQUENCE = 0x04
    INVALID_CBOR = 0x12
    TIMEOUT = 0x05
    # CTAP2_ERR_NOT_ALLOWED: comando não permitido no estado atual
    # (ex.: GetNextAssertion sem GetAssertion prévio).
    INVALID_STATE = NOT_ALLOWED = 0x30
    CHANNEL_BUSY = 0x06
    CREDENTIAL_EXCLUDED = 0x19
    UNSUPPORTED_ALGORITHM = 0x26
    OPERATION_DENIED = 0x27
    KEY_NOT_SUPPORTED = 0x28
    NO_CREDENTIALS = 0x2E
    USER_NOT_ACTIONED = 0x23
    PIN_INVALID = 0x31
    PIN_INVALID_RETRIES = 0x32
    PIN_REQUIRED = 0x36
    PIN_POLICY_VIOLATION = 0x37
    PIN_BLOCKED = 0x32
    PIN_AUTH_INVALID = 0x33
    PIN_AUTH_BLOCKED = 0x34
    PIN_NOT_SET = 0x35
    REQUEST_TOO_LARGE = 0x39
    LARGE_BLOB_STORAGE_FULL = 0x18


def get_simulator_path() -> Path:
    """Localiza o binário do simulador compilado."""
    repo_root = Path(__file__).resolve().parents[3]
    # Windows vs Unix
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
        f"Binário fido2-simulator não encontrado. Execute 'cargo build -p fido2-simulator'."
    )


class SimulatorClient:
    """Cliente binário CTAP2 que interage com o simulador via pipes stdio."""

    def __init__(self, storage_path: Path | None = None) -> None:
        sim_path = get_simulator_path()
        cmd = [str(sim_path), "--raw-cbor"]
        if storage_path is not None:
            cmd.extend(["--storage-path", str(storage_path)])

        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )

    def close(self) -> None:
        """Encerra o processo do simulador.

        Garante (de forma portátil) que o filho terminou e que os pipes
        do pai foram liberados antes de retornar, de modo que no Windows
        nenhum handle sobre o arquivo de storage permaneça aberto quando
        o `TemporaryDirectory` do teste for removido.
        """
        proc = self._proc
        if proc.poll() is None:
            if proc.stdin:
                try:
                    proc.stdin.close()
                except OSError:
                    pass
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except OSError:
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        # Libera os fds do lado do pai; no Windows, pipes abertos podem
        # reter locks e fazer `shutil.rmtree` falhar com WinError 145.
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass

    def __enter__(self) -> SimulatorClient:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _read_exact(self, n: int) -> bytes:
        """Lê exatamente `n` bytes do stdout, tratando reads parciais do pipe.

        Com `bufsize=0` o stdout é um pipe não-bufferizado (`FileIO`), e
        `read(n)` pode retornar menos que `n` bytes — truncando respostas
        grandes (ex.: getInfo). Este helper acumula até completar `n` bytes.
        """
        assert self._proc.stdout is not None
        chunks: list[bytes] = []
        remaining = n
        while remaining > 0:
            chunk = self._proc.stdout.read(remaining)
            if not chunk:
                raise EOFError("Simulador fechou a conexão inesperadamente")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def send_frame(self, frame: bytes) -> None:
        """Escreve bytes crus no stdin sem montar framing válido.

        Usado por testes de injeção de falha na camada de transporte: o
        chamador controla exatamente o que entra no pipe (frames com
        comprimento zero, truncados etc.) e observa a reação do simulador.
        """
        assert self._proc.stdin is not None
        self._proc.stdin.write(frame)
        self._proc.stdin.flush()

    def close_stdin(self) -> None:
        """Fecha o stdin para sinalizar fim do stream ao simulador."""
        if self._proc.stdin and not self._proc.stdin.closed:
            try:
                self._proc.stdin.close()
            except OSError:
                pass

    def wait_exited(self, timeout: float = 5.0) -> int | None:
        """Aguarda o processo terminar e retorna seu código de saída.

        Em caso de timeout, faz fallback para `kill()` + nova espera, de
        modo que o chamador nunca libere o diretório de storage com o
        filho ainda vivo (flake WinError 145 no teardown).
        """
        try:
            return self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                self._proc.kill()
            except OSError:
                pass
            try:
                return self._proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                return None

    def send_raw(self, cmd: int, payload: bytes = b"") -> tuple[int, bytes]:
        """Envia um comando CTAP2 cru e retorna (status_code, response_bytes)."""
        assert self._proc.stdin is not None
        assert self._proc.stdout is not None

        # Framing: [2 bytes length big-endian] + [1 byte cmd] + [payload]
        total_len = 1 + len(payload)
        header = struct.pack(">H", total_len)
        self._proc.stdin.write(header + bytes([cmd]) + payload)
        self._proc.stdin.flush()

        # Resposta: [2 bytes length] + [1 byte status] + [payload]
        len_bytes = self._read_exact(2)
        (resp_len,) = struct.unpack(">H", len_bytes)
        if resp_len < 1:
            raise ValueError(f"Tamanho de resposta inválido: {resp_len}")

        status = self._read_exact(1)[0]
        data_len = resp_len - 1
        data = self._read_exact(data_len) if data_len > 0 else b""
        return status, data

    def send_cbor(self, cmd: int, payload: Any = None) -> tuple[int, Any]:
        """Envia um comando codificado em CBOR e retorna (status_code, decoded_cbor)."""
        raw_payload = cbor.encode(payload) if payload is not None else b""
        status, resp_data = self.send_raw(cmd, raw_payload)
        if status == CtapError.SUCCESS and resp_data:
            return status, cbor.decode(resp_data)
        return status, resp_data
