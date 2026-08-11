"""Testes do virtual board (emulação de board/HAL em Python).

Cobre o codec CBOR, os periféricos (GPIO, I2C, SPI), o transporte CCID
(APDU/fragmentação) e a agregação no VirtualBoard com os perfis de
`board-generic/src/profiles.rs`. Estes testes não dependem de hardware nem do
simulador Rust — rodam apenas com stdlib.
"""

import sys
from pathlib import Path

import pytest

WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
BOARD_DIR = WORKSPACE_ROOT / "simulator" / "python"
if str(BOARD_DIR) not in sys.path:
    sys.path.insert(0, str(BOARD_DIR))

from board import (  # noqa: E402
    CborError,
    GpioController,
    I2CBus,
    I2CDevice,
    SPIBus,
    VirtualBoard,
    build_response,
    decode,
    encode,
    fragment,
    unwrap_apdu,
    wrap_apdu,
)
from board.profiles import ALL, GENERIC, NRF52840, STM32L4  # noqa: E402


class TestCbor:
    def test_roundtrip_scalars(self):
        for value in (0, 1, 23, 24, 255, 256, 65536, -1, -256, True, False, None):
            assert decode(encode(value)) == value

    def test_roundtrip_strings(self):
        for value in ("", "example.com", "crédito", "a" * 300):
            assert decode(encode(value)) == value

    def test_roundtrip_bytes(self):
        for value in (b"", b"\x00", b"\xff" * 100, b"user123"):
            assert decode(encode(value)) == value

    def test_roundtrip_containers(self):
        payload = {
            1: b"rp_id_hash",
            2: {"rk": True, "uv": False},
            3: [b"id1", b"id2"],
            4: -7,
            5: "texto",
        }
        assert decode(encode(payload)) == payload

    def test_decode_truncated_raises(self):
        with pytest.raises(CborError):
            decode(b"\x58\x05\x01")  # bstr de 5 bytes com só 1

    def test_decode_trailing_bytes_raises(self):
        with pytest.raises(CborError):
            decode(b"\x01\x02")

    def test_indefinite_length_string(self):
        # _byte strings_ indefinite: 0x5f 0x41 0x01 0x41 0x02 0xff
        assert decode(b"\x5f\x41\x01\x41\x02\xff") == b"\x01\x02"

    def test_encode_unsupported_type_raises(self):
        with pytest.raises(TypeError):
            encode(object())


class TestGpio:
    def test_initial_state(self):
        gpio = GpioController()
        assert gpio.is_low(3)

    def test_set_high_low_and_toggle(self):
        gpio = GpioController()
        gpio.set_high(3)
        assert gpio.is_high(3)
        gpio.toggle(3)
        assert gpio.is_low(3)

    def test_listener_notified_on_change(self):
        gpio = GpioController()
        events = []
        gpio.pin(4).add_listener(lambda number, value: events.append((number, value)))
        gpio.set_high(4)
        gpio.set_high(4)
        assert events == [(4, 1)]

    def test_pulse_toggles(self):
        gpio = GpioController()
        gpio.pulse(2, ticks=2)
        assert gpio.is_low(2)


class TestI2C:
    def test_register_read_write(self):
        bus = I2CBus()
        device = I2CDevice(0x28, registers={0x10: 0xAB})
        bus.add_device(device)
        bus.write_register(0x28, 0x10, 0x42)
        assert bus.read_register(0x28, 0x10) == 0x42

    def test_transactions_recorded(self):
        bus = I2CBus()
        bus.add_device(I2CDevice(0x28))
        bus.write_register(0x28, 0x01, 0x02)
        bus.read_register(0x28, 0x01)
        kinds = [transaction[0] for transaction in bus.transactions]
        assert kinds == ["write_register", "read_register"]

    def test_missing_device_raises(self):
        bus = I2CBus()
        with pytest.raises(KeyError):
            bus.read_register(0x28, 0x01)


class TestSPI:
    def test_loopback_default(self):
        bus = SPIBus()
        bus.select()
        assert bus.transfer(b"\x01\x02\x03") == b"\x01\x02\x03"

    def test_custom_miso_transform(self):
        bus = SPIBus(miso_transform=lambda data: bytes(0xFF - value for value in data))
        bus.select()
        assert bus.transfer(b"\x00") == b"\xff"

    def test_miso_length_mismatch_raises(self):
        bus = SPIBus(miso_transform=lambda data: b"")
        bus.select()
        with pytest.raises(ValueError):
            bus.transfer(b"\x01\x02")

    def test_transfer_count(self):
        bus = SPIBus()
        bus.select()
        bus.transfer(b"\x01")
        bus.transfer(b"\x02\x03")
        assert bus.bytes_transferred == 3


class TestCcid:
    def test_wrap_apdu_header(self):
        block = wrap_apdu(b"\x01\x02\x03", seq=1, slot=2)
        assert block[0] == 0x6F
        assert block[1] == 0x00
        length = int.from_bytes(block[2:6], "little")
        assert length == len(block) - 10
        assert block[6] == 0x02  # slot
        assert block[7] == 0x01  # seq

    def test_roundtrip_wrap_unwrap(self):
        for extended, payload in ((True, bytes(range(256))), (False, bytes(range(100)))):
            block = wrap_apdu(payload, extended=extended)
            assert unwrap_apdu(block) == payload

    def test_unwrap_rejects_non_bulk(self):
        assert unwrap_apdu(b"\x00" * 20) is None

    def test_fragment_blocks_are_chunk_sized(self):
        payload = b"x" * 200
        blocks = fragment(payload, chunk=64)
        assert all(len(block) <= 64 for block in blocks)
        assert len(blocks) >= 2

    def test_fragment_roundtrip(self):
        payload = b"ctap2-message" * 10
        blocks = fragment(payload, chunk=64)
        reassembled = b"".join(blocks)
        assert unwrap_apdu(reassembled) == payload

    def test_build_response_status(self):
        response = build_response(0x0A, b"\x00")
        assert unwrap_apdu(response)[:2] == bytes([0x6A, 0x0A])


class TestProfiles:
    def test_generic_ccid_only(self):
        assert GENERIC.transports == 0x01  # TRANSPORT_USB_CCID
        assert GENERIC.has_transport(0x01)
        assert not GENERIC.has_transport(0x02)

    def test_nrf52840_transports(self):
        assert NRF52840.transports == 0x02 | 0x04 | 0x08  # HID|NFC|BLE
        assert NRF52840.has_secure_storage

    def test_stm32l4_has_ccid(self):
        assert STM32L4.has_transport(0x01)
        assert STM32L4.has_secure_storage

    def test_all_profiles_match_rust_names(self):
        expected = {
            "nrf52840-fido",
            "stm32l4-fido",
            "esp32c3-fido",
            "rp2350-fido",
            "generic-fido",
        }
        assert {profile.name for profile in ALL} == expected

    def test_aaguid_length(self):
        assert all(len(profile.aaguid) == 16 for profile in ALL)

    def test_rp2350_security_features(self):
        from board.profiles import RP2350
        assert RP2350.has_secure_storage
        security = RP2350.security
        assert security is not None
        assert security.secure_boot is True
        assert security.trust_zone is True
        assert security.hardware_rng is True
        assert security.sha256_accelerator is True
        assert security.debug_disable is True
        assert security.otp_memory is True
        assert security.unique_id is True
        assert security.tamper_detection is False


class TestVirtualBoard:
    def test_default_uses_generic(self):
        board = VirtualBoard()
        assert board.config == GENERIC

    def test_reset_tracks_count(self):
        board = VirtualBoard()
        board.reset()
        board.reset()
        assert board.reset_count == 2

    def test_led_control(self):
        board = VirtualBoard()
        assert board.led_state is False
        board.led_on()
        assert board.led_state is True
        board.led_blink(1)
        assert board.led_state is False
        assert board.delay_total_ms >= 200

    def test_credential_storage(self):
        board = VirtualBoard()
        credential = {"id": b"id-1", "rp_id_hash": b"\x00" * 32}
        board.store_credential(b"id-1", credential)
        assert board.get_credential(b"id-1") == credential
        assert len(board.all_credentials()) == 1

    def test_sign_counter_bumps(self):
        board = VirtualBoard()
        assert board.bump_sign_counter(b"cred-1") == 1
        assert board.bump_sign_counter(b"cred-1") == 2

    def test_profile_wiring(self):
        board = VirtualBoard(profile=ALL[0])
        assert board.config.name == "nrf52840-fido"
        assert board.config.has_transport(0x02)
