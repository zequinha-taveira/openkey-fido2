"""Testes de recursos de segurança do RP2350 sem hardware.

Cobre os recursos de segurança expostos pelo struct `SecurityFeatures`
em `board-generic/src/board_generic.rs` e pelos perfis do virtual board:

- `SecurityFeatures::rp2350()` fornece todos os recursos de segurança
  do Raspberry Pi RP2350 (secure boot, TrustZone, TRNG, etc.)
- Outros boards (NRF52840, STM32L4, ESP32C3, GENERIC) têm
  `security: SecurityFeatures::none()`
- Builder methods individuais funcionam corretamente
- Propagação via `DeviceProfileBuilder::from_board` até `DeviceProfile.security`
"""

import sys
from pathlib import Path

import pytest

WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
BOARD_DIR = WORKSPACE_ROOT / "simulator" / "python"
if str(BOARD_DIR) not in sys.path:
    sys.path.insert(0, str(BOARD_DIR))

from board import VirtualBoard  # noqa: E402
from board.profiles import (  # noqa: E402
    ALL,
    ESP32C3,
    GENERIC,
    NRF52840,
    RP2350,
    RP2350_ZERO,
    STM32L4,
    TRANSPORT_USB_CCID,
    TRANSPORT_USB_HID,
    SecurityFeatures,
    YUBIKEY_4_5,
)

TRANSPORT_NFC = 0x04
TRANSPORT_BLE = 0x08


class TestSecurityFeaturesStruct:
    def test_default_all_false(self):
        features = SecurityFeatures()
        assert not features.secure_boot
        assert not features.trust_zone
        assert not features.hardware_rng
        assert not features.sha256_accelerator
        assert not features.debug_disable
        assert not features.otp_memory
        assert not features.unique_id
        assert not features.tamper_detection

    def test_all_features_true(self):
        features = SecurityFeatures(
            secure_boot=True,
            trust_zone=True,
            hardware_rng=True,
            sha256_accelerator=True,
            debug_disable=True,
            otp_memory=True,
            unique_id=True,
            tamper_detection=True,
        )
        assert features.secure_boot
        assert features.trust_zone
        assert features.hardware_rng
        assert features.sha256_accelerator
        assert features.debug_disable
        assert features.otp_memory
        assert features.unique_id
        assert features.tamper_detection

    def test_partial_features(self):
        features = SecurityFeatures(secure_boot=True, hardware_rng=True)
        assert features.secure_boot
        assert not features.trust_zone
        assert features.hardware_rng
        assert not features.sha256_accelerator


class TestRP2350SecurityProfile:
    def test_rp2350_has_all_security_features(self):
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

    def test_rp2350_has_secure_storage(self):
        assert RP2350.has_secure_storage is True

    def test_rp2350_has_crypto_accelerator(self):
        assert RP2350.has_crypto_accelerator is True

    def test_rp2350_transports(self):
        assert RP2350.has_transport(TRANSPORT_USB_HID)
        assert RP2350.has_transport(TRANSPORT_USB_CCID)
        assert not RP2350.has_transport(TRANSPORT_NFC)
        assert not RP2350.has_transport(TRANSPORT_BLE)

    def test_rp2350_aaguid(self):
        assert RP2350.aaguid[:5] == bytes([0x52, 0x50, 0x32, 0x33, 0x35])
        assert RP2350.aaguid[-1] == 0x05


class TestOtherBoardsNoSecurity:
    def test_nrf52840_no_security_features(self):
        assert NRF52840.security is None
        assert NRF52840.has_secure_storage is True

    def test_stm32l4_no_security_features(self):
        assert STM32L4.security is None
        assert STM32L4.has_secure_storage is True

    def test_esp32c3_no_security_features(self):
        assert ESP32C3.security is None
        assert ESP32C3.has_secure_storage is False

    def test_generic_no_security_features(self):
        assert GENERIC.security is None
        assert GENERIC.has_secure_storage is False


class TestVirtualBoardSecurity:
    def test_virtual_board_rpm2350_blink_with_security(self):
        board = VirtualBoard(profile=RP2350)
        board.led_blink(1)
        assert board.led_state is False

    def test_virtual_board_rpm2350_bump_sign_counter(self):
        board = VirtualBoard(profile=RP2350)
        assert board.bump_sign_counter(b"key") == 1
        assert board.bump_sign_counter(b"key") == 2

    def test_virtual_board_rpm2350_credential_operations(self):
        board = VirtualBoard(profile=RP2350)
        cred = {"id": b"cred-1", "rp_id_hash": b"\x00" * 32, "security_level": "high"}
        board.store_credential(b"cred-1", cred)
        assert board.get_credential(b"cred-1") == cred
        assert len(board.all_credentials()) == 1


class TestAllProfilesSecurity:
    def test_all_profiles_have_unique_names(self):
        names = {profile.name for profile in ALL}
        assert "rp2350-fido" in names
        assert "yubikey-4-5" in names
        assert "rp2350-zero" in names
        assert len(ALL) == 7

    def test_rp2350_is_in_all_profiles(self):
        assert RP2350 in ALL
        assert RP2350_ZERO in ALL
        assert YUBIKEY_4_5 in ALL

    def test_only_rp2350_has_security_features(self):
        for profile in ALL:
            if profile in (RP2350, RP2350_ZERO, YUBIKEY_4_5):
                assert profile.security is not None
            else:
                assert profile.security is None

    def test_yubikey_has_secure_boot_and_secure_lock(self):
        sec = YUBIKEY_4_5.security
        assert sec.secure_boot is True
        assert sec.debug_disable is True
        assert sec.otp_memory is True
        assert sec.unique_id is True
        assert sec.tamper_detection is True

    def test_yubikey_differs_from_rp2350_by_tamper(self):
        assert YUBIKEY_4_5.security.tamper_detection is True
        assert RP2350.security.tamper_detection is False
        assert YUBIKEY_4_5.aaguid[-1] == 0x07
        assert RP2350_ZERO.aaguid[-1] == 0x06
