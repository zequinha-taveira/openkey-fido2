# Changelog

## Unreleased

- Implemented interoperable CTAP2.1 authenticatorClientPIN (0x06): spec subcommands, integer-key CBOR wire format (array + map), P-256 ECDH key agreement, pinUvAuthProtocol 1 and 2 (SHA-256/HKDF KDF, AES-256-CBC, HMAC-SHA256), CTAP2 PIN error codes, retry/PIN_AUTH_BLOCKED semantics, and GetInfo pinUvAuthProtocols [1, 2] with clientPin/pinUvAuthToken options (see docs/adr/ADR-0017).
- Added `crypto::pin_protocol` (P-256 ECDH, AES-256-CBC via RustCrypto aes/cbc, HKDF-SHA256, constant-time MAC verification) with python-fido2-derived test vectors.
- Added session pinUvAuthToken state and `Ctap2Authenticator::verify_pin_uv_auth_param`.
- E2E: rewrote `tests/python/conformance/test_client_pin.py` to drive the simulator with `fido2.ctap2.pin.ClientPin` (protocols 1 and 2), including getPinUvAuthTokenUsingPinWithPermissions (0x09).
- Pending release publication and artifact signing.

## 0.1.1 - 2026-08-14

- Added regression coverage for random-nonce authenticated encryption.
- Added CTAP2 dispatch and CTAPHID framing fuzz targets.
- Added release artifact checksums.
- Added crash-recovery journaling for host file persistence.
- Added a deterministic two-slot simulated flash backend with power-loss tests.
- Added a protected cosign signing gate; no release is published by this preparation.
- Documented the ClientPIN CTAP2 migration boundary and real-board blockers.
- Recorded the exact CTAP2.1 ClientPIN subcommands, integer-key maps, and v1/v2 crypto wire formats; implementation remains blocked.

## 0.1.0

- Initial development release.
