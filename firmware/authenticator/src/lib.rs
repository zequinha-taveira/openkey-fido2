//! API final do autenticador FIDO2 embarcado.
//!
//! [`EmbeddedAuthenticator`] costura as camadas (device profile, transporte,
//! WebAuthn, CTAP2, crypto, storage) para que integradores dependam de um
//! único tipo. Ver `docs/architecture.md` para o diagrama completo.
//!
//! Compila tanto em host (`std`, padrão — inclui o storage inseguro de
//! arquivo) quanto em alvos bare-metal (`no_std` + `alloc`) via a feature
//! `std`.

#![cfg_attr(not(feature = "std"), no_std)]

/// Coordenação das camadas do firmware.
pub mod authenticator;

/// Aplicação Yubico OATH (YKOATH) como applet ISO 7816-4.
pub mod yubico_oath;

/// Aplicação Yubico Management como applet ISO 7816-4.
pub mod yubico_management;

pub use authenticator::EmbeddedAuthenticator;
#[cfg(feature = "std")]
pub use authenticator::InsecureHostStorage;
pub use yubico_management::{register_yubico_applets, ManagementApplet, AID_YUBICO_MANAGEMENT};
pub use yubico_oath::{OathAlgorithm, OathApplet, OathType, AID_YUBICO_OATH, MAX_CREDENTIALS};
