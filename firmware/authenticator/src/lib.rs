//! API final do autenticador FIDO2 embarcado.
//!
//! [`EmbeddedAuthenticator`] costura as camadas (device profile, transporte,
//! WebAuthn, CTAP2, crypto, storage) para que integradores dependam de um
//! único tipo. Ver `docs/architecture.md` para o diagrama completo.

/// Coordenação das camadas do firmware.
pub mod authenticator;

pub use authenticator::EmbeddedAuthenticator;
