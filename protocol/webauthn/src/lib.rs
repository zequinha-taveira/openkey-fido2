//! Validação de requests WebAuthn antes de delegar ao CTAP2.
//!
//! Esta crate é a fronteira WebAuthn: valida campos obrigatórios das
//! requests (`rp_id`, `client_data_hash`) e repassa ao [`Ctap2Authenticator`].
//! Erros de validação retornam [`WebAuthnError`]; erros do CTAP2 são
//! propagados como `Box<dyn std::error::Error>`.

mod webauthn;

pub use webauthn::WebAuthnAuthenticator;
