//! Validação de requests WebAuthn antes de delegar ao CTAP2.
//!
//! Esta crate é a fronteira WebAuthn: valida campos obrigatórios das
//! requests (`rp_id`, `client_data_hash`) e repassa ao [`Ctap2Authenticator`].
//! Erros de validação retornam [`WebAuthnError`]; erros do CTAP2 são
//! propagados como `Box<dyn core::error::Error>`.
//!
//! Compila tanto em host (`std`, padrão) quanto em alvos bare-metal
//! (`no_std` + `alloc`) via a feature `std`.

#![cfg_attr(not(feature = "std"), no_std)]

mod webauthn;

pub use webauthn::WebAuthnAuthenticator;
