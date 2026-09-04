//! Implementação do protocolo CTAP2 (Client to Authenticator Protocol v2).
//!
//! Esta é a fronteira do protocolo: erros das camadas inferiores são mapeados
//! para [`Ctap2Error`], de modo que o transporte sempre receba um código de
//! status válido. Ver `docs/architecture.md` para o fluxo completo.
//!
//! Compila tanto em host (`std`, padrão) quanto em alvos bare-metal
//! (`no_std` + `alloc`) via a feature `std`.

#![cfg_attr(not(feature = "std"), no_std)]

/// Formatos de attestation (`none`, `packed`, `self`).
pub mod attestation;
/// Comando authenticatorConfig (CTAP2 0x0D).
pub mod authnr_config;
/// Comando ClientPIN (CTAP2 0x06) e gestão do pinUvAuthToken.
pub mod client_pin;
/// Comando Credential Management (CTAP2 0x0A).
pub mod cred_mgmt;
/// Máquina de estado CTAP2 e tipos de request/response.
pub mod ctap2;
/// Extensão `hmac-secret` (CTAP 2.1 §12.5).
pub mod hmac_secret;
/// Comando LargeBlobs (CTAP2 0x0C).
pub mod large_blobs;

pub use attestation::{
    AttestationCertificate, AttestationFormat, PackedAttestation, SelfAttestation,
};
pub use authnr_config::sub_commands as authnr_cfg_subcommands;
pub use cred_mgmt::{
    sub_commands as cred_mgmt_subcommands, CredMgmtParams, CredentialManagementRequest,
    CredsMetadataResponse, EnumerateCredentialsEntryResponse, EnumerateRpsEntryResponse,
};
pub use ctap2::{
    decode_cbor, encode_cbor, BioEnrollRequest, BioEnrollResponse, CoseAlgorithmEntry,
    CredProtectPolicy, CredentialData, CredentialDescriptor, Ctap2Authenticator, Ctap2Capabilities,
    Ctap2Command, Ctap2Error, CtapCommand, CtapResponse, EnumerateRPsResponse, ExtensionOutputs,
    Extensions, GetAssertionOptions, GetAssertionRequest, GetAssertionResponse, GetInfoResponse,
    GetVersionResponse, MakeCredentialOptions, MakeCredentialRequest, MakeCredentialResponse,
    PublicKeyCredParams, RelyingParty, SecurityFeatures, User, UserPresence, UserVerification,
    AAGUID,
};
pub use large_blobs::{LargeBlobsRequest, LargeBlobsResponse};

pub use client_pin::{ClientPin, ClientPinRequest, ClientPinResponse, ClientPinSubCommand};
