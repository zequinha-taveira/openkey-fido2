//! Implementação do protocolo CTAP2 (Client to Authenticator Protocol v2).
//!
//! Esta é a fronteira do protocolo: erros das camadas inferiores são mapeados
//! para [`Ctap2Error`], de modo que o transporte sempre receba um código de
//! status válido. Ver `docs/architecture.md` para o fluxo completo.

/// Formatos de attestation (`none`, `packed`, `self`).
pub mod attestation;
/// Comando ClientPIN (CTAP2 0x06) e gestão do pinUvAuthToken.
pub mod client_pin;
/// Máquina de estado CTAP2 e tipos de request/response.
pub mod ctap2;

pub use attestation::{
    AttestationCertificate, AttestationFormat, PackedAttestation, SelfAttestation,
};
pub use ctap2::{
    decode_cbor, encode_cbor, BioEnrollRequest, BioEnrollResponse, CoseAlgorithmEntry,
    CredProtectPolicy, CredentialData, CredentialDescriptor, Ctap2Authenticator, Ctap2Capabilities,
    Ctap2Command, Ctap2Error, CtapCommand, CtapResponse, EnumerateRPsResponse, ExtensionOutputs,
    Extensions, GetAssertionOptions, GetAssertionRequest, GetAssertionResponse, GetInfoResponse,
    GetVersionResponse, HmacSecretInput, MakeCredentialOptions, MakeCredentialRequest,
    MakeCredentialResponse, PublicKeyCredParams, RelyingParty, SecurityFeatures, User,
    UserPresence, AAGUID,
};

pub use client_pin::{ClientPin, ClientPinRequest, ClientPinResponse, ClientPinSubCommand};
