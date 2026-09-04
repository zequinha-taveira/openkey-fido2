//! Estruturas de requisição e resposta do comando Credential Management (CTAP 2.1 §6.8, Opcode 0x0A).

extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Subcomandos do Credential Management (CTAP 2.1 §6.8).
pub mod sub_commands {
    pub const GET_CREDS_METADATA: u8 = 0x01;
    pub const ENUMERATE_RPS_BEGIN: u8 = 0x02;
    pub const ENUMERATE_RPS_GET_NEXT: u8 = 0x03;
    pub const ENUMERATE_CREDENTIALS_BEGIN: u8 = 0x04;
    pub const ENUMERATE_CREDENTIALS_GET_NEXT: u8 = 0x05;
    pub const DELETE_CREDENTIAL: u8 = 0x06;
    pub const UPDATE_USER_INFORMATION: u8 = 0x07;
}

/// Requisição para o comando Credential Management (0x0A).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialManagementRequest {
    /// Subcomando a ser executado.
    #[serde(rename = "subCommand")]
    pub sub_command: u8,
    /// Parâmetros específicos do subcomando.
    #[serde(
        default,
        rename = "subCommandParams",
        skip_serializing_if = "Option::is_none"
    )]
    pub sub_command_params: Option<CredMgmtParams>,
    /// Protocolo de autenticação PIN/UV.
    #[serde(
        default,
        rename = "pinUvAuthProtocol",
        skip_serializing_if = "Option::is_none"
    )]
    pub pin_uv_auth_protocol: Option<u8>,
    /// Token de autenticação PIN/UV.
    #[serde(
        default,
        with = "serde_bytes",
        rename = "pinUvAuthParam",
        skip_serializing_if = "Option::is_none"
    )]
    pub pin_uv_auth_param: Option<Vec<u8>>,
}

/// Parâmetros adicionais para subcomandos do Credential Management.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredMgmtParams {
    /// Hash do RP ID para enumeração de credenciais.
    #[serde(
        default,
        with = "serde_bytes",
        rename = "rpIDHash",
        skip_serializing_if = "Option::is_none"
    )]
    pub rp_id_hash: Option<Vec<u8>>,
    /// Descritor da credencial para deleção ou atualização.
    #[serde(
        default,
        rename = "credentialId",
        skip_serializing_if = "Option::is_none"
    )]
    pub credential_id: Option<crate::ctap2::CredentialDescriptor>,
    /// Novos metadados do usuário para atualização.
    #[serde(default, rename = "user", skip_serializing_if = "Option::is_none")]
    pub user: Option<crate::ctap2::User>,
}

/// Resposta para o subcomando `getCredsMetadata` (0x01).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredsMetadataResponse {
    /// Quantidade de credenciais residentes existentes.
    #[serde(rename = "existingResidentCredentialsCount")]
    pub existing_resident_credentials_count: u32,
    /// Quantidade máxima estimada de credenciais residentes que ainda cabem no storage.
    #[serde(rename = "maxPossibleRemainingResidentCredentialsCount")]
    pub max_possible_remaining_resident_credentials_count: u32,
}

/// Resposta para o subcomando `enumerateRPs` (0x02 e 0x03).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumerateRpsEntryResponse {
    /// Metadados do Relying Party.
    pub rp: crate::ctap2::RelyingParty,
    /// SHA-256 do RP ID.
    #[serde(with = "serde_bytes", rename = "rpIDHash")]
    pub rp_id_hash: Vec<u8>,
    /// Total de Relying Parties armazenados.
    #[serde(rename = "totalRPs")]
    pub total_rps: u32,
}

/// Resposta para o subcomando `enumerateCredentials` (0x04 e 0x05).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumerateCredentialsEntryResponse {
    /// Metadados do usuário associado.
    pub user: crate::ctap2::User,
    /// Descritor da credencial (ID e tipo).
    #[serde(rename = "credentialId")]
    pub credential_id: crate::ctap2::CredentialDescriptor,
    /// Chave pública no formato COSE.
    #[serde(rename = "publicKey")]
    pub public_key: ciborium::Value,
    /// Total de credenciais para este Relying Party.
    #[serde(rename = "totalCredentials")]
    pub total_credentials: u32,
    /// Política de proteção da credencial (credProtect).
    #[serde(rename = "credProtect", skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<u8>,
    /// Chave da extensão largeBlobKey (32 bytes), se presente.
    #[serde(
        with = "serde_bytes",
        rename = "largeBlobKey",
        skip_serializing_if = "Option::is_none"
    )]
    pub large_blob_key: Option<Vec<u8>>,
}
