//! Estruturas de requisição e resposta do comando LargeBlobs (CTAP 2.1 §6.10, Opcode 0x0C).

extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Requisição para o comando LargeBlobs (0x0C).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LargeBlobsRequest {
    /// Offset em bytes no array global de large blobs para leitura/escrita.
    pub offset: u64,
    /// Quantidade de bytes solicitada para leitura (`get`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub get: Option<u64>,
    /// Dados a serem gravados (`set`).
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub set: Option<Vec<u8>>,
    /// Comprimento total esperado do array de large blobs após a escrita (`length`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    /// Autenticação PIN/UV para a escrita.
    #[serde(
        default,
        with = "serde_bytes",
        rename = "pinUvAuthParam",
        skip_serializing_if = "Option::is_none"
    )]
    pub pin_uv_auth_param: Option<Vec<u8>>,
    /// Versão do protocolo PIN/UV auth.
    #[serde(
        default,
        rename = "pinUvAuthProtocol",
        skip_serializing_if = "Option::is_none"
    )]
    pub pin_uv_auth_protocol: Option<u8>,
}

/// Resposta do comando LargeBlobs (0x0C).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LargeBlobsResponse {
    /// Fragmento lido do array de large blobs.
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub config: Option<Vec<u8>>,
}
