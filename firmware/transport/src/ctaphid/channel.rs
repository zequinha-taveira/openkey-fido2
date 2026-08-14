use super::types::{CTAPHID_BROADCAST_CID, CTAPHID_INVALID_CID};
use alloc::vec::Vec;

/// Flags de capacidade do protocolo CTAPHID retornadas na resposta `CTAPHID_INIT`.
pub mod capabilities {
    /// Suporte ao comando `CTAPHID_WINK` (0x01).
    pub const CAPABILITY_WINK: u8 = 0x01;
    /// Suporte a bloqueio de canal `CTAPHID_LOCK` (0x02).
    pub const CAPABILITY_LOCK: u8 = 0x02;
    /// Suporte ao comando `CTAPHID_CBOR` (0x04).
    pub const CAPABILITY_CBOR: u8 = 0x04;
    /// Suporte a comandos não-CTAP1/U2F (`NMSG` = 0x08).
    pub const CAPABILITY_NMSG: u8 = 0x08;
}

/// Gerenciador de canais CTAPHID.
///
/// Controla os Channel IDs (CIDs) ativos e aloca novos identificadores
/// durante o handshake inicial `CTAPHID_INIT`.
#[derive(Debug, Clone)]
pub struct ChannelManager {
    next_cid: u32,
    active_channels: Vec<u32>,
}

impl ChannelManager {
    /// Cria uma nova instância iniciando a alocação a partir de um CID base.
    pub fn new() -> Self {
        Self {
            next_cid: 0x00010001,
            active_channels: Vec::new(),
        }
    }

    /// Aloca um novo Channel ID único e não reservado.
    pub fn allocate_cid(&mut self) -> u32 {
        loop {
            let cid = self.next_cid;
            self.next_cid = self.next_cid.wrapping_add(1);

            // Pula CIDs reservados: 0x00000000 e 0xFFFFFFFF (Broadcast)
            if cid == CTAPHID_INVALID_CID || cid == CTAPHID_BROADCAST_CID {
                continue;
            }

            if !self.active_channels.contains(&cid) {
                self.active_channels.push(cid);
                return cid;
            }
        }
    }

    /// Verifica se um CID está atualmente ativo e alocado.
    pub fn is_valid_cid(&self, cid: u32) -> bool {
        cid == CTAPHID_BROADCAST_CID || self.active_channels.contains(&cid)
    }

    /// Libera um canal previamente alocado.
    pub fn release_cid(&mut self, cid: u32) {
        self.active_channels.retain(|&c| c != cid);
    }

    /// Monta o payload de resposta para o handshake `CTAPHID_INIT` (17 bytes).
    ///
    /// Layout:
    /// - Nonce: 8 bytes (eco do nonce enviado pelo host)
    /// - Assigned CID: 4 bytes (big-endian)
    /// - CTAPHID Protocol Version: 1 byte (2)
    /// - Major Device Version: 1 byte
    /// - Minor Device Version: 1 byte
    /// - Build Device Version: 1 byte
    /// - Capabilities: 1 byte
    pub fn build_init_response(
        &mut self,
        nonce: &[u8],
        major: u8,
        minor: u8,
        build: u8,
        capabilities: u8,
    ) -> Vec<u8> {
        let assigned_cid = self.allocate_cid();
        let mut response = Vec::with_capacity(17);

        // Eco do Nonce de 8 bytes
        if nonce.len() >= 8 {
            response.extend_from_slice(&nonce[..8]);
        } else {
            response.extend_from_slice(nonce);
            response.resize(8, 0);
        }

        // Assigned CID (4 bytes big-endian)
        response.extend_from_slice(&assigned_cid.to_be_bytes());

        // CTAPHID Protocol Version = 2
        response.push(2);

        // Versão do firmware
        response.push(major);
        response.push(minor);
        response.push(build);

        // Capabilities
        response.push(capabilities);

        response
    }
}

impl Default for ChannelManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_unique_cids() {
        let mut mgr = ChannelManager::new();
        let cid1 = mgr.allocate_cid();
        let cid2 = mgr.allocate_cid();
        let cid3 = mgr.allocate_cid();

        assert_ne!(cid1, cid2);
        assert_ne!(cid2, cid3);
        assert_ne!(cid1, CTAPHID_INVALID_CID);
        assert_ne!(cid1, CTAPHID_BROADCAST_CID);

        assert!(mgr.is_valid_cid(cid1));
        assert!(mgr.is_valid_cid(cid2));
        assert!(mgr.is_valid_cid(cid3));

        mgr.release_cid(cid2);
        assert!(!mgr.is_valid_cid(cid2));
        assert!(mgr.is_valid_cid(cid1));
    }

    #[test]
    fn test_build_init_response() {
        let mut mgr = ChannelManager::new();
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let resp = mgr.build_init_response(
            &nonce,
            1,
            0,
            0,
            capabilities::CAPABILITY_CBOR | capabilities::CAPABILITY_WINK,
        );

        assert_eq!(resp.len(), 17);
        assert_eq!(&resp[0..8], &nonce);

        let allocated_cid = u32::from_be_bytes([resp[8], resp[9], resp[10], resp[11]]);
        assert!(mgr.is_valid_cid(allocated_cid));
        assert_eq!(resp[12], 2); // CTAPHID version
        assert_eq!(resp[13], 1); // Major
        assert_eq!(resp[14], 0); // Minor
        assert_eq!(resp[15], 0); // Build
        assert_eq!(
            resp[16],
            capabilities::CAPABILITY_CBOR | capabilities::CAPABILITY_WINK
        );
    }
}
