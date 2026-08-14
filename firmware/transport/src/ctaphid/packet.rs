//! Codificação e decodificação de pacotes USB-HID brutos de 64 bytes (CTAP 2.1 §8.2.4).

use super::types::{
    CtaphidCommand, CTAPHID_CONT_PAYLOAD_SIZE, CTAPHID_INIT_PAYLOAD_SIZE, CTAPHID_PACKET_SIZE,
};
use alloc::vec::Vec;

/// Erros na decodificação de pacotes brutos CTAPHID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    /// Buffer fornecido tem tamanho diferente de 64 bytes.
    InvalidBufferSize,
    /// Comprimento total de payload excede o limite máximo permitido.
    PayloadLengthTooLarge(usize),
}

impl core::fmt::Display for PacketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidBufferSize => write!(f, "buffer size must be exactly 64 bytes"),
            Self::PayloadLengthTooLarge(len) => {
                write!(f, "payload length {} exceeds CTAPHID maximum", len)
            }
        }
    }
}

/// Representação de um único pacote CTAPHID de 64 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtaphidPacket {
    /// Pacote de Inicialização (INIT).
    /// Contém CID (4B), CMD (1B com bit 7=1), BCNT (2B) e até 57B de payload inicial.
    Init {
        /// Channel ID (4 bytes, big-endian).
        cid: u32,
        /// Comando CTAPHID.
        cmd: CtaphidCommand,
        /// Tamanho total da mensagem lógica completa (BCNT, 2 bytes).
        total_len: u16,
        /// Dados iniciais presentes neste pacote (máx 57 bytes).
        data: Vec<u8>,
    },
    /// Pacote de Continuação (CONT).
    /// Contém CID (4B), SEQ (1B com bit 7=0) e até 59B de payload de continuação.
    Cont {
        /// Channel ID (4 bytes, big-endian).
        cid: u32,
        /// Número de sequência (0..127).
        seq: u8,
        /// Dados de continuação presentes neste pacote (máx 59 bytes).
        data: Vec<u8>,
    },
}

impl CtaphidPacket {
    /// Decodifica um pacote CTAPHID a partir de um array de 64 bytes.
    pub fn from_bytes(raw: &[u8; CTAPHID_PACKET_SIZE]) -> Result<Self, PacketError> {
        let cid = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let cmd_or_seq = raw[4];

        if cmd_or_seq & 0x80 != 0 {
            // Pacote INIT: bit 7 está setado
            let cmd = CtaphidCommand::from_raw_cmd(cmd_or_seq);
            let total_len = u16::from_be_bytes([raw[5], raw[6]]);
            let init_data_len = core::cmp::min(total_len as usize, CTAPHID_INIT_PAYLOAD_SIZE);
            let data = raw[7..7 + init_data_len].to_vec();

            Ok(Self::Init {
                cid,
                cmd,
                total_len,
                data,
            })
        } else {
            // Pacote CONT: bit 7 é zero
            let seq = cmd_or_seq & 0x7F;
            let data = raw[5..CTAPHID_PACKET_SIZE].to_vec();

            Ok(Self::Cont { cid, seq, data })
        }
    }

    /// Serializa o pacote CTAPHID em um buffer de 64 bytes, preenchendo com zeros (padding).
    pub fn to_bytes(&self) -> [u8; CTAPHID_PACKET_SIZE] {
        let mut raw = [0u8; CTAPHID_PACKET_SIZE];
        match self {
            Self::Init {
                cid,
                cmd,
                total_len,
                data,
            } => {
                raw[0..4].copy_from_slice(&cid.to_be_bytes());
                raw[4] = cmd.to_init_cmd_byte();
                raw[5..7].copy_from_slice(&total_len.to_be_bytes());
                let copy_len = core::cmp::min(data.len(), CTAPHID_INIT_PAYLOAD_SIZE);
                raw[7..7 + copy_len].copy_from_slice(&data[..copy_len]);
            }
            Self::Cont { cid, seq, data } => {
                raw[0..4].copy_from_slice(&cid.to_be_bytes());
                raw[4] = seq & 0x7F;
                let copy_len = core::cmp::min(data.len(), CTAPHID_CONT_PAYLOAD_SIZE);
                raw[5..5 + copy_len].copy_from_slice(&data[..copy_len]);
            }
        }
        raw
    }

    /// Retorna o Channel ID deste pacote.
    pub fn cid(&self) -> u32 {
        match self {
            Self::Init { cid, .. } => *cid,
            Self::Cont { cid, .. } => *cid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_packet_roundtrip() {
        let payload = vec![1, 2, 3, 4, 5];
        let pkt = CtaphidPacket::Init {
            cid: 0x11223344,
            cmd: CtaphidCommand::Cbor,
            total_len: 5,
            data: payload.clone(),
        };

        let raw = pkt.to_bytes();
        assert_eq!(&raw[0..4], &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(raw[4], 0x80 | 0x10); // Cbor command with bit 7 set
        assert_eq!(&raw[5..7], &[0x00, 0x05]); // total_len = 5
        assert_eq!(&raw[7..12], &[1, 2, 3, 4, 5]);
        assert_eq!(&raw[12..64], &[0u8; 52]); // padding

        let decoded = CtaphidPacket::from_bytes(&raw).unwrap();
        match decoded {
            CtaphidPacket::Init {
                cid,
                cmd,
                total_len,
                data,
            } => {
                assert_eq!(cid, 0x11223344);
                assert_eq!(cmd, CtaphidCommand::Cbor);
                assert_eq!(total_len, 5);
                assert_eq!(data, payload);
            }
            _ => panic!("expected Init packet"),
        }
    }

    #[test]
    fn test_cont_packet_roundtrip() {
        let payload = vec![0xAA; 59];
        let pkt = CtaphidPacket::Cont {
            cid: 0xAABBCCDD,
            seq: 2,
            data: payload.clone(),
        };

        let raw = pkt.to_bytes();
        assert_eq!(&raw[0..4], &[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(raw[4], 2); // seq = 2, bit 7 = 0
        assert_eq!(&raw[5..64], payload.as_slice());

        let decoded = CtaphidPacket::from_bytes(&raw).unwrap();
        match decoded {
            CtaphidPacket::Cont { cid, seq, data } => {
                assert_eq!(cid, 0xAABBCCDD);
                assert_eq!(seq, 2);
                assert_eq!(data, payload);
            }
            _ => panic!("expected Cont packet"),
        }
    }
}
