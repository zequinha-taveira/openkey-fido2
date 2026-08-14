use super::packet::CtaphidPacket;
use super::types::{
    CtaphidCommand, CTAPHID_CONT_PAYLOAD_SIZE, CTAPHID_INIT_PAYLOAD_SIZE, CTAPHID_MAX_PAYLOAD_LEN,
    CTAPHID_PACKET_SIZE,
};
use alloc::vec::Vec;

/// Erros na fragmentação de mensagens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmenterError {
    /// Payload excede o tamanho máximo suportado pelo CTAPHID (7609 bytes).
    PayloadTooLarge(usize),
}

impl core::fmt::Display for FragmenterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PayloadTooLarge(len) => {
                write!(
                    f,
                    "payload size {} exceeds CTAPHID limit of {} bytes",
                    len, CTAPHID_MAX_PAYLOAD_LEN
                )
            }
        }
    }
}

/// Fragmentador de mensagens CTAPHID.
pub struct CtaphidFragmenter;

impl CtaphidFragmenter {
    /// Segmenta uma mensagem completa em um vetor de pacotes brutos de 64 bytes.
    ///
    /// O primeiro pacote é sempre do tipo `INIT` (com até 57 bytes).
    /// Os pacotes subsequentes são do tipo `CONT` (com até 59 bytes cada e `seq` 0, 1, 2...).
    pub fn fragment(
        cid: u32,
        cmd: CtaphidCommand,
        payload: &[u8],
    ) -> Result<Vec<[u8; CTAPHID_PACKET_SIZE]>, FragmenterError> {
        let total_len = payload.len();
        if total_len > CTAPHID_MAX_PAYLOAD_LEN {
            return Err(FragmenterError::PayloadTooLarge(total_len));
        }

        let mut packets = Vec::new();

        // 1. Pacote INIT
        let init_chunk_len = core::cmp::min(total_len, CTAPHID_INIT_PAYLOAD_SIZE);
        let init_data = payload[..init_chunk_len].to_vec();

        let init_pkt = CtaphidPacket::Init {
            cid,
            cmd,
            total_len: total_len as u16,
            data: init_data,
        };
        packets.push(init_pkt.to_bytes());

        // 2. Pacotes CONT
        let mut offset = init_chunk_len;
        let mut seq: u8 = 0;

        while offset < total_len {
            let remaining = total_len - offset;
            let chunk_len = core::cmp::min(remaining, CTAPHID_CONT_PAYLOAD_SIZE);
            let cont_data = payload[offset..offset + chunk_len].to_vec();

            let cont_pkt = CtaphidPacket::Cont {
                cid,
                seq,
                data: cont_data,
            };
            packets.push(cont_pkt.to_bytes());

            offset += chunk_len;
            seq = seq.wrapping_add(1);
        }

        Ok(packets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_empty_payload() {
        let pkts = CtaphidFragmenter::fragment(0x12345678, CtaphidCommand::Wink, &[]).unwrap();
        assert_eq!(pkts.len(), 1);
        let decoded = CtaphidPacket::from_bytes(&pkts[0]).unwrap();
        match decoded {
            CtaphidPacket::Init {
                cid,
                cmd,
                total_len,
                data,
            } => {
                assert_eq!(cid, 0x12345678);
                assert_eq!(cmd, CtaphidCommand::Wink);
                assert_eq!(total_len, 0);
                assert!(data.is_empty());
            }
            _ => panic!("expected Init"),
        }
    }

    #[test]
    fn test_fragment_single_packet_payload() {
        let payload = vec![0x42; 50];
        let pkts = CtaphidFragmenter::fragment(0x12345678, CtaphidCommand::Cbor, &payload).unwrap();
        assert_eq!(pkts.len(), 1);

        let decoded = CtaphidPacket::from_bytes(&pkts[0]).unwrap();
        match decoded {
            CtaphidPacket::Init {
                cid,
                cmd,
                total_len,
                data,
            } => {
                assert_eq!(cid, 0x12345678);
                assert_eq!(cmd, CtaphidCommand::Cbor);
                assert_eq!(total_len, 50);
                assert_eq!(data, payload);
            }
            _ => panic!("expected Init"),
        }
    }

    #[test]
    fn test_fragment_multi_packet_payload() {
        // 57 bytes (INIT) + 59 bytes (CONT 0) + 10 bytes (CONT 1) = 126 bytes
        let payload = (0..126).map(|i| (i % 256) as u8).collect::<Vec<_>>();
        let pkts = CtaphidFragmenter::fragment(0x99887766, CtaphidCommand::Msg, &payload).unwrap();
        assert_eq!(pkts.len(), 3);

        // Packet 0 (INIT)
        let p0 = CtaphidPacket::from_bytes(&pkts[0]).unwrap();
        match p0 {
            CtaphidPacket::Init {
                cid,
                total_len,
                data,
                ..
            } => {
                assert_eq!(cid, 0x99887766);
                assert_eq!(total_len, 126);
                assert_eq!(data.len(), 57);
                assert_eq!(data, &payload[0..57]);
            }
            _ => panic!("expected Init"),
        }

        // Packet 1 (CONT 0)
        let p1 = CtaphidPacket::from_bytes(&pkts[1]).unwrap();
        match p1 {
            CtaphidPacket::Cont { cid, seq, data } => {
                assert_eq!(cid, 0x99887766);
                assert_eq!(seq, 0);
                assert_eq!(data.len(), 59);
                assert_eq!(data, &payload[57..116]);
            }
            _ => panic!("expected Cont"),
        }

        // Packet 2 (CONT 1)
        let p2 = CtaphidPacket::from_bytes(&pkts[2]).unwrap();
        match p2 {
            CtaphidPacket::Cont { cid, seq, data } => {
                assert_eq!(cid, 0x99887766);
                assert_eq!(seq, 1);
                // The raw packet will have padding up to 59 bytes, but the data is the chunk
                assert_eq!(&data[..10], &payload[116..126]);
            }
            _ => panic!("expected Cont"),
        }
    }

    #[test]
    fn test_fragment_oversized_payload() {
        let payload = vec![0u8; CTAPHID_MAX_PAYLOAD_LEN + 1];
        let result = CtaphidFragmenter::fragment(0x11223344, CtaphidCommand::Cbor, &payload);
        assert!(matches!(result, Err(FragmenterError::PayloadTooLarge(_))));
    }
}
