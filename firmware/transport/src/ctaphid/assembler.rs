use super::packet::CtaphidPacket;
use super::types::{
    CtaphidCommand, CtaphidErrorCode, CtaphidMessage, CTAPHID_CONT_PAYLOAD_SIZE,
    CTAPHID_INIT_PAYLOAD_SIZE, CTAPHID_MAX_PAYLOAD_LEN, CTAPHID_PACKET_SIZE,
};
use alloc::vec::Vec;

/// Estado de montagem de uma transação CTAPHID em andamento.
#[derive(Debug, Clone)]
struct AssemblyState {
    cid: u32,
    cmd: CtaphidCommand,
    total_len: usize,
    buffer: Vec<u8>,
    next_seq: u8,
}

/// Remontador de pacotes CTAPHID.
///
/// Processa pacotes de 64 bytes sequencialmente, validando Channel ID,
/// comandos, comprimento e números de sequência.
#[derive(Debug, Clone, Default)]
pub struct CtaphidAssembler {
    active_state: Option<AssemblyState>,
}

impl CtaphidAssembler {
    /// Cria uma nova instância do remontador.
    pub fn new() -> Self {
        Self { active_state: None }
    }

    /// Limpa qualquer estado de transação em andamento.
    pub fn reset(&mut self) {
        self.active_state = None;
    }

    /// Retorna `true` se há uma transação ativa aguardando pacotes de continuação.
    pub fn is_assembling(&self) -> bool {
        self.active_state.is_some()
    }

    /// Processa um pacote bruto de 64 bytes.
    ///
    /// - Retorna `Ok(Some(msg))` quando a mensagem completa foi remontada.
    /// - Retorna `Ok(None)` se pacotes adicionais (`CONT`) ainda são aguardados.
    /// - Retorna `Err((cid, error_code))` se uma violação de protocolo ocorreu.
    pub fn process_packet(
        &mut self,
        packet_bytes: &[u8; CTAPHID_PACKET_SIZE],
    ) -> Result<Option<CtaphidMessage>, (u32, CtaphidErrorCode)> {
        let packet = CtaphidPacket::from_bytes(packet_bytes)
            .map_err(|_| (0, CtaphidErrorCode::InvalidPar))?;

        match packet {
            CtaphidPacket::Init {
                cid,
                cmd,
                total_len,
                data,
            } => {
                let total_len_usize = total_len as usize;

                // 1. Validação de tamanho máximo
                if total_len_usize > CTAPHID_MAX_PAYLOAD_LEN {
                    self.active_state = None;
                    return Err((cid, CtaphidErrorCode::InvalidLen));
                }

                // 2. Tratamento especial de CANCEL: cancela qualquer transação em andamento
                if cmd == CtaphidCommand::Cancel {
                    self.active_state = None;
                    return Ok(Some(CtaphidMessage::new(cid, cmd, Vec::new())));
                }

                // 3. Se a mensagem cabe inteiramente no pacote INIT
                if total_len_usize <= CTAPHID_INIT_PAYLOAD_SIZE {
                    self.active_state = None;
                    let actual_len = core::cmp::min(total_len_usize, data.len());
                    return Ok(Some(CtaphidMessage::new(
                        cid,
                        cmd,
                        data[..actual_len].to_vec(),
                    )));
                }

                // 4. Mensagem multipart: inicializa o buffer de montagem
                let mut buffer = Vec::with_capacity(total_len_usize);
                buffer.extend_from_slice(&data);

                self.active_state = Some(AssemblyState {
                    cid,
                    cmd,
                    total_len: total_len_usize,
                    buffer,
                    next_seq: 0,
                });

                Ok(None)
            }
            CtaphidPacket::Cont { cid, seq, data } => {
                let state = match self.active_state.as_mut() {
                    Some(s) => s,
                    None => {
                        // Pacote CONT recebido sem pacote INIT anterior
                        return Err((cid, CtaphidErrorCode::InvalidSeq));
                    }
                };

                // 1. Verifica se o CID confere com o da transação ativa
                if state.cid != cid {
                    return Err((cid, CtaphidErrorCode::InvalidChannel));
                }

                // 2. Verifica o número de sequência esperado
                if state.next_seq != seq {
                    self.active_state = None;
                    return Err((cid, CtaphidErrorCode::InvalidSeq));
                }

                // 3. Acrescenta os dados ao buffer
                let remaining = state.total_len - state.buffer.len();
                let chunk_len = core::cmp::min(
                    remaining,
                    core::cmp::min(data.len(), CTAPHID_CONT_PAYLOAD_SIZE),
                );
                state.buffer.extend_from_slice(&data[..chunk_len]);
                state.next_seq = state.next_seq.wrapping_add(1);

                // 4. Verifica se a mensagem foi completada
                if state.buffer.len() >= state.total_len {
                    let completed = self.active_state.take().unwrap();
                    Ok(Some(CtaphidMessage::new(
                        completed.cid,
                        completed.cmd,
                        completed.buffer,
                    )))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctaphid::fragmenter::CtaphidFragmenter;

    #[test]
    fn test_assemble_single_packet() {
        let payload = vec![0x10, 0x20, 0x30];
        let pkts = CtaphidFragmenter::fragment(0x11223344, CtaphidCommand::Ping, &payload).unwrap();

        let mut assembler = CtaphidAssembler::new();
        let result = assembler.process_packet(&pkts[0]).unwrap();
        assert!(result.is_some());
        let msg = result.unwrap();
        assert_eq!(msg.cid, 0x11223344);
        assert_eq!(msg.cmd, CtaphidCommand::Ping);
        assert_eq!(msg.payload, payload);
    }

    #[test]
    fn test_assemble_multi_packet_roundtrip() {
        let payload = (0..300).map(|i| (i % 256) as u8).collect::<Vec<_>>();
        let pkts = CtaphidFragmenter::fragment(0x55667788, CtaphidCommand::Cbor, &payload).unwrap();
        assert!(pkts.len() > 1);

        let mut assembler = CtaphidAssembler::new();
        let mut completed = None;

        for (i, pkt) in pkts.iter().enumerate() {
            let res = assembler.process_packet(pkt).unwrap();
            if i + 1 == pkts.len() {
                assert!(res.is_some());
                completed = res;
            } else {
                assert!(res.is_none());
                assert!(assembler.is_assembling());
            }
        }

        let msg = completed.unwrap();
        assert_eq!(msg.cid, 0x55667788);
        assert_eq!(msg.cmd, CtaphidCommand::Cbor);
        assert_eq!(msg.payload, payload);
    }

    #[test]
    fn test_assemble_out_of_order_sequence() {
        let payload = (0..200).map(|i| (i % 256) as u8).collect::<Vec<_>>();
        let pkts = CtaphidFragmenter::fragment(0x11112222, CtaphidCommand::Msg, &payload).unwrap();

        let mut assembler = CtaphidAssembler::new();
        // Send INIT
        assert!(assembler.process_packet(&pkts[0]).unwrap().is_none());

        // Send pkt[2] instead of pkt[1] (seq 1 instead of seq 0)
        let err = assembler.process_packet(&pkts[2]).unwrap_err();
        assert_eq!(err.0, 0x11112222);
        assert_eq!(err.1, CtaphidErrorCode::InvalidSeq);
    }

    #[test]
    fn test_assemble_cid_mismatch() {
        let payload = (0..200).map(|i| (i % 256) as u8).collect::<Vec<_>>();
        let pkts = CtaphidFragmenter::fragment(0x11112222, CtaphidCommand::Msg, &payload).unwrap();

        let mut assembler = CtaphidAssembler::new();
        assert!(assembler.process_packet(&pkts[0]).unwrap().is_none());

        // Corrupt CID of CONT packet
        let mut bad_pkt = pkts[1];
        bad_pkt[0] = 0x99;

        let err = assembler.process_packet(&bad_pkt).unwrap_err();
        assert_eq!(err.1, CtaphidErrorCode::InvalidChannel);
    }

    #[test]
    fn test_assemble_cancel_aborts_transaction() {
        let payload = (0..200).map(|i| (i % 256) as u8).collect::<Vec<_>>();
        let pkts = CtaphidFragmenter::fragment(0x11112222, CtaphidCommand::Msg, &payload).unwrap();

        let mut assembler = CtaphidAssembler::new();
        assert!(assembler.process_packet(&pkts[0]).unwrap().is_none());
        assert!(assembler.is_assembling());

        let cancel_pkts =
            CtaphidFragmenter::fragment(0x11112222, CtaphidCommand::Cancel, &[]).unwrap();
        let res = assembler.process_packet(&cancel_pkts[0]).unwrap();
        assert!(res.is_some());
        assert_eq!(res.unwrap().cmd, CtaphidCommand::Cancel);
        assert!(!assembler.is_assembling());
    }
}
