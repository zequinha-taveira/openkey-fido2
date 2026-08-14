//! Constantes, comandos e tipos de erro do protocolo CTAPHID (CTAP 2.1 §8.2).

use alloc::vec::Vec;

/// Tamanho fixo do pacote USB-HID Full-Speed em bytes.
pub const CTAPHID_PACKET_SIZE: usize = 64;

/// Channel ID reservado para broadcast / alocação de canal inicial (`CTAPHID_INIT`).
pub const CTAPHID_BROADCAST_CID: u32 = 0xFFFFFFFF;

/// Channel ID reservado inválido (número zero).
pub const CTAPHID_INVALID_CID: u32 = 0x00000000;

/// Tamanho máximo do payload de mensagem lógica em bytes (CTAP 2.1).
/// 1 INIT packet (57 bytes) + 128 CONT packets (59 bytes) = 7609 bytes.
pub const CTAPHID_MAX_PAYLOAD_LEN: usize = 57 + 128 * 59;

/// Máximo de bytes de dados em um pacote de inicialização (INIT).
pub const CTAPHID_INIT_PAYLOAD_SIZE: usize = 57;

/// Máximo de bytes de dados em um pacote de continuação (CONT).
pub const CTAPHID_CONT_PAYLOAD_SIZE: usize = 59;

/// Comandos do protocolo CTAPHID (CTAP 2.1 §8.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CtaphidCommand {
    /// Echo de dados de teste (0x01).
    Ping = 0x01,
    /// Mensagem CTAP1 / U2F bruta (0x03).
    Msg = 0x03,
    /// Bloqueio exclusivo de canal (0x04).
    Lock = 0x04,
    /// Alocação e sincronização de canal (0x06).
    Init = 0x06,
    /// Feedback visual no dispositivo (0x08).
    Wink = 0x08,
    /// Comando CTAP2 codificado em CBOR (0x10).
    Cbor = 0x10,
    /// Cancelamento de transação em andamento (0x11).
    Cancel = 0x11,
    /// Keepalive periódico durante operações longas (0x3B).
    Keepalive = 0x3B,
    /// Resposta de erro CTAPHID (0x3F).
    Error = 0x3F,
    /// Comando vendor-specific (0x40..=0x7F).
    Vendor(u8),
}

impl CtaphidCommand {
    /// Converte um byte de comando bruto (sem o bit 7) para o enum.
    pub fn from_raw_cmd(cmd: u8) -> Self {
        let clean = cmd & 0x7F;
        match clean {
            0x01 => Self::Ping,
            0x03 => Self::Msg,
            0x04 => Self::Lock,
            0x06 => Self::Init,
            0x08 => Self::Wink,
            0x10 => Self::Cbor,
            0x11 => Self::Cancel,
            0x3B => Self::Keepalive,
            0x3F => Self::Error,
            v => Self::Vendor(v),
        }
    }

    /// Retorna o código numérico do comando (sem o bit 7).
    pub fn raw_code(&self) -> u8 {
        match self {
            Self::Ping => 0x01,
            Self::Msg => 0x03,
            Self::Lock => 0x04,
            Self::Init => 0x06,
            Self::Wink => 0x08,
            Self::Cbor => 0x10,
            Self::Cancel => 0x11,
            Self::Keepalive => 0x3B,
            Self::Error => 0x3F,
            Self::Vendor(v) => *v,
        }
    }

    /// Retorna o código do comando com o bit 7 setado (`0x80 | cmd`).
    pub fn to_init_cmd_byte(&self) -> u8 {
        0x80 | (self.raw_code() & 0x7F)
    }
}

/// Códigos de erro reportados no payload do comando `CTAPHID_ERROR` (CTAP 2.1 §8.2.4.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CtaphidErrorCode {
    /// Comando desconhecido ou não suportado (0x01).
    InvalidCmd = 0x01,
    /// Parâmetro inválido na requisição (0x02).
    InvalidPar = 0x02,
    /// Tamanho de payload inválido (0x03).
    InvalidLen = 0x03,
    /// Número de sequência inesperado ou fora de ordem (0x04).
    InvalidSeq = 0x04,
    /// Timeout esperando pacotes de continuação (0x05).
    MsgTimeout = 0x05,
    /// Canal ocupado processando outra requisição (0x06).
    ChannelBusy = 0x06,
    /// Bloqueio exclusivo exigido para esta operação (0x0A).
    LockRequired = 0x0A,
    /// Canal inválido ou não alocado (0x0B).
    InvalidChannel = 0x0B,
    /// Outro erro não especificado (0x7F).
    Other = 0x7F,
}

impl CtaphidErrorCode {
    /// Converte um byte de erro para o enum correspondente.
    pub fn from_u8(code: u8) -> Self {
        match code {
            0x01 => Self::InvalidCmd,
            0x02 => Self::InvalidPar,
            0x03 => Self::InvalidLen,
            0x04 => Self::InvalidSeq,
            0x05 => Self::MsgTimeout,
            0x06 => Self::ChannelBusy,
            0x0A => Self::LockRequired,
            0x0B => Self::InvalidChannel,
            _ => Self::Other,
        }
    }

    /// Converte o enum para o código numérico.
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Status de keepalive enviados ao host durante operações demoradas (CTAP 2.1 §8.2.4.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtaphidKeepaliveStatus {
    /// O autenticador ainda está processando o comando (0x01).
    Processing = 0x01,
    /// O autenticador está aguardando o teste de presença do usuário (0x02).
    UpNeeded = 0x02,
}

impl CtaphidKeepaliveStatus {
    /// Converte um byte para o status correspondente.
    pub fn from_u8(code: u8) -> Self {
        match code {
            0x02 => Self::UpNeeded,
            _ => Self::Processing,
        }
    }

    /// Retorna o valor numérico do status.
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

/// Mensagem CTAPHID completa desempacotada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtaphidMessage {
    /// Channel ID da transação.
    pub cid: u32,
    /// Comando CTAPHID.
    pub cmd: CtaphidCommand,
    /// Payload completo remontado.
    pub payload: Vec<u8>,
}

impl CtaphidMessage {
    /// Cria uma nova mensagem CTAPHID.
    pub fn new(cid: u32, cmd: CtaphidCommand, payload: Vec<u8>) -> Self {
        Self { cid, cmd, payload }
    }

    /// Cria uma mensagem de resposta de erro CTAPHID.
    pub fn error(cid: u32, err: CtaphidErrorCode) -> Self {
        Self {
            cid,
            cmd: CtaphidCommand::Error,
            payload: vec![err.as_u8()],
        }
    }
}
