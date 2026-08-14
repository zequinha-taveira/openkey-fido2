//! Módulo de empacotamento, segmentação e controle de canal CTAPHID (CTAP 2.1 §8.2).

pub mod assembler;
pub mod channel;
pub mod fragmenter;
pub mod packet;
pub mod types;

pub use assembler::CtaphidAssembler;
pub use channel::{capabilities as ctaphid_capabilities, ChannelManager};
pub use fragmenter::{CtaphidFragmenter, FragmenterError};
pub use packet::{CtaphidPacket, PacketError};
pub use types::{
    CtaphidCommand, CtaphidErrorCode, CtaphidKeepaliveStatus, CtaphidMessage,
    CTAPHID_BROADCAST_CID, CTAPHID_CONT_PAYLOAD_SIZE, CTAPHID_INIT_PAYLOAD_SIZE,
    CTAPHID_INVALID_CID, CTAPHID_MAX_PAYLOAD_LEN, CTAPHID_PACKET_SIZE,
};
