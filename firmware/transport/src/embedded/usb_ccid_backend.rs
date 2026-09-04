//! Backend USB-CCID concreto sobre o stack `usb-device`.
//!
//! Implementa uma interface CCID 1.1 (chip smart card, `bInterfaceClass`
//! `0x0B`) sobre um [`UsbBusAllocator`] genérico (`B: UsbBus`), espelhando a
//! arquitetura do backend USB-HID ([`super::usb_hid_backend`]): a classe
//! [`CcidClass`] cuida dos descritores e endpoints; o wrapper [`UsbCcidBackend`]
//! monta um [`UsbDevice`] de interface única e expõe o ciclo de vida
//! `init`/`recv_apdu`/`send_apdu`, análogo a `recv_packet`/`send_packet`.
//!
//! # Protocolo
//!
//! Subconjunto mínimo e correto do CCID 1.1 (rev. 1.10), todos com cabeçalho
//! de 10 bytes:
//!
//! | PC_to_RDR (host → device)     | RDR_to_PC (device → host)         |
//! |-------------------------------|-----------------------------------|
//! | IccPowerOn (0x62)             | DataBlock (0x80) com ATR T=0      |
//! | IccPowerOff (0x63)            | SlotStatus (0x81)                 |
//! | GetSlotStatus (0x65)          | SlotStatus (0x81)                 |
//! | SetParameters (0x61)          | Parameters (0x82) ecoado          |
//! | GetParameters (0x6C)          | Parameters (0x82) T=0             |
//! | XfrBlock (0x6F)               | DataBlock (0x80) via handler/APDU |
//! | Abort (0x72) + controle ABORT | SlotStatus (0x81)                 |
//!
//! Mensagens desconhecidas ou malformadas recebem resposta de falha
//! (`bmCommandStatus = FAILED`, `bError = CMD_NOT_SUPPORTED`) em vez de travar
//! o host — nunca entram em pânico.
//!
//! # Decisão de protocolo: T=0
//!
//! O descritor declara apenas T=0 (`dwProtocols = 1`). Motivos: é o protocolo
//! mais simples de implementar sem hardware NFC real (sem retransmissões de
//! bloco T=1, sem máquina de estados de chaining); o PCSC do Windows/Linux
//! conduz trocas T=0 nativamente; e o lado do applet (mapeamento CTAP2/OATH
//! sobre APDU) é controlado por fases posteriores deste projeto. O nível de
//! troca declarado é "short and extended APDU" (`dwFeatures` bit 17).
//!
//! Sem endpoint interrupt: o host consulta estado via `GetSlotStatus`
//! (polling), comportamento aceito pelos drivers PCSC padrão.
//!
//! Buffers fixos ([`MAX_MSG_LEN`]), zero alocação, compatível com `no_std`.
//!
//! # Limites de payload vs. comandos YKOATH (análise, 2026-08-22)
//!
//! `MAX_MSG_LEN = 288` → 10 B de header CCID + até ~278 B de mensagem; em
//! forma estendida (cabeçalho APDU de 7 B + Le de 2 B) restam ≈ **269 B**
//! úteis para dados de comando. O pior caso real do protocolo YKOATH —
//! `PUT` com nome (≤64 B), issuer (≤64 B) e segredo (≤64 B) mais TLVs —
//! fica em ≈ **200 B**, dentro do limite com folga. Respostas grandes
//! (`LIST`/`CALCULATE_ALL`) não competem por esse espaço: fluem via
//! `SEND REMAINING`/`GET RESPONSE` (chaining no roteador ISO 7816). Um bump
//! de `MAX_MSG_LEN` só se justificaria para futuros comandos com payloads
//! maiores que 269 B — nenhum conhecido hoje.

use usb_device::bus::{InterfaceNumber, UsbBus, UsbBusAllocator};
use usb_device::class::{ControlOut, UsbClass};
use usb_device::control;
use usb_device::descriptor::DescriptorWriter;
use usb_device::device::{
    StringDescriptors, UsbDevice, UsbDeviceBuilder, UsbDeviceState, UsbVidPid,
};
use usb_device::endpoint::{EndpointAddress, EndpointIn, EndpointOut};
use usb_device::{Result as UsbResult, UsbError};

use super::EmbeddedTransportError;

/// Tamanho do pacote bulk Full-Speed (todos os endpoints CCID desta classe).
const PACKET_SIZE: usize = 64;

/// Comprimento do cabeçalho comum das mensagens CCID (ambas as direções).
const CCID_HEADER_LEN: usize = 10;

/// Comprimento máximo de uma mensagem CCID aceita/gerada (cabeçalho incluído).
///
/// Cobre o maior APDU curto possível (262 bytes) mais cabeçalho, com folga; o
/// valor é anunciado no descritor (`dwMaxCCIDMessageLength`).
pub const MAX_MSG_LEN: usize = 288;

/// Comprimento máximo do payload (`abData`) transportável numa mensagem.
pub const MAX_PAYLOAD_LEN: usize = MAX_MSG_LEN - CCID_HEADER_LEN;

// --- bMessageType: host → device (PC_to_RDR) -------------------------------
/// Ativa o ICC e devolve o ATR.
pub const PC_TO_RDR_ICC_POWER_ON: u8 = 0x62;
/// Desativa o ICC.
pub const PC_TO_RDR_ICC_POWER_OFF: u8 = 0x63;
/// Consulta o estado do slot.
pub const PC_TO_RDR_GET_SLOT_STATUS: u8 = 0x65;
/// Define os parâmetros de protocolo (T=0: estrutura de 5 bytes).
pub const PC_TO_RDR_SET_PARAMETERS: u8 = 0x61;
/// Lê os parâmetros de protocolo correntes.
pub const PC_TO_RDR_GET_PARAMETERS: u8 = 0x6C;
/// Troca APDU com o cartão.
pub const PC_TO_RDR_XFR_BLOCK: u8 = 0x6F;
/// Aborta a operação em curso no slot.
pub const PC_TO_RDR_ABORT: u8 = 0x72;

// --- bMessageType: device → host (RDR_to_PC) -------------------------------
/// Resposta com dados (ATR ou resposta de APDU).
pub const RDR_TO_PC_DATABLOCK: u8 = 0x80;
/// Resposta de estado do slot.
pub const RDR_TO_PC_SLOTSTATUS: u8 = 0x81;
/// Resposta de parâmetros de protocolo.
pub const RDR_TO_PC_PARAMETERS: u8 = 0x82;

// --- bStatus (§6.2.2): bits 1:0 bmICCStatus; bit 6 bmCommandStatus ---
/// ICC presente mas inativo (antes de PowerOn bem-sucedido).
pub const STATUS_ICC_INACTIVE: u8 = 0x01;
/// ICC presente e ativo.
pub const STATUS_ICC_ACTIVE: u8 = 0x00;
/// Falha no comando — OR com o status do slot (torna `bError` válido, bit 6).
pub const STATUS_CMD_FAILED: u8 = 0x40;

// --- bError (§6.2.6, códigos usados nesta implementação) --------------------
/// Comando não suportado / tipo de mensagem desconhecido.
pub const BERR_CMD_NOT_SUPPORTED: u8 = 0x00;
/// Slot ocupado (XfrBlock enquanto outro aguarda resposta manual).
pub const BERR_CMD_SLOT_BUSY: u8 = 0x05;
/// Transferência terminou antes dos bytes declarados em `dwLength`.
pub const BERR_XFR_UNDERRUN: u8 = 0xFC;
/// Transferência excedeu a capacidade do buffer ou `dwLength` impossível.
pub const BERR_XFR_OVERRUN: u8 = 0xFD;

/// Valor `bError` para comandos processados sem erro.
const NO_ERROR: u8 = 0x00;

/// Número do protocolo T=0 (`bProtocolNum` nas mensagens de parâmetros).
const T_PROTOCOL_NUM: u8 = 0x00;

/// Parâmetros de protocolo T=0 (estrutura de 5 bytes, §6.1-3).
const T0_PARAM_LEN: usize = 5;

/// Request de controle classe-específico ABORT do CCID (complementa o
/// PC_to_RDR_Abort no bulk OUT; aceito em `control_out`).
const CCID_CONTROL_ABORT: u8 = 0x01;

/// ATR T=0 plausível retornado pelo `IccPowerOn`.
///
/// TS/T0 com convenção direta, TA1/TB1/TD1 presentes (T=0 exclusivo,
/// coerente com `dwProtocols` do descritor) e 10 bytes históricos contendo
/// o ASCII "openkey" — suficiente para o PCSC negociar velocidade padrão
/// T=0. Total 1+1+3+10 = 15 bytes exatos: T0 errado ou byte extra (ex.:
/// TCK de T=1, que T=0 não tem) faz o PCSC rejeitar o ATR (slot MUTE,
/// `SCardConnect` 0x80100066). Há teste estrutural que trava o comprimento.
pub const T0_ATR: [u8; 15] = [
    0x3B, // TS: convenção direta
    0xDA, // T0: Y1=1101b (TA1, TB1, TD1), K=10 bytes históricos
    0x11, // TA1: Fi=372, Di=1
    0x50, // TB1: PI1
    0x00, // TD1: próximo grupo vazio, protocolo T=0
    0x01, 0x6F, 0x70, 0x65, 0x6E, // 0x01 + 'open'
    0x4B, 0x65, 0x79, // 'key'
    0xA0, 0x00,
];

/// Parâmetros T=0 padrão (Fi/Di=372/1, guarda N=0, WI=10, clock parado não
/// permitido). Retornados pelo GetParameters até que o host envie
/// SetParameters.
const T0_DEFAULT_PARAMS: [u8; T0_PARAM_LEN] = [0x11, 0x00, 0x00, 0x0A, 0x00];

/// Descritor de classe CCID (54 bytes, §6.1.1) embutido no descriptor de
/// configuração após o descritor de interface.
#[rustfmt::skip]
pub const CCID_CLASS_DESCRIPTOR: [u8; 54] = [
    0x36,             // bLength (54)
    0x21,             // bDescriptorType (CLASS)
    0x10, 0x01,       // bcdCCID 1.10
    0x00,             // bMaxSlotIndex: slot único
    0x07,             // bVoltageSupport: 5V | 3.3V | 1.8V
    0x01, 0x00, 0x00, 0x00, // dwProtocols: apenas T=0 (ver doc do módulo)
    0xA0, 0x0F, 0x00, 0x00, // dwDefaultClock: 4000 kHz
    0xA0, 0x0F, 0x00, 0x00, // dwMaximumClock
    0x00,             // bNumClockSupported
    0x00, 0x2A, 0x00, 0x00, // dwDataRate: 10752 bps
    0x00, 0xC2, 0x01, 0x00, // dwMaxDataRate: 115200 bps
    0x00,             // bNumDataRatesSupported
    0x00, 0x00, 0x00, 0x00, // dwMaxIFSD: não aplicável a T=0
    0x00, 0x00, 0x00, 0x00, // dwSynchProtocols: nenhum
    0x00, 0x00, 0x00, 0x00, // dwMechanical: nenhum
    0x00, 0x00, 0x02, 0x00, // dwFeatures: bit 17 = "short and extended
                            //   APDU level exchange" — habilita hosts PCSC a
                            //   emitirem APDUs estendidas (wLevelParameter=1)
    (MAX_MSG_LEN & 0xFF) as u8, ((MAX_MSG_LEN >> 8) & 0xFF) as u8, 0x00, 0x00,
                      // dwMaxCCIDMessageLength (LE)
    0xFF,             // bClassGetResponse
    0x00,             // bClassEnvelope
    0x00, 0x00,       // wLcdLayout
    0x00,             // bPINSupport: nenhum
    0x01,             // bMaxCCIDBusySlots
];

/// Callback de troca de APDU injetável na classe.
///
/// Recebe os bytes do APDU do `XfrBlock` e um buffer de rascunho para a
/// resposta; retorna o comprimento da resposta escrita em `resp`. A inclusão
/// dos Status Words (ex.: `90 00`) é responsabilidade do callback.
pub type CcidApduHandler<'a> = dyn FnMut(&[u8], &mut [u8]) -> usize + 'a;

/// Classe USB CCID (interface smart card única, bulk IN/OUT de 64 bytes).
///
/// Acumula pacotes USB do bulk OUT até completar uma mensagem CCID
/// (delimitada por `dwLength` no cabeçalho ou por pacote curto), responde
/// automaticamente às mensagens de controle e entrega `XfrBlock` ao handler
/// injetado — ou o retém para a API manual
/// ([`UsbCcidBackend::recv_apdu`]/[`UsbCcidBackend::send_apdu`]).
pub struct CcidClass<'a, B: UsbBus> {
    iface: InterfaceNumber,
    ep_in: EndpointIn<'a, B>,
    ep_out: EndpointOut<'a, B>,
    /// Acumulador da mensagem PC_to_RDR em recepção.
    rx_buf: [u8; MAX_MSG_LEN],
    rx_len: usize,
    /// Mensagem completa pronta para despacho.
    rx_ready: bool,
    /// Recepção excedeu a capacidade (responde XFR_OVERRUN).
    rx_overflow: bool,
    /// Mensagem RDR_to_PC montada aguardando envio no bulk IN.
    tx_buf: [u8; MAX_MSG_LEN],
    tx_len: usize,
    /// Bytes da mensagem ativa já entregues ao bulk IN (dreno em pacotes
    /// de até 64 B — `EndpointIn::write` leva um pacote por chamada).
    tx_sent: usize,
    /// Segunda mensagem enfileirada enquanto a ativa drena. Sem ela, uma
    /// sondagem `GetSlotStatus` (o driver PCSC sonda agressivamente durante
    /// o `IccPowerOn`) sobrescreveria a resposta ativa — o host nunca veria
    /// o ATR e marcaria o slot como MUTE.
    q_buf: [u8; MAX_MSG_LEN],
    q_len: usize,
    /// ICC ativado por IccPowerOn ainda não seguido de PowerOff.
    powered: bool,
    /// Parâmetros T=0 correntes (atualizados por SetParameters).
    params: [u8; T0_PARAM_LEN],
    /// XfrBlock retido aguardando consumo via `take_pending_request`.
    pending: bool,
    /// `bSlot`/`bSeq` do XfrBlock pendente (reusados na resposta).
    pending_slot: u8,
    pending_seq: u8,
    /// Payload do XfrBlock pendente (buffer próprio: o slot segue respondendo
    /// mensagens de controle enquanto a aplicação decide a resposta).
    pending_apdu: [u8; MAX_PAYLOAD_LEN],
    pending_len: usize,
    /// Resposta manual esperada após `take_pending_request` bem-sucedido.
    resp_awaiting: bool,
    /// Handler injetado; quando presente, responde XfrBlock automaticamente.
    handler: Option<&'a mut CcidApduHandler<'a>>,
}

impl<'a, B: UsbBus> CcidClass<'a, B> {
    /// Cria a classe alocando endpoints bulk IN/OUT no `alloc` (modo manual:
    /// cada XfrBlock fica retido até consumo explícito).
    pub fn new(alloc: &'a UsbBusAllocator<B>) -> Self {
        Self::build(alloc, None)
    }

    /// Variante com handler injetado: cada `XfrBlock` recebido é entregue ao
    /// callback e respondido como `DataBlock` sem intervenção externa.
    pub fn with_handler(
        alloc: &'a UsbBusAllocator<B>,
        handler: &'a mut CcidApduHandler<'a>,
    ) -> Self {
        Self::build(alloc, Some(handler))
    }

    /// Construtor único — aloca exatamente uma interface e dois endpoints.
    fn build(alloc: &'a UsbBusAllocator<B>, handler: Option<&'a mut CcidApduHandler<'a>>) -> Self {
        Self {
            iface: alloc.interface(),
            ep_in: alloc.bulk(PACKET_SIZE as u16),
            ep_out: alloc.bulk(PACKET_SIZE as u16),
            rx_buf: [0u8; MAX_MSG_LEN],
            rx_len: 0,
            rx_ready: false,
            rx_overflow: false,
            tx_buf: [0u8; MAX_MSG_LEN],
            tx_len: 0,
            tx_sent: 0,
            q_buf: [0u8; MAX_MSG_LEN],
            q_len: 0,
            powered: false,
            params: T0_DEFAULT_PARAMS,
            pending: false,
            pending_slot: 0,
            pending_seq: 0,
            pending_apdu: [0u8; MAX_PAYLOAD_LEN],
            pending_len: 0,
            resp_awaiting: false,
            handler,
        }
    }

    /// Indica se existe um handler automático configurado.
    pub fn has_handler(&self) -> bool {
        self.handler.is_some()
    }

    /// Indica se o ICC está ativo (após IccPowerOn, antes de PowerOff).
    pub fn is_powered(&self) -> bool {
        self.powered
    }

    /// Indica se há um XfrBlock retido aguardando consumo.
    pub fn is_pending(&self) -> bool {
        self.pending
    }

    /// Comprimento do APDU retido (0 se não há requisição pendente).
    pub fn pending_request_len(&self) -> usize {
        if self.pending {
            self.pending_len
        } else {
            0
        }
    }

    /// Copia o payload do XfrBlock retido para `buf` (trunca se menor),
    /// libera o slot e arma a expectativa de resposta manual. Retorna `None`
    /// se não há requisição pendente.
    pub fn take_pending_request(&mut self, buf: &mut [u8]) -> Option<usize> {
        if !self.pending {
            return None;
        }
        let n = core::cmp::min(self.pending_len, buf.len());
        buf[..n].copy_from_slice(&self.pending_apdu[..n]);
        self.pending = false;
        self.pending_len = 0;
        self.resp_awaiting = true;
        Some(n)
    }

    /// Envia a resposta do último XfrBlock consumido como
    /// `RDR_to_PC_DataBlock`, ecoando `bSlot`/`bSeq` originais.
    ///
    /// Retorna `Err(BufferTooSmall)` se `resp` exceder [`MAX_PAYLOAD_LEN`] e
    /// `Err(FramingError)` se nenhuma requisição aguarda resposta.
    pub fn send_response(&mut self, resp: &[u8]) -> Result<(), EmbeddedTransportError> {
        if !self.resp_awaiting {
            return Err(EmbeddedTransportError::FramingError);
        }
        if resp.len() > MAX_PAYLOAD_LEN {
            return Err(EmbeddedTransportError::BufferTooSmall);
        }
        let (slot, seq) = (self.pending_slot, self.pending_seq);
        let st = self.ok_status();
        self.resp_awaiting = false;
        self.queue_response(RDR_TO_PC_DATABLOCK, slot, seq, st, NO_ERROR, 0x00, resp);
        Ok(())
    }

    /// Processa uma mensagem completa (se houver) e tenta esvaziar o TX.
    ///
    /// Com handler armazenado ([`Self::with_handler`]) o XfrBlock é respondido
    /// automaticamente; sem handler, fica retido para a troca manual
    /// [`UsbCcidBackend::recv_apdu`]/[`UsbCcidBackend::send_apdu`].
    pub fn process(&mut self) {
        if self.rx_ready {
            self.dispatch_rx();
        }
        self.flush_tx();
    }

    /// Despacha a mensagem acumulada em `rx_buf`.
    fn dispatch_rx(&mut self) {
        // Campos copiados antes de qualquer mutação de rx_buf.
        let msg_type = self.rx_buf[0];
        let slot = self.rx_buf[5];
        let seq = self.rx_buf[6];

        if self.rx_overflow {
            let st = self.fail_status();
            self.clear_rx();
            self.queue_response(
                RDR_TO_PC_SLOTSTATUS,
                slot,
                seq,
                st,
                BERR_XFR_OVERRUN,
                0x00,
                &[],
            );
            return;
        }

        if self.rx_len < CCID_HEADER_LEN {
            // Mensagem curta demais para parsear: falha genérica, sem pânico.
            let st = self.fail_status();
            self.clear_rx();
            self.queue_response(
                RDR_TO_PC_SLOTSTATUS,
                slot,
                seq,
                st,
                BERR_CMD_NOT_SUPPORTED,
                0x00,
                &[],
            );
            return;
        }

        let dw_len = u32::from_le_bytes([
            self.rx_buf[1],
            self.rx_buf[2],
            self.rx_buf[3],
            self.rx_buf[4],
        ]) as usize;

        if CCID_HEADER_LEN + dw_len > self.rx_len {
            // Pacote curto encerrou a transferência antes dos bytes declarados.
            let st = self.fail_status();
            self.clear_rx();
            self.queue_response(
                RDR_TO_PC_SLOTSTATUS,
                slot,
                seq,
                st,
                BERR_XFR_UNDERRUN,
                0x00,
                &[],
            );
            return;
        }

        match msg_type {
            PC_TO_RDR_ICC_POWER_ON => {
                // Cartão virtual sempre presente: qualquer tensão solicitada
                // (bPowerSelect em rx_buf[7]) é aceita.
                self.powered = true;
                let st = self.ok_status();
                self.clear_rx();
                self.queue_response(RDR_TO_PC_DATABLOCK, slot, seq, st, NO_ERROR, 0x00, &T0_ATR);
            }
            PC_TO_RDR_ICC_POWER_OFF => {
                self.powered = false;
                let st = self.ok_status();
                self.clear_rx();
                self.queue_response(RDR_TO_PC_SLOTSTATUS, slot, seq, st, NO_ERROR, 0x00, &[]);
            }
            PC_TO_RDR_GET_SLOT_STATUS => {
                let st = self.ok_status();
                self.clear_rx();
                self.queue_response(RDR_TO_PC_SLOTSTATUS, slot, seq, st, NO_ERROR, 0x00, &[]);
            }
            PC_TO_RDR_GET_PARAMETERS => {
                // Devolve os parâmetros correntes mesmo inativo (padrão T=0);
                // escolha documentada: simplifica clientes que sondam antes
                // de ligar o slot.
                let params = self.params;
                let st = self.ok_status();
                self.clear_rx();
                self.queue_parameters(slot, seq, st, T_PROTOCOL_NUM, &params);
            }
            PC_TO_RDR_SET_PARAMETERS => {
                let proto = self.rx_buf[7]; // bProtocolNum
                if proto == T_PROTOCOL_NUM && dw_len == T0_PARAM_LEN {
                    self.params.copy_from_slice(
                        &self.rx_buf[CCID_HEADER_LEN..CCID_HEADER_LEN + T0_PARAM_LEN],
                    );
                    let params = self.params;
                    let st = self.ok_status();
                    self.clear_rx();
                    self.queue_parameters(slot, seq, st, T_PROTOCOL_NUM, &params);
                } else {
                    let st = self.fail_status();
                    self.clear_rx();
                    self.queue_response(
                        RDR_TO_PC_SLOTSTATUS,
                        slot,
                        seq,
                        st,
                        BERR_CMD_NOT_SUPPORTED,
                        0x00,
                        &[],
                    );
                }
            }
            PC_TO_RDR_ABORT => {
                // Sequência mínima de abort: descarta qualquer operação em
                // aberto e confirma com SlotStatus ecoando bSeq.
                self.pending = false;
                self.resp_awaiting = false;
                let st = self.ok_status();
                self.clear_rx();
                self.queue_response(RDR_TO_PC_SLOTSTATUS, slot, seq, st, NO_ERROR, 0x00, &[]);
            }
            PC_TO_RDR_XFR_BLOCK => {
                // wLevelParameter (rx_buf[8..10], após bRFU em [7]): 0x0000 =
                // APDU curto único; 0x0001 = APDU estendido (nível "short and
                // extended" — ver dwFeatures no descritor). Outros: não
                // suportados.
                let level = u16::from_le_bytes([self.rx_buf[8], self.rx_buf[9]]);
                if level > 1 {
                    let st = self.fail_status();
                    self.clear_rx();
                    self.queue_response(
                        RDR_TO_PC_DATABLOCK,
                        slot,
                        seq,
                        st,
                        BERR_CMD_NOT_SUPPORTED,
                        0x00,
                        &[],
                    );
                } else if self.pending || self.resp_awaiting {
                    let st = self.fail_status();
                    self.clear_rx();
                    self.queue_response(
                        RDR_TO_PC_DATABLOCK,
                        slot,
                        seq,
                        st,
                        BERR_CMD_SLOT_BUSY,
                        0x00,
                        &[],
                    );
                } else {
                    // take() desacopla o handler de &mut self, permitindo
                    // chamar métodos durante o empréstimo; restaurado ao final.
                    // Destino da resposta: fila quando há mensagem ativa
                    // ainda drenando (nunca sobrescreve o TX ativo).
                    let to_queue = self.tx_active();
                    let mut stored = self.handler.take();
                    let handled = match stored.as_deref_mut() {
                        Some(f) => {
                            let dest = if to_queue {
                                &mut self.q_buf[CCID_HEADER_LEN..]
                            } else {
                                &mut self.tx_buf[CCID_HEADER_LEN..]
                            };
                            let n = f(
                                &self.rx_buf[CCID_HEADER_LEN..CCID_HEADER_LEN + dw_len],
                                dest,
                            );
                            Some((core::cmp::min(n, MAX_PAYLOAD_LEN), to_queue))
                        }
                        None => {
                            // Modo manual: retém o payload para a troca
                            // recv_apdu/send_apdu.
                            self.pending_apdu[..dw_len].copy_from_slice(
                                &self.rx_buf[CCID_HEADER_LEN..CCID_HEADER_LEN + dw_len],
                            );
                            self.pending_len = dw_len;
                            self.pending_slot = slot;
                            self.pending_seq = seq;
                            self.pending = true;
                            None
                        }
                    };
                    self.handler = stored;

                    match handled {
                        Some((n, true)) => {
                            let st = self.ok_status();
                            self.seal_q(RDR_TO_PC_DATABLOCK, n, slot, seq, st, NO_ERROR, 0x00);
                        }
                        Some((n, false)) => {
                            let st = self.ok_status();
                            self.seal_tx(RDR_TO_PC_DATABLOCK, n, slot, seq, st, NO_ERROR, 0x00);
                        }
                        None => {
                            // Congela o rx (payload já copiado) até a resposta.
                            self.rx_ready = false;
                            self.rx_len = 0;
                            self.rx_overflow = false;
                        }
                    }
                }
            }
            _ => {
                let st = self.fail_status();
                self.clear_rx();
                self.queue_response(
                    RDR_TO_PC_SLOTSTATUS,
                    slot,
                    seq,
                    st,
                    BERR_CMD_NOT_SUPPORTED,
                    0x00,
                    &[],
                );
            }
        }
    }

    /// bStatus para comando processado com sucesso.
    fn ok_status(&self) -> u8 {
        if self.powered {
            STATUS_ICC_ACTIVE
        } else {
            STATUS_ICC_INACTIVE
        }
    }

    /// bStatus para comando com falha (bit 6 `bmCommandStatus` setado).
    fn fail_status(&self) -> u8 {
        self.ok_status() | STATUS_CMD_FAILED
    }

    /// Limpa o estado de recepção.
    fn clear_rx(&mut self) {
        self.rx_ready = false;
        self.rx_len = 0;
        self.rx_overflow = false;
    }

    /// Há mensagem ativa ainda drenando no bulk IN.
    fn tx_active(&self) -> bool {
        self.tx_sent < self.tx_len
    }

    /// Escreve o cabeçalho RDR_to_PC no buffer (10 bytes, §6.2).
    ///
    /// Layout: `[tipo][dwLength LE][slot][seq][bStatus][bError][específico]`
    /// — o byte 9 é `bChainParameter` (DataBlock), `bRFU` (SlotStatus) ou
    /// `bProtocolNum` (Parameters).
    #[allow(clippy::too_many_arguments)]
    fn write_header(
        buf: &mut [u8; MAX_MSG_LEN],
        msg_type: u8,
        data_len: usize,
        slot: u8,
        seq: u8,
        status: u8,
        error: u8,
        specific: u8,
    ) {
        buf[0] = msg_type;
        let dl = data_len as u32;
        buf[1..5].copy_from_slice(&dl.to_le_bytes());
        buf[5] = slot;
        buf[6] = seq;
        buf[7] = status;
        buf[8] = error;
        buf[9] = specific;
    }

    /// Escreve o cabeçalho RDR_to_PC em `tx_buf` e dispara o envio; os dados
    /// já residem em `tx_buf[CCID_HEADER_LEN..CCID_HEADER_LEN + data_len]`.
    ///
    /// Chamadores garantem que não há mensagem ativa drenando (ver
    /// `dispatch_rx`: handler escreve na fila nesse caso).
    #[allow(clippy::too_many_arguments)]
    fn seal_tx(
        &mut self,
        msg_type: u8,
        data_len: usize,
        slot: u8,
        seq: u8,
        status: u8,
        error: u8,
        specific: u8,
    ) {
        Self::write_header(
            &mut self.tx_buf,
            msg_type,
            data_len,
            slot,
            seq,
            status,
            error,
            specific,
        );
        self.tx_len = CCID_HEADER_LEN + data_len;
        self.tx_sent = 0;
        self.flush_tx();
    }

    /// Sela uma resposta direto na fila (mensagem ativa ainda drenando).
    #[allow(clippy::too_many_arguments)]
    fn seal_q(
        &mut self,
        msg_type: u8,
        data_len: usize,
        slot: u8,
        seq: u8,
        status: u8,
        error: u8,
        specific: u8,
    ) {
        Self::write_header(
            &mut self.q_buf,
            msg_type,
            data_len,
            slot,
            seq,
            status,
            error,
            specific,
        );
        // Fila de profundidade 1: a mais recente vence (sondagens de
        // SlotStatus são idempotentes; DataBlocks nunca disputam a fila —
        // `resp_awaiting` os serializa).
        self.q_len = CCID_HEADER_LEN + data_len;
        self.flush_tx();
    }

    /// Monta e enfileira uma resposta cujos dados precisam ser copiados.
    ///
    /// Vai para a fila quando há mensagem ativa drenando — nunca sobrescreve
    /// bytes ainda não escoados (causa raiz do slot MUTE no driver real).
    #[allow(clippy::too_many_arguments)]
    fn queue_response(
        &mut self,
        msg_type: u8,
        slot: u8,
        seq: u8,
        status: u8,
        error: u8,
        specific: u8,
        data: &[u8],
    ) {
        let n = core::cmp::min(data.len(), MAX_PAYLOAD_LEN);
        if self.tx_active() {
            self.q_buf[CCID_HEADER_LEN..CCID_HEADER_LEN + n].copy_from_slice(&data[..n]);
            Self::write_header(
                &mut self.q_buf,
                msg_type,
                n,
                slot,
                seq,
                status,
                error,
                specific,
            );
            self.q_len = CCID_HEADER_LEN + n;
        } else {
            self.tx_buf[CCID_HEADER_LEN..CCID_HEADER_LEN + n].copy_from_slice(&data[..n]);
            Self::write_header(
                &mut self.tx_buf,
                msg_type,
                n,
                slot,
                seq,
                status,
                error,
                specific,
            );
            self.tx_len = CCID_HEADER_LEN + n;
            self.tx_sent = 0;
        }
        self.flush_tx();
    }

    /// Monta `RDR_to_PC_Parameters`: o byte 9 carrega `bProtocolNum`.
    fn queue_parameters(&mut self, slot: u8, seq: u8, status: u8, proto: u8, params: &[u8]) {
        self.queue_response(
            RDR_TO_PC_PARAMETERS,
            slot,
            seq,
            status,
            NO_ERROR,
            proto,
            params,
        );
    }

    /// Drena o TX no bulk IN em pacotes de até 64 B, escoando o máximo
    /// possível por ciclo de polling (`WouldBlock` — endpoint ainda ocupado
    /// — pausa até o próximo poll). Promove a fila quando a ativa escoa.
    /// Outros erros descartam a mensagem ativa (sem pânico) e promovem a fila.
    fn flush_tx(&mut self) {
        loop {
            if !self.tx_active() {
                if self.q_len == 0 {
                    return;
                }
                self.tx_buf[..self.q_len].copy_from_slice(&self.q_buf[..self.q_len]);
                self.tx_len = self.q_len;
                self.tx_sent = 0;
                self.q_len = 0;
            }
            let end = core::cmp::min(self.tx_sent + PACKET_SIZE, self.tx_len);
            match self.ep_in.write(&self.tx_buf[self.tx_sent..end]) {
                Ok(0) => return, // sem progresso: retenta no próximo poll
                Ok(n) => {
                    self.tx_sent += n;
                    if !self.tx_active() {
                        self.tx_len = 0;
                        self.tx_sent = 0;
                    }
                }
                Err(UsbError::WouldBlock) => return,
                Err(_) => {
                    self.tx_len = 0;
                    self.tx_sent = 0;
                }
            }
        }
    }

    /// Anexa um pacote USB recebido ao acumulador RX e detecta o fim da
    /// transferência bulk (pacote curto, capacidade excedida ou soma dos
    /// bytes atingindo `dwLength` declarado no cabeçalho).
    fn rx_append(&mut self, chunk: &[u8]) {
        if self.rx_ready {
            // Mensagem anterior ainda não consumida: descarta para manter o
            // fluxo sincronizado (o host reenviará após a resposta).
            return;
        }

        let space = MAX_MSG_LEN - self.rx_len;
        let n = core::cmp::min(chunk.len(), space);
        self.rx_buf[self.rx_len..self.rx_len + n].copy_from_slice(&chunk[..n]);
        self.rx_len += n;

        if n < chunk.len() {
            self.rx_overflow = true;
            self.rx_ready = true;
            return;
        }

        if chunk.len() < PACKET_SIZE {
            // Pacote curto encerra a transferência bulk.
            self.rx_ready = true;
            return;
        }

        if self.rx_len >= CCID_HEADER_LEN {
            let dl = u32::from_le_bytes([
                self.rx_buf[1],
                self.rx_buf[2],
                self.rx_buf[3],
                self.rx_buf[4],
            ]) as usize;
            if dl > MAX_PAYLOAD_LEN {
                // dwLength impossível: finaliza imediatamente como overflow.
                self.rx_overflow = true;
                self.rx_ready = true;
            } else if self.rx_len >= CCID_HEADER_LEN + dl {
                // Transferência múltipla de pacotes completou a mensagem.
                self.rx_ready = true;
            }
        }
    }
}

impl<B: UsbBus> UsbClass<B> for CcidClass<'_, B> {
    fn get_configuration_descriptors(&self, writer: &mut DescriptorWriter) -> UsbResult<()> {
        // Interface smart card (bInterfaceClass 0x0B), sem subclass/protocol.
        writer.interface(self.iface, 0x0B, 0x00, 0x00)?;
        // DescriptorWriter::write já prefixa bLength (54) e bDescriptorType (0x21);
        // passa apenas o corpo de 52 bytes sem duplicar o cabeçalho.
        writer.write(0x21, &CCID_CLASS_DESCRIPTOR[2..])?;
        writer.endpoint(&self.ep_in)?;
        writer.endpoint(&self.ep_out)?;
        Ok(())
    }

    fn reset(&mut self) {
        // Reset USB limpa o estado de comunicação; a sessão do cartão
        // (powered) persiste até um PowerOff explícito.
        self.clear_rx();
        self.tx_len = 0;
        self.tx_sent = 0;
        self.q_len = 0;
    }

    fn control_out(&mut self, xfer: ControlOut<B>) {
        let req = *xfer.request();

        // ABORT classe-específico (bmRequestType 0x21, bRequest 0x01):
        // primeira metade da sequência de abort; a segunda chega como
        // PC_to_RDR_Abort no bulk OUT.
        if req.request_type == control::RequestType::Class
            && req.recipient == control::Recipient::Interface
            && req.request == CCID_CONTROL_ABORT
        {
            let _ = xfer.accept();
        }
        // Demais pedidos ficam sem resposta (stall pelo framework).
    }

    fn endpoint_out(&mut self, addr: EndpointAddress) {
        if addr != self.ep_out.address() {
            return;
        }
        let mut pkt = [0u8; PACKET_SIZE];
        if let Ok(n) = self.ep_out.read(&mut pkt) {
            self.rx_append(&pkt[..n]);
        }
    }
}

/// Backend USB-CCID concreto sobre `usb-device`, espelhando
/// [`super::usb_hid_backend::UsbHidBackend`].
///
/// Encapsula um [`UsbDevice`] + [`CcidClass`] montados sobre um
/// [`UsbBusAllocator`] compartilhado. O `UsbBus` concreto (`B`) é fornecido
/// pela HAL da placa. Dois modos de uso:
///
/// - **Automático** ([`UsbCcidBackend::with_handler`]): cada `XfrBlock` é
///   entregue ao callback injetado e respondido como `DataBlock`.
/// - **Manual** ([`UsbCcidBackend::new`]): o loop principal chama
///   [`UsbCcidBackend::recv_apdu`] (retorna o APDU do `XfrBlock`) e
///   [`UsbCcidBackend::send_apdu`] (envia a resposta), espelhando
///   `recv_packet`/`send_packet` do backend HID.
pub struct UsbCcidBackend<'a, B: UsbBus> {
    usb_dev: UsbDevice<'a, B>,
    ccid: CcidClass<'a, B>,
    initialized: bool,
}

impl<'a, B: UsbBus> UsbCcidBackend<'a, B> {
    /// Cria o backend (modo manual de troca de APDU) a partir de um
    /// `UsbBusAllocator` já montado.
    ///
    /// O `alloc` deve viver pelo menos tanto quanto o backend (tipicamente o
    /// escopo de `main`), pois `UsbDevice`/`CcidClass` o referenciam.
    pub fn new(alloc: &'a UsbBusAllocator<B>, vid: u16, pid: u16) -> Self {
        Self::build(alloc, vid, pid, None)
    }

    /// Cria o backend (modo automático) com handler de APDU injetado.
    ///
    /// O handler deve viver tanto quanto o `alloc` (em testes/exemplos,
    /// `Box::leak` produz a referência `'static` adequada).
    pub fn with_handler(
        alloc: &'a UsbBusAllocator<B>,
        vid: u16,
        pid: u16,
        handler: &'a mut CcidApduHandler<'a>,
    ) -> Self {
        Self::build(alloc, vid, pid, Some(handler))
    }

    fn build(
        alloc: &'a UsbBusAllocator<B>,
        vid: u16,
        pid: u16,
        handler: Option<&'a mut CcidApduHandler<'a>>,
    ) -> Self {
        let ccid = CcidClass::build(alloc, handler);

        let usb_dev = UsbDeviceBuilder::new(alloc, UsbVidPid(vid, pid))
            .strings(&[StringDescriptors::default()
                .manufacturer("openkey-fido2")
                .product("FIDO2 Authenticator CCID")
                .serial_number("openkey")])
            .unwrap()
            .max_packet_size_0(64)
            .unwrap()
            .device_class(0x00)
            .build();

        Self {
            usb_dev,
            ccid,
            initialized: false,
        }
    }

    /// Executa um ciclo de polling do stack USB e processa qualquer mensagem
    /// CCID completa pendente (respostas automáticas usam o handler
    /// armazenado, se houver). Retorna `true` quando houve atividade USB ou
    /// existe XfrBlock retido aguardando consumo.
    pub fn poll(&mut self) -> bool {
        let activity = self.usb_dev.poll(&mut [&mut self.ccid]);
        self.ccid.process();
        activity || self.ccid.is_pending()
    }

    /// Inicializa o backend, habilitando `recv_apdu`/`send_apdu`.
    ///
    /// Espelha `UsbHidDevice::init`: por ora apenas marca o estado (a
    /// configuração real de endpoints acontece na enumeração USB conduzida
    /// pelo polling do stack).
    pub fn init(&mut self) -> Result<(), EmbeddedTransportError> {
        self.initialized = true;
        Ok(())
    }

    /// Modo manual: retorna os bytes do APDU recebido num `XfrBlock`
    /// (equivalente a `recv_packet` do backend HID).
    ///
    /// Retorna `Err(Timeout)` quando nenhum `XfrBlock` completo chegou neste
    /// ciclo e `Err(BufferTooSmall)` se `buf` não comporta o APDU (a
    /// requisição permanece retida para nova tentativa com buffer maior).
    pub fn recv_apdu(&mut self, buf: &mut [u8]) -> Result<usize, EmbeddedTransportError> {
        if !self.initialized {
            return Err(EmbeddedTransportError::NotInitialized);
        }
        self.usb_dev.poll(&mut [&mut self.ccid]);
        self.ccid.process();

        let need = self.ccid.pending_request_len();
        if need == 0 {
            return Err(EmbeddedTransportError::Timeout);
        }
        if buf.len() < need {
            return Err(EmbeddedTransportError::BufferTooSmall);
        }
        match self.ccid.take_pending_request(buf) {
            Some(n) => Ok(n),
            None => Err(EmbeddedTransportError::Timeout),
        }
    }

    /// Modo manual: envia a resposta do último APDU consumido via
    /// `recv_apdu` como `RDR_to_PC_DataBlock` (equivalente a `send_packet`).
    pub fn send_apdu(&mut self, resp: &[u8]) -> Result<(), EmbeddedTransportError> {
        if !self.initialized {
            return Err(EmbeddedTransportError::NotInitialized);
        }
        self.ccid.send_response(resp)
    }

    /// Indica se o backend foi inicializado.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Indica se o host configurou o dispositivo USB.
    pub fn is_configured(&self) -> bool {
        self.usb_dev.state() == UsbDeviceState::Configured
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use usb_device::bus::PollResult;
    use usb_device::endpoint::EndpointType;
    use usb_device::{UsbDirection, UsbError};

    /// Capacidade dos buffers do mock (cobre mensagens CCID inteiras).
    const MOCK_CAP: usize = MAX_MSG_LEN;

    /// Estado interno do mock de `UsbBus` (simula o lado do host).
    struct MockInner {
        in_data: [u8; MOCK_CAP],
        in_len: usize,
        /// Quando true, o bulk IN rejeita escritas (`WouldBlock`), como o
        /// endpoint ocupado no hardware real.
        in_busy: bool,
        out_data: [u8; MOCK_CAP],
        out_len: usize,
        out_pending: bool,
        in_addr: Option<EndpointAddress>,
        out_addr: Option<EndpointAddress>,
    }

    impl Default for MockInner {
        fn default() -> Self {
            Self {
                in_data: [0; MOCK_CAP],
                in_len: 0,
                in_busy: false,
                out_data: [0; MOCK_CAP],
                out_len: 0,
                out_pending: false,
                in_addr: None,
                out_addr: None,
            }
        }
    }

    /// Mock de `UsbBus` com estado compartilhado para os testes.
    struct MockUsbBus {
        state: Arc<Mutex<MockInner>>,
    }

    impl MockUsbBus {
        fn new(state: Arc<Mutex<MockInner>>) -> Self {
            Self { state }
        }

        /// Enfileira um pacote OUT (máx. 64 bytes, como o hardware real).
        fn queue_out(state: &Arc<Mutex<MockInner>>, data: &[u8]) {
            assert!(data.len() <= PACKET_SIZE);
            let mut inner = state.lock().unwrap();
            inner.out_data[..data.len()].copy_from_slice(data);
            inner.out_len = data.len();
            inner.out_pending = true;
        }

        /// Snapshot de tudo enviado no bulk IN desde a última coleta (zera
        /// o registro). Acumula pacotes: respostas multi-pacote chegam
        /// concatenadas, como o host as recebe.
        fn take_sent(state: &Arc<Mutex<MockInner>>) -> Vec<u8> {
            let mut inner = state.lock().unwrap();
            let v = inner.in_data[..inner.in_len].to_vec();
            inner.in_len = 0;
            v
        }

        /// Liga/desliga a simulação de endpoint IN ocupado (`WouldBlock`).
        fn set_busy(state: &Arc<Mutex<MockInner>>, busy: bool) {
            state.lock().unwrap().in_busy = busy;
        }
    }

    impl UsbBus for MockUsbBus {
        fn alloc_ep(
            &mut self,
            ep_dir: UsbDirection,
            _ep_addr: Option<EndpointAddress>,
            _ep_type: EndpointType,
            max_packet_size: u16,
            _interval: u8,
        ) -> UsbResult<EndpointAddress> {
            assert_eq!(max_packet_size, PACKET_SIZE as u16);
            let addr = EndpointAddress::from_parts(1, ep_dir);
            let mut inner = self.state.lock().unwrap();
            match ep_dir {
                UsbDirection::In => inner.in_addr = Some(addr),
                UsbDirection::Out => inner.out_addr = Some(addr),
            }
            Ok(addr)
        }

        fn enable(&mut self) {}

        fn reset(&self) {}

        fn set_device_address(&self, _addr: u8) {}

        fn write(&self, _ep_addr: EndpointAddress, buf: &[u8]) -> UsbResult<usize> {
            let mut inner = self.state.lock().unwrap();
            if inner.in_busy {
                return Err(UsbError::WouldBlock);
            }
            // Modela o hardware: um pacote bulk por escrita (64 B); o resto
            // segue nas próximas chamadas — como `flush_tx` drena em chunks.
            let space = MOCK_CAP - inner.in_len;
            let n = core::cmp::min(buf.len(), space);
            let n = core::cmp::min(n, PACKET_SIZE);
            let off = inner.in_len;
            inner.in_data[off..off + n].copy_from_slice(&buf[..n]);
            inner.in_len += n;
            Ok(n)
        }

        fn read(&self, _ep_addr: EndpointAddress, buf: &mut [u8]) -> UsbResult<usize> {
            let mut inner = self.state.lock().unwrap();
            if inner.out_pending {
                let n = core::cmp::min(inner.out_len, buf.len());
                buf[..n].copy_from_slice(&inner.out_data[..n]);
                inner.out_pending = false;
                Ok(n)
            } else {
                Err(UsbError::WouldBlock)
            }
        }

        fn set_stalled(&self, _ep_addr: EndpointAddress, _stalled: bool) {}

        fn is_stalled(&self, _ep_addr: EndpointAddress) -> bool {
            false
        }

        fn suspend(&self) {}

        fn resume(&self) {}

        fn poll(&self) -> PollResult {
            let inner = self.state.lock().unwrap();
            if inner.out_pending {
                PollResult::Data {
                    ep_out: 1 << 1, // endpoint 1, direção OUT
                    ep_in_complete: 0,
                    ep_setup: 0,
                }
            } else {
                PollResult::None
            }
        }

        const QUIRK_SET_ADDRESS_BEFORE_STATUS: bool = false;
    }

    /// Vaza um closure para `'static` (mesmo tempo de vida do allocator).
    fn leak_handler<F>(f: F) -> &'static mut CcidApduHandler<'static>
    where
        F: FnMut(&[u8], &mut [u8]) -> usize + 'static,
    {
        Box::leak(Box::new(f))
    }

    fn make_backend() -> (UsbCcidBackend<'static, MockUsbBus>, Arc<Mutex<MockInner>>) {
        let state = Arc::new(Mutex::new(MockInner::default()));
        let bus = MockUsbBus::new(state.clone());
        let alloc: &'static UsbBusAllocator<MockUsbBus> =
            Box::leak(Box::new(UsbBusAllocator::new(bus)));
        (UsbCcidBackend::new(alloc, 0x1234, 0x5678), state)
    }

    fn make_backend_with_handler<F>(
        f: F,
    ) -> (UsbCcidBackend<'static, MockUsbBus>, Arc<Mutex<MockInner>>)
    where
        F: FnMut(&[u8], &mut [u8]) -> usize + 'static,
    {
        let state = Arc::new(Mutex::new(MockInner::default()));
        let bus = MockUsbBus::new(state.clone());
        let alloc: &'static UsbBusAllocator<MockUsbBus> =
            Box::leak(Box::new(UsbBusAllocator::new(bus)));
        let backend = UsbCcidBackend::with_handler(alloc, 0x1234, 0x5678, leak_handler(f));
        (backend, state)
    }

    /// Monta uma mensagem PC_to_RDR com cabeçalho de 10 bytes.
    fn pc_msg(msg_type: u8, seq: u8, spec: [u8; 3], payload: &[u8]) -> Vec<u8> {
        let mut m = Vec::with_capacity(CCID_HEADER_LEN + payload.len());
        m.push(msg_type);
        m.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        m.push(0x00); // bSlot
        m.push(seq);
        m.extend_from_slice(&spec);
        m.extend_from_slice(payload);
        m
    }

    /// Interpreta uma resposta RDR_to_PC.
    #[allow(clippy::type_complexity)]
    fn rdr_parse(resp: &[u8]) -> (u8, usize, u8, u8, u8, u8, u8, Vec<u8>) {
        assert!(resp.len() >= CCID_HEADER_LEN);
        let mtype = resp[0];
        let dw = u32::from_le_bytes([resp[1], resp[2], resp[3], resp[4]]) as usize;
        let slot = resp[5];
        let seq = resp[6];
        let status = resp[7];
        let error = resp[8];
        let specific = resp[9];
        (
            mtype,
            dw,
            slot,
            seq,
            status,
            error,
            specific,
            resp[CCID_HEADER_LEN..].to_vec(),
        )
    }

    /// Envia uma mensagem do host e consome um ciclo de polling; retorna a
    /// resposta escrita no bulk IN.
    fn exchange(
        backend: &mut UsbCcidBackend<'static, MockUsbBus>,
        state: &Arc<Mutex<MockInner>>,
        msg: &[u8],
    ) -> Vec<u8> {
        MockUsbBus::queue_out(state, msg);
        assert!(backend.poll(), "poll deve reportar atividade do mock");
        MockUsbBus::take_sent(state)
    }

    #[test]
    fn test_class_descriptor_declares_smart_card_t0() {
        assert_eq!(CCID_CLASS_DESCRIPTOR.len(), 54);
        assert_eq!(CCID_CLASS_DESCRIPTOR[0], 0x36); // bLength
        assert_eq!(CCID_CLASS_DESCRIPTOR[1], 0x21); // bDescriptorType CLASS
        assert_eq!(&CCID_CLASS_DESCRIPTOR[2..4], &[0x10, 0x01]); // bcdCCID 1.10
                                                                 // dwProtocols: apenas T=0.
        assert_eq!(&CCID_CLASS_DESCRIPTOR[6..10], &[0x01, 0x00, 0x00, 0x00]);
        // dwFeatures: bit 17 = short and extended APDU level exchange.
        assert_eq!(&CCID_CLASS_DESCRIPTOR[40..44], &[0x00, 0x00, 0x02, 0x00]);
        // dwMaxCCIDMessageLength coerente com MAX_MSG_LEN.
        let declared =
            u32::from_le_bytes(CCID_CLASS_DESCRIPTOR[44..48].try_into().unwrap()) as usize;
        assert_eq!(declared, MAX_MSG_LEN);
    }

    #[test]
    fn test_bulk_endpoints_allocated_64_bytes() {
        let (_backend, state) = make_backend();
        let inner = state.lock().unwrap();
        let in_addr = inner.in_addr.expect("IN endpoint deve ser alocado");
        let out_addr = inner.out_addr.expect("OUT endpoint deve ser alocado");
        drop(inner);
        assert!(in_addr.is_in());
        assert!(out_addr.is_out());
    }

    #[test]
    fn test_icc_power_on_returns_atr_in_data_block() {
        let (mut backend, state) = make_backend();
        backend.init().unwrap();

        let resp = exchange(
            &mut backend,
            &state,
            &pc_msg(PC_TO_RDR_ICC_POWER_ON, 0x42, [0x01, 0, 0], &[]),
        );
        let (mtype, dw, _slot, seq, status, error, _specific, data) = rdr_parse(&resp);
        assert_eq!(mtype, RDR_TO_PC_DATABLOCK);
        assert_eq!(dw, T0_ATR.len());
        assert_eq!(seq, 0x42);
        assert_eq!(status, STATUS_ICC_ACTIVE);
        assert_eq!(error, NO_ERROR);
        assert_eq!(data, T0_ATR.to_vec());
        assert!(backend.ccid.is_powered());
    }

    #[test]
    fn test_t0_atr_length_matches_t0_declaration() {
        // ISO 7816-3: total = 1 (TS) + 1 (T0) + iface(Y1) + hist(K), sem
        // TCK em T=0 exclusivo. ATR fora do declarado faz o PCSC rejeitar
        // (slot MUTE, `SCardConnect` 0x80100066 em hardware real).
        let t0 = T0_ATR[1];
        let y = t0 >> 4;
        let k = (t0 & 0x0F) as usize;
        let n_iface = (0..4).filter(|i| y & (8 >> i) != 0).count();
        assert_eq!(T0_ATR.len(), 2 + n_iface + k);
        // Último byte de interface (TD1): sem grupos seguintes (Y2=0) e
        // protocolo T=0 (coerente com dwProtocols do descritor).
        let td1 = T0_ATR[2 + n_iface - 1];
        assert_eq!(td1 & 0xF0, 0x00);
        assert_eq!(td1 & 0x0F, 0x00);
    }

    #[test]
    fn test_atr_survives_slot_status_race_on_busy_endpoint() {
        // Regressão do slot MUTE no driver real: com o bulk IN ocupado, o
        // ATR do PowerOn fica retido e a sondagem GetSlotStatus (agressiva
        // durante o power-on) NÃO pode sobrescrevê-lo — vai para a fila.
        let (mut backend, state) = make_backend();
        backend.init().unwrap();

        MockUsbBus::set_busy(&state, true);
        MockUsbBus::queue_out(
            &state,
            &pc_msg(PC_TO_RDR_ICC_POWER_ON, 7, [0x01, 0, 0], &[]),
        );
        assert!(backend.poll());
        assert!(backend.ccid.tx_active(), "ATR retido sem escoar");
        assert_eq!(MockUsbBus::take_sent(&state).len(), 0);

        MockUsbBus::queue_out(
            &state,
            &pc_msg(PC_TO_RDR_GET_SLOT_STATUS, 8, [0, 0, 0], &[]),
        );
        assert!(backend.poll());

        // Endpoint livre: as duas respostas escoam em ordem (ATR primeiro).
        MockUsbBus::set_busy(&state, false);
        backend.poll();
        let sent = MockUsbBus::take_sent(&state);
        let (mtype, dw, _slot, seq, status, error, _specific, data) = rdr_parse(&sent);
        assert_eq!(mtype, RDR_TO_PC_DATABLOCK);
        assert_eq!(dw, T0_ATR.len());
        assert_eq!(seq, 7);
        assert_eq!(status, STATUS_ICC_ACTIVE);
        assert_eq!(error, NO_ERROR);
        assert_eq!(&data[..dw], &T0_ATR.to_vec()[..]);
        // Segunda mensagem concatenada: SlotStatus da sondagem, com bSeq.
        let rest = &sent[CCID_HEADER_LEN + dw..];
        let (mtype2, dw2, _s2, seq2, status2, error2, _sp2, _d2) = rdr_parse(rest);
        assert_eq!(mtype2, RDR_TO_PC_SLOTSTATUS);
        assert_eq!(dw2, 0);
        assert_eq!(seq2, 8);
        assert_eq!(status2, STATUS_ICC_ACTIVE);
        assert_eq!(error2, NO_ERROR);
        assert!(backend.ccid.is_powered());
    }

    #[test]
    fn test_long_data_block_drains_in_64b_chunks_without_loss() {
        // Resposta manual de 200 bytes → DataBlock de 210 bytes escoa em
        // pacotes de 64 B (64+64+64+18) sem truncamento nem perda.
        let (mut backend, state) = make_backend();
        backend.init().unwrap();

        let select = [
            0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01,
        ];
        MockUsbBus::queue_out(
            &state,
            &pc_msg(PC_TO_RDR_XFR_BLOCK, 9, [0x00, 0x00, 0x00], &select),
        );
        assert!(backend.poll());
        assert!(backend.ccid.is_pending());
        let mut apdu = [0u8; MAX_PAYLOAD_LEN];
        let n = backend.ccid.take_pending_request(&mut apdu).unwrap();
        assert_eq!(&apdu[..n], &select);

        let big = [0xABu8; 200];
        backend.ccid.send_response(&big).unwrap();
        backend.poll();
        let sent = MockUsbBus::take_sent(&state);
        let (mtype, dw, _slot, seq, status, error, _specific, data) = rdr_parse(&sent);
        assert_eq!(mtype, RDR_TO_PC_DATABLOCK);
        assert_eq!(dw, 200);
        assert_eq!(seq, 9);
        assert_eq!(status, STATUS_ICC_INACTIVE);
        assert_eq!(error, NO_ERROR);
        assert_eq!(data, big.to_vec());
    }

    #[test]
    fn test_get_slot_status_before_and_after_power_on() {
        let (mut backend, state) = make_backend();
        backend.init().unwrap();

        // Antes do power-on: ICC presente porém inativo.
        let resp = exchange(
            &mut backend,
            &state,
            &pc_msg(PC_TO_RDR_GET_SLOT_STATUS, 1, [0, 0, 0], &[]),
        );
        let (mtype, dw, _slot, seq, status, error, _specific, data) = rdr_parse(&resp);
        assert_eq!(mtype, RDR_TO_PC_SLOTSTATUS);
        assert_eq!(seq, 1);
        assert_eq!(status, STATUS_ICC_INACTIVE);
        assert_eq!(error, NO_ERROR);
        assert_eq!(dw, 0);
        assert!(data.is_empty());

        // Power-on ativa o slot...
        exchange(
            &mut backend,
            &state,
            &pc_msg(PC_TO_RDR_ICC_POWER_ON, 2, [0x01, 0, 0], &[]),
        );

        // ...e o status passa a "presente e ativo".
        let resp = exchange(
            &mut backend,
            &state,
            &pc_msg(PC_TO_RDR_GET_SLOT_STATUS, 3, [0, 0, 0], &[]),
        );
        let (_mtype, _dw, _slot, seq, status, _error, _specific, _data) = rdr_parse(&resp);
        assert_eq!(seq, 3);
        assert_eq!(status, STATUS_ICC_ACTIVE);
    }

    #[test]
    fn test_icc_power_off_deactivates_slot() {
        let (mut backend, state) = make_backend();
        backend.init().unwrap();

        exchange(
            &mut backend,
            &state,
            &pc_msg(PC_TO_RDR_ICC_POWER_ON, 1, [0x01, 0, 0], &[]),
        );
        let resp = exchange(
            &mut backend,
            &state,
            &pc_msg(PC_TO_RDR_ICC_POWER_OFF, 2, [0, 0, 0], &[]),
        );
        let (mtype, _dw, _slot, seq, status, _error, _specific, _data) = rdr_parse(&resp);
        assert_eq!(mtype, RDR_TO_PC_SLOTSTATUS);
        assert_eq!(seq, 2);
        assert_eq!(status, STATUS_ICC_INACTIVE);
        assert!(!backend.ccid.is_powered());
    }

    #[test]
    fn test_xfr_block_round_trip_through_handler() {
        // Handler ecoa o APDU e acrescenta SW 9000.
        let (mut backend, state) = make_backend_with_handler(|req, resp| {
            let n = core::cmp::min(req.len(), resp.len() - 2);
            resp[..n].copy_from_slice(&req[..n]);
            resp[n] = 0x90;
            resp[n + 1] = 0x00;
            n + 2
        });
        backend.init().unwrap();

        exchange(
            &mut backend,
            &state,
            &pc_msg(PC_TO_RDR_ICC_POWER_ON, 1, [0x01, 0, 0], &[]),
        );

        let apdu = [0x80u8, 0x10, 0x00, 0x00, 0x02, 0xAA, 0xBB];
        let resp = exchange(
            &mut backend,
            &state,
            &pc_msg(PC_TO_RDR_XFR_BLOCK, 7, [0x00, 0x00, 0x00], &apdu),
        );
        let (mtype, dw, _slot, seq, status, error, _specific, data) = rdr_parse(&resp);
        assert_eq!(mtype, RDR_TO_PC_DATABLOCK);
        assert_eq!(seq, 7);
        assert_eq!(status, STATUS_ICC_ACTIVE);
        assert_eq!(error, NO_ERROR);
        let mut expected = apdu.to_vec();
        expected.extend_from_slice(&[0x90, 0x00]);
        assert_eq!(dw, expected.len());
        assert_eq!(data, expected);
    }

    #[test]
    fn test_xfr_block_extended_level_parameter_accepted() {
        // wLevelParameter=0x0001 ("extended APDU level exchange") deve ser
        // aceito; bRFU em [7] é ignorado — prova o offset correto [8..10].
        let (mut backend, state) = make_backend_with_handler(|req, resp| {
            let n = core::cmp::min(req.len(), resp.len() - 2);
            resp[..n].copy_from_slice(&req[..n]);
            resp[n] = 0x90;
            resp[n + 1] = 0x00;
            n + 2
        });
        backend.init().unwrap();
        exchange(
            &mut backend,
            &state,
            &pc_msg(PC_TO_RDR_ICC_POWER_ON, 1, [0x01, 0, 0], &[]),
        );

        // APDU estendido estilo yubikit: [CLA INS P1 P2 00 LcHi LcLo data]
        let apdu = [
            0x00u8, 0xA4, 0x04, 0x00, 0x00, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01,
        ];
        let resp = exchange(
            &mut backend,
            &state,
            &pc_msg(PC_TO_RDR_XFR_BLOCK, 9, [0xAA, 0x01, 0x00], &apdu), // RFU=0xAA, level=1
        );
        let (mtype, dw, _slot, seq, status, error, _specific, data) = rdr_parse(&resp);
        assert_eq!(mtype, RDR_TO_PC_DATABLOCK);
        assert_eq!(seq, 9);
        assert_eq!(status, STATUS_ICC_ACTIVE);
        assert_eq!(error, NO_ERROR);
        let mut expected = apdu.to_vec();
        expected.extend_from_slice(&[0x90, 0x00]);
        assert_eq!(dw, expected.len());
        assert_eq!(data, expected);
    }

    #[test]
    fn test_xfr_block_unknown_level_parameter_rejected() {
        let (mut backend, state) = make_backend_with_handler(|req, resp| {
            resp[0] = req[0];
            1
        });
        backend.init().unwrap();
        exchange(
            &mut backend,
            &state,
            &pc_msg(PC_TO_RDR_ICC_POWER_ON, 1, [0x01, 0, 0], &[]),
        );
        let resp = exchange(
            &mut backend,
            &state,
            &pc_msg(PC_TO_RDR_XFR_BLOCK, 5, [0x00, 0x02, 0x00], &[0x00]),
        );
        let (mtype, _dw, _slot, _seq, _status, error, _specific, data) = rdr_parse(&resp);
        assert_eq!(mtype, RDR_TO_PC_DATABLOCK);
        assert_eq!(error, BERR_CMD_NOT_SUPPORTED);
        assert!(data.is_empty());
    }

    #[test]
    fn test_xfr_block_manual_recv_apdu_send_apdu() {
        let (mut backend, state) = make_backend();
        backend.init().unwrap();

        let apdu = [0x00u8, 0xA4, 0x04, 0x00, 0x02, 0x3F, 0x00];
        MockUsbBus::queue_out(
            &state,
            &pc_msg(PC_TO_RDR_XFR_BLOCK, 0x33, [0x00, 0x00, 0x00], &apdu),
        );
        assert!(backend.poll());

        let mut got = [0u8; MAX_PAYLOAD_LEN];
        let n = backend.recv_apdu(&mut got).unwrap();
        assert_eq!(n, apdu.len());
        assert_eq!(&got[..n], &apdu);

        // Resposta manual vira DataBlock ecoando bSeq original. Slot inativo
        // (sem power-on neste teste): bStatus reflete presença inativa.
        backend.send_apdu(&[0x61, 0x02]).unwrap();
        let resp = MockUsbBus::take_sent(&state);
        let (mtype, dw, _slot, seq, status, error, _specific, data) = rdr_parse(&resp);
        assert_eq!(mtype, RDR_TO_PC_DATABLOCK);
        assert_eq!(seq, 0x33);
        assert_eq!(status, STATUS_ICC_INACTIVE);
        assert_eq!(error, NO_ERROR);
        assert_eq!(data, vec![0x61, 0x02]);
        assert_eq!(dw, 2);

        // Sem tráfego novo, recv_apdu indica timeout...
        let mut scratch = [0u8; MAX_PAYLOAD_LEN];
        assert!(matches!(
            backend.recv_apdu(&mut scratch),
            Err(EmbeddedTransportError::Timeout)
        ));
        // ...e send_apdu fora de ordem falha sem pânico.
        assert!(matches!(
            backend.send_apdu(&[0x90, 0x00]),
            Err(EmbeddedTransportError::FramingError)
        ));
    }

    #[test]
    fn test_recv_apdu_buffer_too_small_keeps_request() {
        let (mut backend, state) = make_backend();
        backend.init().unwrap();

        MockUsbBus::queue_out(
            &state,
            &pc_msg(PC_TO_RDR_XFR_BLOCK, 9, [0x00, 0x00, 0x00], &[1, 2, 3, 4]),
        );
        assert!(backend.poll());

        // Buffer pequeno demais: erro, mas a requisição permanece retida.
        let mut tiny = [0u8; 2];
        assert!(matches!(
            backend.recv_apdu(&mut tiny),
            Err(EmbeddedTransportError::BufferTooSmall)
        ));
        let mut ok = [0u8; MAX_PAYLOAD_LEN];
        let n = backend.recv_apdu(&mut ok).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&ok[..n], &[1, 2, 3, 4]);
    }

    #[test]
    fn test_xfr_block_multipacket_reassembly() {
        let (mut backend, state) = make_backend();
        backend.init().unwrap();

        // APDU de 100 bytes: mensagem total de 110 → dois pacotes (64 + 46).
        let apdu: Vec<u8> = (0..100u8).collect();
        let msg = pc_msg(PC_TO_RDR_XFR_BLOCK, 0x11, [0x00, 0x00, 0x00], &apdu);
        assert_eq!(msg.len(), 110);

        MockUsbBus::queue_out(&state, &msg[..64]);
        assert!(backend.poll());
        // Primeiro pacote sozinho não completa a mensagem.
        let mut scratch = [0u8; MAX_PAYLOAD_LEN];
        assert!(matches!(
            backend.recv_apdu(&mut scratch),
            Err(EmbeddedTransportError::Timeout)
        ));

        MockUsbBus::queue_out(&state, &msg[64..]);
        let n = backend.recv_apdu(&mut scratch).unwrap();
        assert_eq!(n, apdu.len());
        assert_eq!(&scratch[..n], &apdu[..]);
    }

    #[test]
    fn test_unknown_message_type_responds_failed_not_supported() {
        let (mut backend, state) = make_backend();
        backend.init().unwrap();

        let resp = exchange(
            &mut backend,
            &state,
            &pc_msg(0x99, 9, [0, 0, 0], &[0xDE, 0xAD]),
        );
        let (mtype, _dw, _slot, seq, status, error, _specific, _data) = rdr_parse(&resp);
        assert_eq!(mtype, RDR_TO_PC_SLOTSTATUS);
        assert_eq!(seq, 9);
        assert_eq!(status, STATUS_ICC_INACTIVE | STATUS_CMD_FAILED);
        assert_eq!(error, BERR_CMD_NOT_SUPPORTED);
    }

    #[test]
    fn test_abort_sequence_returns_slot_status_and_clears_pending() {
        let (mut backend, state) = make_backend();
        backend.init().unwrap();

        exchange(
            &mut backend,
            &state,
            &pc_msg(PC_TO_RDR_ICC_POWER_ON, 1, [0x01, 0, 0], &[]),
        );

        // Deixa um XfrBlock pendente (sem consumir).
        MockUsbBus::queue_out(
            &state,
            &pc_msg(PC_TO_RDR_XFR_BLOCK, 2, [0x00, 0x00, 0x00], &[0x00, 0x12]),
        );
        assert!(backend.poll());
        assert!(backend.ccid.is_pending());

        // Abort termina a sequência e limpa a operação pendente.
        let resp = exchange(
            &mut backend,
            &state,
            &pc_msg(PC_TO_RDR_ABORT, 0x77, [0, 0, 0], &[]),
        );
        let (mtype, _dw, _slot, seq, status, error, _specific, _data) = rdr_parse(&resp);
        assert_eq!(mtype, RDR_TO_PC_SLOTSTATUS);
        assert_eq!(seq, 0x77);
        assert_eq!(status, STATUS_ICC_ACTIVE);
        assert_eq!(error, NO_ERROR);
        assert!(!backend.ccid.is_pending());

        let mut scratch = [0u8; MAX_PAYLOAD_LEN];
        assert!(matches!(
            backend.recv_apdu(&mut scratch),
            Err(EmbeddedTransportError::Timeout)
        ));
    }

    #[test]
    fn test_xfr_block_while_pending_responds_slot_busy() {
        let (mut backend, state) = make_backend();
        backend.init().unwrap();

        exchange(
            &mut backend,
            &state,
            &pc_msg(PC_TO_RDR_ICC_POWER_ON, 1, [0x01, 0, 0], &[]),
        );

        // Primeiro XfrBlock fica pendente (consumo manual)...
        MockUsbBus::queue_out(
            &state,
            &pc_msg(PC_TO_RDR_XFR_BLOCK, 2, [0x00, 0x00, 0x00], &[0x01]),
        );
        assert!(backend.poll());
        assert!(backend.ccid.is_pending());

        // ...e o segundo recebe CMD_SLOT_BUSY sem perturbar o primeiro.
        let resp = exchange(
            &mut backend,
            &state,
            &pc_msg(PC_TO_RDR_XFR_BLOCK, 3, [0x00, 0x00, 0x00], &[0x02]),
        );
        let (mtype, _dw, _slot, seq, status, error, _specific, _data) = rdr_parse(&resp);
        assert_eq!(mtype, RDR_TO_PC_DATABLOCK);
        assert_eq!(seq, 3);
        assert_ne!(status & STATUS_CMD_FAILED, 0);
        assert_eq!(error, BERR_CMD_SLOT_BUSY);
        assert!(backend.ccid.is_pending());
    }

    #[test]
    fn test_set_parameters_then_get_parameters_echoes_t0() {
        let (mut backend, state) = make_backend();
        backend.init().unwrap();

        let params: [u8; T0_PARAM_LEN] = [0x18, 0x10, 0x20, 0x64, 0x00];
        let resp = exchange(
            &mut backend,
            &state,
            &pc_msg(PC_TO_RDR_SET_PARAMETERS, 4, [T_PROTOCOL_NUM, 0, 0], &params),
        );
        // Slot nunca ligado neste teste: bStatus = presente/inativo.
        let (mtype, dw, _slot, seq, status, error, specific, data) = rdr_parse(&resp);
        assert_eq!(mtype, RDR_TO_PC_PARAMETERS);
        assert_eq!(seq, 4);
        assert_eq!(status, STATUS_ICC_INACTIVE);
        assert_eq!(error, NO_ERROR);
        assert_eq!(specific, T_PROTOCOL_NUM);
        assert_eq!(dw, T0_PARAM_LEN);
        assert_eq!(data, params.to_vec());

        // GetParameters devolve os parâmetros recém-configurados.
        let resp = exchange(
            &mut backend,
            &state,
            &pc_msg(PC_TO_RDR_GET_PARAMETERS, 5, [T_PROTOCOL_NUM, 0, 0], &[]),
        );
        let (mtype, dw, _slot, _seq, _status, _error, specific, data) = rdr_parse(&resp);
        assert_eq!(mtype, RDR_TO_PC_PARAMETERS);
        assert_eq!(specific, T_PROTOCOL_NUM);
        assert_eq!(dw, T0_PARAM_LEN);
        assert_eq!(data, params.to_vec());
    }

    #[test]
    fn test_malformed_dw_length_does_not_panic() {
        let (mut backend, state) = make_backend();
        backend.init().unwrap();

        // Underrun: declara 200 bytes mas encerra com pacote curto de 20.
        let mut bogus = vec![PC_TO_RDR_XFR_BLOCK];
        bogus.extend_from_slice(&200u32.to_le_bytes());
        bogus.push(0x00); // bSlot
        bogus.push(0x55); // bSeq
        bogus.extend_from_slice(&[0, 0, 0]);
        bogus.extend_from_slice(&[0xAB; 10]); // só 10 bytes de payload
        let resp = exchange(&mut backend, &state, &bogus);
        let (_mtype, _dw, _slot, seq, status, error, _specific, _data) = rdr_parse(&resp);
        assert_eq!(seq, 0x55);
        assert_eq!(status, STATUS_ICC_INACTIVE | STATUS_CMD_FAILED);
        assert_eq!(error, BERR_XFR_UNDERRUN);

        // Lixo curto (< 10 bytes de cabeçalho): falha genérica, sem pânico.
        let resp = exchange(&mut backend, &state, &[0x42, 0x24]);
        let (mtype, _dw, _slot, _seq, status, error, _specific, _data) = rdr_parse(&resp);
        assert_eq!(mtype, RDR_TO_PC_SLOTSTATUS);
        assert_ne!(status & STATUS_CMD_FAILED, 0);
        assert_eq!(error, BERR_CMD_NOT_SUPPORTED);
    }

    #[test]
    fn test_apdu_before_init_fails() {
        let (mut backend, _state) = make_backend();
        let mut scratch = [0u8; MAX_PAYLOAD_LEN];
        assert!(matches!(
            backend.recv_apdu(&mut scratch),
            Err(EmbeddedTransportError::NotInitialized)
        ));
        assert!(matches!(
            backend.send_apdu(&[0x90, 0x00]),
            Err(EmbeddedTransportError::NotInitialized)
        ));
    }
}
