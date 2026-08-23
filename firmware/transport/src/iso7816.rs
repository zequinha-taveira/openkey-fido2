//! Roteador ISO/IEC 7816-4 puro (lógica apenas, sem dependência de USB).
//!
//! Este módulo é a camada de despacho de APDUs da interface CCID: recebe o
//! payload de um `XfrBlock` ([`super::embedded::usb_ccid_backend`]), decide
//! qual *applet* atende o comando e devolve `data + SW` (Status Word).
//!
//! # Modelo de estado do [`CardRouter`]
//!
//! - **Sem applet selecionado**: qualquer comando que não seja SELECT
//!   responde `6D 00` (`SW_INS_NOT_SUPPORTED`). Escolha documentada: até a
//!   seleção inicial não há aplicação corrente, logo "INS não suportado"
//!   reflete o estado do cartão melhor que um erro de condições.
//! - **SELECT** ([`INS_SELECT`], P1 ignorado): casa por AID completo ou
//!   prefixo (o AID requisitado é prefixo do AID registrado; vence o mais
//!   longo). AID desconhecido → `6A 82` com a **seleção anterior preservada**
//!   (escolha documentada). Após sucesso, todos os APDUs seguintes vão para o
//!   applet selecionado, até o próximo SELECT.
//! - **Encadeamento de resposta**: quando o applet produz mais bytes do que o
//!   host pode receber agora (`Le` ausente/curto), o roteador entrega o trecho
//!   cabível e sinaliza `61 XX` (`XX = 00` significa ≥256). O host busca o
//!   restante com GET RESPONSE ([`INS_GET_RESPONSE`]), atendido pelo próprio
//!   roteador — fora de sequência responde `69 85`. Qualquer comando diferente
//!   de GET RESPONSE descarta o encadeamento pendente (escolha documentada).
//!
//! # Formas de comando aceitas
//!
//! - Forma **curta** (casos 1/2S/3S/4S) e forma **estendida** da ISO/IEC
//!   7816-4 §5.1.1 (casos 2E/3E/4E: byte 5 = `00`, Lc/Le de 2 bytes,
//!   `Le = 0000` significa 65536). Um frame de 7 bytes com byte 5 nulo é
//!   interpretado como caso 2E puro (`00 LeHi LeLo`) — exatamente o layout
//!   emitido pelo `ExtendedApduFormatter` do python-yubikit para comando sem
//!   dados com `Le > 0`; um caso 3E truncado nesse tamanho é indistinguível
//!   dessa leitura (escolha documentada). Frames malformados respondem
//!   `67 00` (`SW_WRONG_LENGTH`).
//! - Entrega de resposta com `Le` grande sai inline (sem encadeamento
//!   `61 XX` enquanto o payload couber em `Le`). O roteador nunca emite
//!   `6C XX`: excesso sobre `Le` continua trilhando por `61 XX` +
//!   GET RESPONSE também na forma estendida (escolha documentada).
//! - CLA não é validado no roteador (CTAP2 usa `0x80`, OATH usa `0x00`);
//!   validação fica a cargo dos applets.
//!
//! Os tipos legados [`ApduCommand`](crate::embedded::ApduCommand) e
//! [`ApduResponse`](crate::embedded::ApduResponse) continuam disponíveis para
//! os usuários existentes ([`FramedCcidTransport`](crate::framed_ccid)); este
//! módulo os supersede para roteamento.

use alloc::vec::Vec;

// --- Status Words (ISO/IEC 7816-4, §5.1.3) ----------------------------------

/// Processamento bem-sucedido.
pub const SW_NO_ERROR: u16 = 0x9000;
/// Arquivo/aplicação não encontrada (AID desconhecido no SELECT).
pub const SW_FILE_NOT_FOUND: u16 = 0x6A82;
/// Instruction code (INS) não suportado ou inválido.
pub const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;
/// Parâmetros P1/P2 incorretos.
pub const SW_WRONG_P1_P2: u16 = 0x6B00;
/// Comprimento inválido (Lc/Le inconsistentes com a forma curta).
pub const SW_WRONG_LENGTH: u16 = 0x6700;
/// Condições de uso não satisfeitas (ex.: GET RESPONSE fora de sequência).
pub const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
/// Estado de segurança não satisfeito (ex.: autenticação exigida).
pub const SW_SECURITY_STATUS: u16 = 0x6982;

/// Base do Status Word "mais dados disponíveis" (`61 XX`).
const SW_MORE_DATA_BASE: u16 = 0x6100;

/// Constrói `61 XX`: indica `remaining` bytes adicionais recuperáveis via
/// GET RESPONSE. `remaining > 255` codifica como `61 00`.
#[must_use]
pub const fn sw_more_data(remaining: usize) -> u16 {
    if remaining > 255 {
        SW_MORE_DATA_BASE
    } else {
        SW_MORE_DATA_BASE | remaining as u16
    }
}

/// Indica se `sw` é um Status Word `61 XX` ("mais dados disponíveis").
#[must_use]
pub const fn is_more_data(sw: u16) -> bool {
    sw & 0xFF00 == SW_MORE_DATA_BASE
}

// --- Instruções tratadas pelo próprio roteador -------------------------------

/// SELECT (seleção de aplicação por AID).
pub const INS_SELECT: u8 = 0xA4;
/// GET RESPONSE (recupera trecho pendente de resposta encadeada).
pub const INS_GET_RESPONSE: u8 = 0xC0;

/// Le máximo na forma curta (`00` codifica 256).
const LE_MAX: usize = 256;

/// Le máximo na forma estendida (`00 00` codifica 65536).
const LE_MAX_EXTENDED: usize = 65_536;

// --- Parsing de APDU ----------------------------------------------------------

/// Erros de parsing de APDU (forma curta ou estendida).
///
/// No roteador todos são mapeados para [`SW_WRONG_LENGTH`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApduParseError {
    /// Frame com menos de 4 bytes (cabeçalho CLA INS P1 P2 incompleto).
    TooShort,
    /// Lc declara mais bytes de dados do que o frame contém.
    TruncatedBody,
    /// Bytes excedentes após o Le (ou entre dados e Le na forma estendida).
    TrailingBytes,
}

/// APDU de comando decodificada (dados emprestados do buffer original,
/// zero-cópia, sem alocação).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Apdu<'a> {
    /// Class byte (CLA).
    pub cla: u8,
    /// Instruction byte (INS).
    pub ins: u8,
    /// Parameter 1 (P1).
    pub p1: u8,
    /// Parameter 2 (P2).
    pub p2: u8,
    /// Command data (campo Lc), vazio nos casos 1, 2S e 2E.
    pub data: &'a [u8],
    /// Expected length (Le); `None` quando ausente. `Some(256)` para `00`
    /// na forma curta; `Some(65536)` para `0000` na forma estendida.
    pub le: Option<usize>,
}

impl<'a> Apdu<'a> {
    /// Decodifica uma APDU em forma curta ou estendida:
    ///
    /// | Caso | Layout                                        |
    /// |------|-----------------------------------------------|
    /// | 1    | `CLA INS P1 P2`                               |
    /// | 2S   | `CLA INS P1 P2 Le`                            |
    /// | 3S   | `CLA INS P1 P2 Lc data`                       |
    /// | 4S   | `CLA INS P1 P2 Lc data Le`                    |
    /// | 2E   | `CLA INS P1 P2 00 LeHi LeLo`                  |
    /// | 3E   | `CLA INS P1 P2 00 LcHi LcLo data`             |
    /// | 4E   | `CLA INS P1 P2 00 LcHi LcLo data LeHi LeLo`   |
    ///
    /// `Le = 00` (curta) significa 256; `Le = 0000` (estendida) significa
    /// 65536. Um frame de 5 bytes é sempre caso 2S (ambiguidade com
    /// 3S/Lc=0 resolvida pela ISO); 6 bytes com byte 5 nulo é 4S com Lc
    /// vazio; 7 bytes com byte 5 nulo é 2E puro (ver escolha documentada
    /// no topo do módulo).
    pub fn parse(raw: &'a [u8]) -> Result<Self, ApduParseError> {
        if raw.len() < 4 {
            return Err(ApduParseError::TooShort);
        }
        let cla = raw[0];
        let ins = raw[1];
        let p1 = raw[2];
        let p2 = raw[3];

        // Caso 1: só o cabeçalho.
        if raw.len() == 4 {
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: &[],
                le: None,
            });
        }

        // Caso 2S: cabeçalho + Le (5º byte é Le, não Lc).
        if raw.len() == 5 {
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: &[],
                le: Some(le_from_byte(raw[4])),
            });
        }

        // Byte 5 = 0x00 abre a forma estendida (Lc/Le precedidos de 0x00).
        // Exceção curta: 6 bytes é o caso 4S com Lc vazio (cabeçalho +
        // Lc=0 + Le de 1 byte).
        if raw[4] == 0 {
            if raw.len() == 6 {
                return Ok(Self {
                    cla,
                    ins,
                    p1,
                    p2,
                    data: &[],
                    le: Some(le_from_byte(raw[5])),
                });
            }
            if raw.len() == 7 {
                // Caso 2E puro: cabeçalho + 00 + Le de 2 bytes — o layout
                // do ExtendedApduFormatter do python-yubikit para comando
                // sem dados com Le > 0.
                return Ok(Self {
                    cla,
                    ins,
                    p1,
                    p2,
                    data: &[],
                    le: Some(le_from_pair(raw[5], raw[6])),
                });
            }
            // Casos 3E/4E: 00 + Lc de 2 bytes + dados (+ Le opcional de
            // 2 bytes). Lc cabe em u16, logo `7 + lc` nunca estoura usize.
            let lc = ((raw[5] as usize) << 8) | raw[6] as usize;
            if raw.len() < 7 + lc {
                return Err(ApduParseError::TruncatedBody);
            }
            let data = &raw[7..7 + lc];
            return match raw.len() - (7 + lc) {
                0 => Ok(Self {
                    cla,
                    ins,
                    p1,
                    p2,
                    data,
                    le: None,
                }),
                2 => Ok(Self {
                    cla,
                    ins,
                    p1,
                    p2,
                    data,
                    le: Some(le_from_pair(raw[raw.len() - 2], raw[raw.len() - 1])),
                }),
                _ => Err(ApduParseError::TrailingBytes),
            };
        }

        let lc = raw[4] as usize;
        if raw.len() < 5 + lc {
            return Err(ApduParseError::TruncatedBody);
        }
        let data = &raw[5..5 + lc];
        match raw.len() - (5 + lc) {
            0 => Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data,
                le: None,
            }),
            1 => Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data,
                le: Some(le_from_byte(raw[5 + lc])),
            }),
            _ => Err(ApduParseError::TrailingBytes),
        }
    }
}

/// Decodifica o byte de Le (`00` = 256).
const fn le_from_byte(b: u8) -> usize {
    if b == 0 {
        LE_MAX
    } else {
        b as usize
    }
}

/// Decodifica Le estendido de 2 bytes big-endian (`00 00` = 65536).
const fn le_from_pair(hi: u8, lo: u8) -> usize {
    let value = ((hi as usize) << 8) | lo as usize;
    if value == 0 {
        LE_MAX_EXTENDED
    } else {
        value
    }
}

// --- Applets ------------------------------------------------------------------

/// Resposta de um applet: dados + Status Word opcional.
///
/// `sw = None` equivale a [`SW_NO_ERROR`] após a entrega dos dados.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseData {
    /// Payload da resposta (antes dos Status Words).
    pub data: Vec<u8>,
    /// Status Word explícita; `None` → [`SW_NO_ERROR`].
    pub sw: Option<u16>,
}

impl ResponseData {
    /// Resposta bem-sucedida com dados (SW implícito `9000`).
    #[must_use]
    pub fn ok(data: Vec<u8>) -> Self {
        Self { data, sw: None }
    }

    /// Resposta com Status Word explícita (ex.: aviso com dados).
    #[must_use]
    pub fn with_sw(data: Vec<u8>, sw: u16) -> Self {
        Self { data, sw: Some(sw) }
    }

    /// Serializa como `[DATA | SW1 | SW2]` (formato trocado no XfrBlock).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.data.len() + 2);
        out.extend_from_slice(&self.data);
        out.extend_from_slice(&self.sw.unwrap_or(SW_NO_ERROR).to_be_bytes());
        out
    }
}

impl From<Vec<u8>> for ResponseData {
    fn from(data: Vec<u8>) -> Self {
        Self::ok(data)
    }
}

/// Contrato de uma aplicação cardíaca plugável no [`CardRouter`].
pub trait Applet {
    /// Application Identifier deste applet (5–16 bytes por ISO 7816-5).
    fn aid(&self) -> &[u8];

    /// Seleção bem-sucedida. `Err(sw)` recusa a seleção (o roteador responde
    /// `sw` e preserva a seleção anterior).
    fn select(&mut self) -> Result<(), u16>;

    /// Payload opcional da resposta de seleção (após `select() == Ok`).
    ///
    /// Padrão: vazio. Applets que precisam devolver dados no SELECT AID
    /// (ex.: OATH retorna versão/ID/desafio) sobrescrevem este método; o
    /// roteador anexa o payload ao `9000` da seleção. Limitação registrada:
    /// a resposta de seleção sai sempre inline, sem encadeamento `61 XX`.
    fn select_response(&mut self) -> Vec<u8> {
        Vec::new()
    }

    /// Processa um comando já roteado para este applet.
    ///
    /// `Err(sw)` produz resposta vazia com a Status Word indicada.
    fn process(&mut self, apdu: &Apdu) -> Result<ResponseData, u16>;
}

// --- Roteador -----------------------------------------------------------------

/// Estado de uma resposta encadeada aguardando consumo via GET RESPONSE.
struct ChainState {
    buf: Vec<u8>,
    pos: usize,
    /// SW entregue junto do último byte (normalmente `9000` ou override).
    final_sw: u16,
}

/// Roteador ISO 7816-4: registra applets, trata SELECT e distribui APDUs ao
/// applet selecionado, incluindo o fluxo `61 XX`/GET RESPONSE.
///
/// Lógica pura e determinística: cada [`Self::process`] consome exatamente um
/// comando e produz exatamente uma resposta `data + SW`.
pub struct CardRouter<'a> {
    applets: Vec<&'a mut dyn Applet>,
    selected: Option<usize>,
    chain: Option<ChainState>,
}

impl Default for CardRouter<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> CardRouter<'a> {
    /// Cria um roteador vazio (nenhum applet registrado, nada selecionado).
    #[must_use]
    pub fn new() -> Self {
        Self {
            applets: Vec::new(),
            selected: None,
            chain: None,
        }
    }

    /// Registra um applet. A ordem de registro define prioridade entre
    /// prefixos de mesmo comprimento (primeiro registrado vence).
    pub fn register(&mut self, applet: &'a mut dyn Applet) {
        self.applets.push(applet);
    }

    /// AID do applet corrente, se houver seleção ativa.
    #[must_use]
    pub fn selected_aid(&self) -> Option<&[u8]> {
        self.selected.map(|idx| self.applets[idx].aid())
    }

    /// Indica se existe resposta encadeada pendente de GET RESPONSE.
    #[must_use]
    pub fn is_chain_pending(&self) -> bool {
        self.chain.is_some()
    }

    /// Processa uma APDU bruta e devolve a resposta (`data + SW`).
    ///
    /// Nunca falha: erros de protocolo viram Status Words.
    pub fn process(&mut self, raw: &[u8]) -> ResponseData {
        let apdu = match Apdu::parse(raw) {
            Ok(a) => a,
            Err(_) => return ResponseData::with_sw(Vec::new(), SW_WRONG_LENGTH),
        };

        // GET RESPONSE é transporte do próprio roteador, independe de seleção.
        if apdu.ins == INS_GET_RESPONSE {
            return self.serve_get_response(apdu.le);
        }

        // Qualquer outro comando descarta encadeamento pendente.
        if self.chain.take().is_some() {
            // escolha documentada: nova cadeia de comandos invalida a antiga
        }

        if apdu.ins == INS_SELECT {
            return self.handle_select(&apdu);
        }

        match self.selected {
            Some(idx) => {
                let resp = match self.applets[idx].process(&apdu) {
                    Ok(r) => r,
                    Err(sw) => ResponseData::with_sw(Vec::new(), sw),
                };
                self.deliver(resp, apdu.le)
            }
            // Sem seleção: "INS não suportado" (escolha documentada no topo).
            None => ResponseData::with_sw(Vec::new(), SW_INS_NOT_SUPPORTED),
        }
    }

    /// Trata SELECT: casa o AID requisitado contra os applets registrados
    /// (exato primeiro; senão o applet cujo AID começa com o requisitado e é
    /// o mais longo) e executa a seleção.
    fn handle_select(&mut self, apdu: &Apdu) -> ResponseData {
        let requested = apdu.data;
        if requested.is_empty() {
            return ResponseData::with_sw(Vec::new(), SW_FILE_NOT_FOUND);
        }

        let mut best: Option<usize> = None;
        let mut best_len = 0usize;
        for (idx, applet) in self.applets.iter().enumerate() {
            let aid = applet.aid();
            if aid == requested {
                // Correspondência exata vence imediatamente.
                best = Some(idx);
                break;
            }
            if aid.starts_with(requested) && aid.len() > best_len {
                best = Some(idx);
                best_len = aid.len();
            }
        }

        let idx = match best {
            Some(idx) => idx,
            // AID desconhecido: erro sem alterar a seleção corrente.
            None => return ResponseData::with_sw(Vec::new(), SW_FILE_NOT_FOUND),
        };

        match self.applets[idx].select() {
            Ok(()) => {
                self.selected = Some(idx);
                // Payload opcional do applet (ex.: TLVs de versão/desafio do
                // OATH) sai junto do 9000; vazio por padrão.
                let data = self.applets[idx].select_response();
                ResponseData::with_sw(data, SW_NO_ERROR)
            }
            Err(sw) => ResponseData::with_sw(Vec::new(), sw),
        }
    }

    /// Entrega a resposta do applet: tudo inline quando cabe em `le`; senão
    /// o trecho cabível + `61 XX` com o restante retido para GET RESPONSE.
    ///
    /// Sem Le (caso 1/3) nada é entregue inline: a resposta inteira vai para
    /// o encadeamento, conforme T=0.
    fn deliver(&mut self, resp: ResponseData, le: Option<usize>) -> ResponseData {
        let sw = resp.sw.unwrap_or(SW_NO_ERROR);
        if resp.data.is_empty() {
            return ResponseData::with_sw(Vec::new(), sw);
        }
        let limit = le.unwrap_or(0);
        if resp.data.len() <= limit {
            return ResponseData {
                data: resp.data,
                sw: Some(sw),
            };
        }

        let chunk = resp.data[..limit].to_vec();
        let remaining = resp.data.len() - limit;
        self.chain = Some(ChainState {
            buf: resp.data,
            pos: limit,
            final_sw: sw,
        });
        ResponseData::with_sw(chunk, sw_more_data(remaining))
    }

    /// Serve um trecho da resposta encadeada; o último trecho carrega o SW
    /// final, os intermediários carregam `61 XX` atualizado.
    fn serve_get_response(&mut self, le: Option<usize>) -> ResponseData {
        let chain = match self.chain.take() {
            Some(c) => c,
            // GET RESPONSE sem `61 XX` prévio (escolha documentada no topo).
            None => {
                return ResponseData::with_sw(Vec::new(), SW_CONDITIONS_NOT_SATISFIED);
            }
        };
        let effective_le = le.unwrap_or(LE_MAX);
        let remaining = chain.buf.len() - chain.pos;
        let n = core::cmp::min(effective_le, remaining);
        let chunk = chain.buf[chain.pos..chain.pos + n].to_vec();
        let new_pos = chain.pos + n;

        if new_pos == chain.buf.len() {
            return ResponseData {
                data: chunk,
                sw: Some(chain.final_sw),
            };
        }
        let left = chain.buf.len() - new_pos;
        self.chain = Some(ChainState {
            pos: new_pos,
            ..chain
        });
        ResponseData::with_sw(chunk, sw_more_data(left))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    use std::rc::Rc;

    /// Log de INS compartilhado entre applet e teste.
    type Log = Rc<RefCell<Vec<u8>>>;

    /// Applet de teste com handler injetável e registro dos INS recebidos.
    ///
    /// O log de INS é compartilhado via `Rc<RefCell<...>>` para que os testes
    /// possam verificar o roteamento depois que o applet for movido (leaked)
    /// para dentro do roteador.
    struct MockApplet {
        aid: Vec<u8>,
        select_result: Result<(), u16>,
        /// Payload devolvido por [`Applet::select_response`] (padrão vazio).
        select_payload: Vec<u8>,
        handler: Box<dyn FnMut(&Apdu) -> Result<ResponseData, u16>>,
        seen_ins: Rc<RefCell<Vec<u8>>>,
    }

    impl MockApplet {
        fn new(
            aid: &[u8],
            handler: impl FnMut(&Apdu) -> Result<ResponseData, u16> + 'static,
        ) -> Self {
            Self {
                aid: aid.to_vec(),
                select_result: Ok(()),
                select_payload: Vec::new(),
                handler: Box::new(handler),
                seen_ins: Rc::new(RefCell::new(Vec::new())),
            }
        }

        fn failing_select(mut self, sw: u16) -> Self {
            self.select_result = Err(sw);
            self
        }

        fn log_handle(&self) -> Log {
            self.seen_ins.clone()
        }
    }

    impl Applet for MockApplet {
        fn aid(&self) -> &[u8] {
            &self.aid
        }

        fn select(&mut self) -> Result<(), u16> {
            self.select_result
        }

        fn select_response(&mut self) -> Vec<u8> {
            self.select_payload.clone()
        }

        fn process(&mut self, apdu: &Apdu) -> Result<ResponseData, u16> {
            self.seen_ins.borrow_mut().push(apdu.ins);
            (self.handler)(apdu)
        }
    }

    // --- builders de APDU ---

    fn apdu_case1(cla: u8, ins: u8) -> Vec<u8> {
        vec![cla, ins, 0x00, 0x00]
    }

    fn apdu_case2(cla: u8, ins: u8, le: u8) -> Vec<u8> {
        vec![cla, ins, 0x00, 0x00, le]
    }

    fn apdu_case3(cla: u8, ins: u8, data: &[u8]) -> Vec<u8> {
        let mut v = vec![cla, ins, 0x00, 0x00, data.len() as u8];
        v.extend_from_slice(data);
        v
    }

    fn apdu_case4(cla: u8, ins: u8, data: &[u8], le: u8) -> Vec<u8> {
        let mut v = apdu_case3(cla, ins, data);
        v.push(le);
        v
    }

    fn select(aid: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, INS_SELECT, 0x04, 0x00];
        v.push(aid.len() as u8);
        v.extend_from_slice(aid);
        v
    }

    fn get_response(le: Option<u8>) -> Vec<u8> {
        let mut v = vec![0x00, INS_GET_RESPONSE, 0x00, 0x00];
        if let Some(b) = le {
            v.push(b);
        }
        v
    }

    /// Casos 3E/4E (ExtendedApduFormatter do python-yubikit):
    /// `[hdr][00 LcHi LcLo][dados]` + `LeHi LeLo` quando `le` é `Some`.
    fn apdu_case3e_4e(cla: u8, ins: u8, data: &[u8], le: Option<u16>) -> Vec<u8> {
        let mut v = vec![cla, ins, 0x00, 0x00, 0x00];
        v.extend_from_slice(&(data.len() as u16).to_be_bytes());
        v.extend_from_slice(data);
        if let Some(le) = le {
            v.extend_from_slice(&le.to_be_bytes());
        }
        v
    }

    /// Caso 2E puro: `[hdr][00][LeHi LeLo]` — comando sem dados e com Le.
    fn apdu_case2e(cla: u8, ins: u8, le: u16) -> Vec<u8> {
        let mut v = vec![cla, ins, 0x00, 0x00, 0x00];
        v.extend_from_slice(&le.to_be_bytes());
        v
    }

    // --- parsing ---

    #[test]
    fn test_parse_short_form_cases_1_2_3_4() {
        // Caso 1.
        let a = Apdu::parse(&[0x80, 0x12, 0x01, 0x02]).unwrap();
        assert_eq!(a.ins, 0x12);
        assert!(a.data.is_empty());
        assert_eq!(a.le, None);

        // Caso 3S.
        let raw = [0x00, 0xA4, 0x04, 0x00, 0x02, 0xAA, 0xBB];
        let a = Apdu::parse(&raw).unwrap();
        assert_eq!(a.data, &[0xAA, 0xBB]);
        assert_eq!(a.le, None);

        // Caso 4S.
        let raw = [0x00, 0x10, 0x00, 0x00, 0x01, 0xCC, 0x40];
        let a = Apdu::parse(&raw).unwrap();
        assert_eq!(a.data, &[0xCC]);
        assert_eq!(a.le, Some(64));
    }

    #[test]
    fn test_parse_le_zero_means_256() {
        let raw = apdu_case2(0x00, 0xC0, 0x00);
        let a = Apdu::parse(&raw).unwrap();
        assert_eq!(a.le, Some(256));

        let raw = [0x00, 0x10, 0x00, 0x00, 0x01, 0xDD, 0x00];
        let a = Apdu::parse(&raw).unwrap();
        assert_eq!(a.le, Some(256));
    }

    #[test]
    fn test_parse_rejects_truncated_frames() {
        // Cabeçalho incompleto.
        assert_eq!(Apdu::parse(&[0x00, 0xA4]), Err(ApduParseError::TooShort));
        // Lc declara 10 bytes mas só 2 chegaram.
        assert_eq!(
            Apdu::parse(&[0x00, 0xA4, 0x04, 0x00, 10, 1, 2]),
            Err(ApduParseError::TruncatedBody)
        );
        // Forma estendida truncada (Lc estendido = 0x0100, corpo insuficiente).
        assert_eq!(
            Apdu::parse(&[0x80, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0xAA]),
            Err(ApduParseError::TruncatedBody)
        );
        // Bytes excedentes depois do Le.
        assert_eq!(
            Apdu::parse(&[0x00, 0x10, 0x00, 0x00, 0x01, 0xCC, 0x40, 0xFF]),
            Err(ApduParseError::TrailingBytes)
        );
    }

    // --- parsing da forma estendida ---

    #[test]
    fn test_parse_extended_case_3e_and_4e_like_yubikit_formatter() {
        // Caso 3E (dados sem Le — PUT do yubikit com le=0).
        let data: Vec<u8> = (0..300).map(|i| i as u8).collect();
        let raw = apdu_case3e_4e(0x80, 0x01, &data, None);
        assert_eq!(raw.len(), 7 + data.len());
        let a = Apdu::parse(&raw).unwrap();
        assert_eq!(a.data, &data[..]);
        assert_eq!(a.le, None);

        // Caso 4E completo (dados + Le de 2 bytes).
        let raw = apdu_case3e_4e(0x00, 0x05, b"abc", Some(0x0100));
        let a = Apdu::parse(&raw).unwrap();
        assert_eq!(a.data, b"abc");
        assert_eq!(a.le, Some(256));
    }

    #[test]
    fn test_parse_extended_case_2e_le_only_seven_bytes() {
        // Frame exato do ExtendedApduFormatter para le=256 sem dados.
        let raw = apdu_case2e(0x00, INS_GET_RESPONSE, 0x0100);
        let a = Apdu::parse(&raw).unwrap();
        assert!(a.data.is_empty());
        assert_eq!(a.le, Some(256));

        // Le = 0000 significa 65536.
        let raw = apdu_case2e(0x00, INS_GET_RESPONSE, 0x0000);
        let a = Apdu::parse(&raw).unwrap();
        assert_eq!(a.le, Some(65_536));

        // Variante legado (yubikit antigo): Lc estendido explícito `0000`
        // seguido do Le — mesmo significado do 2E puro.
        let legacy = [0x00u8, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
        let a = Apdu::parse(&legacy).unwrap();
        assert!(a.data.is_empty());
        assert_eq!(a.le, Some(256));
    }

    #[test]
    fn test_parse_extended_le_zero_means_65536_in_case_4e() {
        let raw = apdu_case3e_4e(0x80, 0x10, &[0xAA], Some(0));
        let a = Apdu::parse(&raw).unwrap();
        assert_eq!(a.data, &[0xAA]);
        assert_eq!(a.le, Some(65_536));
    }

    #[test]
    fn test_parse_extended_rejects_truncated_body_and_stray_trailing() {
        // Lc estendido declara 0x0100 mas só 1 byte chegou.
        assert_eq!(
            Apdu::parse(&[0x80, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0xAA]),
            Err(ApduParseError::TruncatedBody)
        );
        // 4E com byte extra além do Le.
        let mut raw = apdu_case3e_4e(0x80, 0x10, &[0xAA], Some(1));
        raw.push(0xFF);
        assert_eq!(Apdu::parse(&raw), Err(ApduParseError::TrailingBytes));
        // 3E com sobra ímpar (nem 0 nem 2 bytes após os dados).
        let mut raw = apdu_case3e_4e(0x80, 0x10, &[0xBB], None);
        raw.push(0xFF);
        assert_eq!(Apdu::parse(&raw), Err(ApduParseError::TrailingBytes));
    }

    // --- SELECT e roteamento ---

    const AID_A: &[u8] = &[0xA0, 0x00, 0x00, 0x06, 0x47]; // RID FIDO (parcial)
    const AID_B: &[u8] = &[0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]; // OATH

    fn router_with_two_applets() -> (CardRouter<'static>, Log, Log) {
        let a = Box::leak(Box::new(MockApplet::new(AID_A, |_| {
            Ok(ResponseData::ok(b"resp-a".to_vec()))
        })));
        let b = Box::leak(Box::new(MockApplet::new(AID_B, |_| {
            Ok(ResponseData::ok(b"resp-b".to_vec()))
        })));
        let log_a = a.log_handle();
        let log_b = b.log_handle();
        let mut router = CardRouter::new();
        router.register(a);
        router.register(b);
        (router, log_a, log_b)
    }

    #[test]
    fn test_select_unknown_aid_returns_file_not_found() {
        let (mut router, _a, _b) = router_with_two_applets();
        let resp = router.process(&select(&[0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(resp.sw, Some(SW_FILE_NOT_FOUND));
        assert!(resp.data.is_empty());
        assert_eq!(router.selected_aid(), None);
    }

    #[test]
    fn test_select_exact_match_wins_over_longer_prefix_applet() {
        // Dois applets onde o AID de um é prefixo do outro; o pedido exato do
        // menor deve selecionar o menor, não o mais longo.
        let full = Box::leak(Box::new(MockApplet::new(
            &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01],
            |_| Ok(ResponseData::ok(Vec::new())),
        )));
        let short = Box::leak(Box::new(MockApplet::new(AID_A, |_| {
            Ok(ResponseData::ok(Vec::new()))
        })));
        let mut router = CardRouter::new();
        router.register(full);
        router.register(short);

        let resp = router.process(&select(AID_A));
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        assert_eq!(router.selected_aid(), Some(AID_A));
    }

    #[test]
    fn test_select_partial_prefix_matches_longest_applet() {
        let full = Box::leak(Box::new(MockApplet::new(
            &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01],
            |_| Ok(ResponseData::ok(Vec::new())),
        )));
        let short = Box::leak(Box::new(MockApplet::new(AID_A, |_| {
            Ok(ResponseData::ok(Vec::new()))
        })));
        let mut router = CardRouter::new();
        router.register(short);
        router.register(full);

        // Prefixo parcial casa com ambos: vence o AID mais longo.
        let resp = router.process(&select(&AID_A[..3]));
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        assert_eq!(
            router.selected_aid(),
            Some(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01][..])
        );
    }

    #[test]
    fn test_commands_route_to_selected_applet_only() {
        let (mut router, log_a, log_b) = router_with_two_applets();

        // Antes de qualquer SELECT: nada é roteado.
        let resp = router.process(&apdu_case1(0x00, 0x10));
        assert_eq!(resp.sw, Some(SW_INS_NOT_SUPPORTED));
        assert!(log_a.borrow().is_empty());
        assert!(log_b.borrow().is_empty());

        // SELECT B → comando vai para B, não para A.
        assert_eq!(router.process(&select(AID_B)).sw, Some(SW_NO_ERROR));
        // Caso 4 com Le folgado: resposta do applet sai inline.
        let resp = router.process(&apdu_case4(0x00, 0x20, &[], 16));
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        assert_eq!(&resp.data, b"resp-b");
        assert!(log_a.borrow().is_empty());
        assert_eq!(*log_b.borrow(), vec![0x20]);

        // Re-SELECT A → próximos comandos vão para A.
        assert_eq!(router.process(&select(AID_A)).sw, Some(SW_NO_ERROR));
        let resp = router.process(&apdu_case4(0x00, 0x30, &[], 16));
        assert_eq!(&resp.data, b"resp-a");
        assert_eq!(*log_b.borrow(), vec![0x20]);
        assert_eq!(*log_a.borrow(), vec![0x30]);
        assert_eq!(router.selected_aid(), Some(AID_A));
    }

    #[test]
    fn test_applet_select_response_data_is_returned() {
        // Applet com payload de seleção (modelo OATH: versão + ID no SELECT).
        let applet = Box::leak(Box::new(MockApplet::new(AID_A, |_| {
            Ok(ResponseData::ok(Vec::new()))
        })));
        applet.select_payload = vec![0x79, 0x03, 0x05, 0x04, 0x00];
        let mut router = CardRouter::new();
        router.register(applet);

        let resp = router.process(&select(AID_A));
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        assert_eq!(resp.data, vec![0x79, 0x03, 0x05, 0x04, 0x00]);
    }

    #[test]
    fn test_failed_select_keeps_previous_selection() {
        let ok = Box::leak(Box::new(MockApplet::new(AID_A, |_| {
            Ok(ResponseData::ok(Vec::new()))
        })));
        let refusing = Box::leak(Box::new(
            MockApplet::new(AID_B, |_| Ok(ResponseData::ok(Vec::new())))
                .failing_select(SW_CONDITIONS_NOT_SATISFIED),
        ));
        let log_ok = ok.log_handle();
        let mut router = CardRouter::new();
        router.register(ok);
        router.register(refusing);

        assert_eq!(router.process(&select(AID_A)).sw, Some(SW_NO_ERROR));
        // SELECT recusado responde o SW do applet...
        let resp = router.process(&select(AID_B));
        assert_eq!(resp.sw, Some(SW_CONDITIONS_NOT_SATISFIED));
        // ...e a seleção anterior permanece ativa.
        assert_eq!(router.selected_aid(), Some(AID_A));
        assert_eq!(
            router.process(&apdu_case1(0x00, 0x11)).sw,
            Some(SW_NO_ERROR)
        );
        assert_eq!(*log_ok.borrow(), vec![0x11]);
    }

    // --- encadeamento (61 XX / GET RESPONSE) ---

    #[test]
    fn test_chaining_splits_large_response_across_get_response() {
        let payload: Vec<u8> = (0..700).map(|i| i as u8).collect();
        let applet = Box::leak(Box::new(MockApplet::new(AID_A, move |_| {
            Ok(ResponseData::ok(payload.clone()))
        })));
        let mut router = CardRouter::new();
        router.register(applet);
        router.process(&select(AID_A));

        // Caso 3 (sem Le): nada sai inline; tudo vira encadeamento.
        let resp = router.process(&apdu_case1(0x80, 0x10));
        assert!(resp.data.is_empty());
        assert_eq!(resp.sw, Some(sw_more_data(700)));
        assert!(router.is_chain_pending());

        // GET RESPONSE Le=0 (=256): primeiro trecho cheio, ainda restam 444.
        let resp = router.process(&get_response(Some(0x00)));
        assert_eq!(resp.data.len(), 256);
        assert_eq!(resp.sw, Some(sw_more_data(444)));

        // GET RESPONSE sem Le (=256): restam 188.
        let resp = router.process(&get_response(None));
        assert_eq!(resp.data.len(), 256);
        assert_eq!(resp.sw, Some(0x61BC)); // 188 restantes

        // Último trecho traz o SW final 9000.
        let resp = router.process(&get_response(None));
        assert_eq!(resp.data.len(), 188);
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        assert!(!router.is_chain_pending());
    }

    #[test]
    fn test_chaining_honours_initial_le_limit() {
        let payload: Vec<u8> = (0..300).map(|i| i as u8).collect();
        let expected = payload.clone();
        let applet = Box::leak(Box::new(MockApplet::new(AID_A, move |_| {
            Ok(ResponseData::ok(payload.clone()))
        })));
        let mut router = CardRouter::new();
        router.register(applet);
        router.process(&select(AID_A));

        // Caso 4 com Le=100: 100 bytes inline + 61 C8 (200 restantes).
        let resp = router.process(&apdu_case4(0x80, 0x10, &[], 100));
        assert_eq!(resp.data, expected[..100]);
        assert_eq!(resp.sw, Some(0x61C8));

        // Host pede os 200 finais de uma vez.
        let resp = router.process(&get_response(Some(200)));
        assert_eq!(resp.data, expected[100..]);
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        assert!(!router.is_chain_pending());
    }

    #[test]
    fn test_extended_select_and_large_le_delivers_inline_without_chaining() {
        let payload: Vec<u8> = (0..700).map(|i| i as u8).collect();
        let applet = Box::leak(Box::new(MockApplet::new(AID_A, move |_| {
            Ok(ResponseData::ok(payload.clone()))
        })));
        let mut router = CardRouter::new();
        router.register(applet);

        // SELECT pela forma estendida (caso 3E do ExtendedApduFormatter:
        // AID como dado, sem Le).
        let select_e = apdu_case3e_4e(0x00, INS_SELECT, AID_A, None);
        assert_eq!(router.process(&select_e).sw, Some(SW_NO_ERROR));
        assert_eq!(router.selected_aid(), Some(AID_A));

        // Comando 4E com Le = 0000 (=65536): payload inteiro sai inline,
        // sem encadeamento `61 XX`.
        let resp = router.process(&apdu_case3e_4e(0x80, 0x10, &[], Some(0)));
        assert_eq!(resp.data.len(), 700);
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        assert!(!router.is_chain_pending());

        // Le estendido menor que o payload preserva o encadeamento.
        let resp = router.process(&apdu_case3e_4e(0x80, 0x10, &[], Some(512)));
        assert_eq!(resp.data.len(), 512);
        assert_eq!(resp.sw, Some(sw_more_data(188)));
        assert!(router.is_chain_pending());

        // Dreno final via GET RESPONSE na forma estendida (caso 2E com
        // Le = 0000 → 65536): restante inteiro + SW final.
        let resp = router.process(&apdu_case2e(0x00, INS_GET_RESPONSE, 0x0000));
        assert_eq!(resp.data.len(), 188);
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        assert!(!router.is_chain_pending());
    }

    #[test]
    fn test_mixed_short_and_extended_forms_on_same_session() {
        let (mut router, log_a, log_b) = router_with_two_applets();

        // SELECT na forma curta...
        assert_eq!(router.process(&select(AID_A)).sw, Some(SW_NO_ERROR));
        // ...comando curto (caso 4S)...
        let resp = router.process(&apdu_case4(0x00, 0x20, &[], 16));
        assert_eq!(&resp.data, b"resp-a");
        // ...re-seleção na forma estendida (3E)...
        let resp = router.process(&apdu_case3e_4e(0x00, INS_SELECT, AID_B, None));
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        // ...e comando estendido com Le explícito entregando inline.
        let resp = router.process(&apdu_case3e_4e(0x00, 0x30, &[], Some(16)));
        assert_eq!(&resp.data, b"resp-b");
        assert_eq!(*log_a.borrow(), vec![0x20]);
        assert_eq!(*log_b.borrow(), vec![0x30]);

        // GET RESPONSE estendido sem cadeia pendente segue respondendo 6985.
        let resp = router.process(&apdu_case2e(0x00, INS_GET_RESPONSE, 1));
        assert_eq!(resp.sw, Some(SW_CONDITIONS_NOT_SATISFIED));

        // Frame estendido malformado continua virando 6700 no roteador.
        let resp = router.process(&[0x80, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0xAA]);
        assert_eq!(resp.sw, Some(SW_WRONG_LENGTH));
    }

    #[test]
    fn test_get_response_without_pending_chain_returns_conditions_not_satisfied() {
        let (mut router, _a, _b) = router_with_two_applets();
        let resp = router.process(&get_response(None));
        assert_eq!(resp.sw, Some(SW_CONDITIONS_NOT_SATISFIED));
        assert!(resp.data.is_empty());
    }

    #[test]
    fn test_non_get_response_command_discards_pending_chain() {
        let payload: Vec<u8> = vec![0xEE; 300];
        let applet = Box::leak(Box::new(MockApplet::new(AID_A, move |_| {
            Ok(ResponseData::ok(payload.clone()))
        })));
        let mut router = CardRouter::new();
        router.register(applet);
        router.process(&select(AID_A));

        // Inicia um encadeamento e abandona-o no meio.
        let resp = router.process(&apdu_case1(0x80, 0x10));
        assert_eq!(resp.sw, Some(sw_more_data(300)));
        let resp = router.process(&get_response(Some(50)));
        assert_eq!(resp.data.len(), 50);

        // Um comando comum invalida a cadeia pendente...
        let resp = router.process(&apdu_case1(0x80, 0x20));
        assert_eq!(resp.sw, Some(sw_more_data(300)));
        // ...e GET RESPONSE subsequente não vê mais a cadeia antiga.
        assert!(router.is_chain_pending()); // nova cadeia do INS 0x20
        let resp = router.process(&get_response(None));
        assert_eq!(resp.data.len(), 256);

        // Cadeia totalmente consumida; novo comando reinicia limpo.
        let resp = router.process(&get_response(None));
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        let resp = router.process(&get_response(None));
        assert_eq!(resp.sw, Some(SW_CONDITIONS_NOT_SATISFIED));
    }

    // --- erros e overrides ---

    #[test]
    fn test_malformed_apdu_returns_wrong_length() {
        let (mut router, _a, _b) = router_with_two_applets();
        let resp = router.process(&[0x00, 0xA4, 0x04, 0x00, 0x08, 0x01]); // Lc truncado
        assert_eq!(resp.sw, Some(SW_WRONG_LENGTH));
        let resp = router.process(&[0x80, 0x10, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00]); // extended
        assert_eq!(resp.sw, Some(SW_WRONG_LENGTH));
    }

    #[test]
    fn test_applet_error_status_word_is_returned() {
        let applet = Box::leak(Box::new(MockApplet::new(AID_A, |_| {
            Err(SW_SECURITY_STATUS)
        })));
        let mut router = CardRouter::new();
        router.register(applet);
        router.process(&select(AID_A));

        let resp = router.process(&apdu_case1(0x00, 0x10));
        assert_eq!(resp.sw, Some(SW_SECURITY_STATUS));
        assert!(resp.data.is_empty());
    }

    #[test]
    fn test_sw_override_passthrough_with_small_payload() {
        let applet = Box::leak(Box::new(MockApplet::new(AID_A, |_| {
            Ok(ResponseData::with_sw(vec![0x01, 0x02], 0x63C1))
        })));
        let mut router = CardRouter::new();
        router.register(applet);
        router.process(&select(AID_A));

        // Dados pequenos + SW override saem inline intactos.
        let resp = router.process(&apdu_case4(0x00, 0x10, &[], 255));
        assert_eq!(resp.to_bytes(), vec![0x01, 0x02, 0x63, 0xC1]);

        // Override também preserva o SW final no fim de uma cadeia.
        let applet2 = Box::leak(Box::new(MockApplet::new(AID_B, |_| {
            Ok(ResponseData::with_sw(vec![0xAA; 300], 0x63C2))
        })));
        router.register(applet2);
        router.process(&select(AID_B));
        let resp = router.process(&apdu_case1(0x00, 0x10));
        assert_eq!(resp.sw, Some(sw_more_data(300)));
        let resp = router.process(&get_response(None));
        assert_eq!(resp.data.len(), 256);
        let resp = router.process(&get_response(None));
        assert_eq!(resp.data, vec![0xAA; 44]);
        assert_eq!(resp.sw, Some(0x63C2));
    }

    #[test]
    fn test_response_data_to_bytes_encoding() {
        assert_eq!(
            ResponseData::ok(vec![1, 2]).to_bytes(),
            vec![1, 2, 0x90, 0x00]
        );
        assert_eq!(
            ResponseData::with_sw(Vec::new(), SW_FILE_NOT_FOUND).to_bytes(),
            vec![0x6A, 0x82]
        );
    }

    #[test]
    fn test_status_word_helpers() {
        assert!(is_more_data(0x6100));
        assert!(is_more_data(0x61FF));
        assert!(!is_more_data(SW_NO_ERROR));
        assert_eq!(sw_more_data(5), 0x6105);
        assert_eq!(sw_more_data(255), 0x61FF);
        assert_eq!(sw_more_data(256), 0x6100);
        assert_eq!(sw_more_data(1000), 0x6100);
    }
}
