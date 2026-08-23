//! Aplicação Yubico OATH (YKOATH) como applet ISO/IEC 7816-4.
//!
//! Implementa o protocolo YKOATH (<https://developers.yubico.com/OATH/YKOATH_Protocol.html>)
//! sobre a trait [`transport::iso7816::Applet`], permitindo que o
//! [`CardRouter`](transport::iso7816::CardRouter) atenda o AID
//! `A0000005272101` e que ferramentas oficiais da Yubico (ykman,
//! Yubico Authenticator via python-yubikit) usem o dispositivo.
//!
//! # Comandos suportados
//!
//! PUT (`0x01`), DELETE (`0x02`), SET CODE (`0x03`), RESET (`0x04`,
//! P1=0xDE P2=0xAD), RENAME (`0x05`, extensão YubiKey ≥5.3.1), LIST
//! (`0xA1`), CALCULATE (`0xA2`), VALIDATE (`0xA3`), CALCULATE ALL
//! (`0xA4`) e SEND REMAINING (`0xA5`).
//!
//! # Autenticação por código de acesso
//!
//! Quando um código de acesso está configurado, todos os comandos exceto
//! SELECT, VALIDATE e RESET exigem VALIDATE prévio (`6982`). A chave de
//! acesso é derivada pelo host com PBKDF2-HMAC-SHA1(senha, salt = ID do
//! dispositivo, 1000 iterações)[:16] e validada mutuamente com HMAC-SHA1
//! em tempo constante. Cada SELECT emite desafio novo (persistido); cada
//! VALIDATE bem-sucedido adota o desafio enviado pelo host.
//!
//! # Persistência cifrada
//!
//! Todo o estado (ID, credenciais, chave de acesso, desafio pendente) é
//! serializado em formato binário próprio, cifrado com ChaCha20-Poly1305
//! (nonce aleatório de 12 bytes via `SystemRandom`) e gravado sob a chave
//! reservada `sys:oath` do [`StorageEngine`] a cada mutação — encryption
//! at rest idêntico ao das credenciais FIDO2.
//!
//! # Decisões registradas
//!
//! - **Versão reportada `(3,4,0)`**: python-yubikit troca para APDUs de
//!   forma estendida quando versão ≥ 4 no USB; o roteador atual só aceita
//!   forma curta. RENAME está implementado no nível de fio, mas fica
//!   desabilitado nas ferramentas Yubico até suporte a forma estendida.
//! - **Contador HOTP monotônico**: todo CALCULATE de credencial HOTP avança
//!   o contador interno persistido ANTES da resposta ser devolvida (modo
//!   desafio-vazio usa o contador interno; modo absoluto exige contador ≥
//!   interno). Queda de energia entre cálculo e resposta não reutiliza
//!   código — desvio consciente dos YubiKeys físicos, que não avançam o
//!   contador no modo absoluto.
//! - **CALCULATE ALL não avança contadores HOTP** (retorna tag `0x77`),
//!   igual aos YubiKeys físicos; códigos HOTP saem por CALCULATE.
//! - **Toque** (`require touch`) é armazenado/reportado (LIST/CALCULATE
//!   ALL usam tag `0x7C`), mas CALCULATE individual ainda calcula sem UI
//!   física — integração com user-presence vem em fase posterior.
//! - **Encadeamento duplo**: respostas > `Le` são fracionadas pelo roteador
//!   (GET RESPONSE) e espelhadas dentro do applet para SEND REMAINING —
//!   python-yubikit continua cadeias `61 XX` com INS `0xA5`, não com `0xC0`.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use crypto::constant_time_eq;
use crypto::CryptoEngine;
use log::{debug, warn};
use storage::StorageEngine;
use transport::iso7816::{sw_more_data, Apdu, Applet, ResponseData};
use zeroize::Zeroize;

extern crate alloc;

/// AID da aplicação Yubico OATH (YKOATH Protocol §General Definitions).
pub const AID_YUBICO_OATH: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

/// Chave reservada no [`StorageEngine`] para o estado cifrado do applet.
const STORAGE_KEY: &str = "sys:oath";

/// Versão do formato de serialização do estado.
const STATE_FORMAT_VERSION: u8 = 1;

/// Limite de credenciais (capacidade escolhida; YubiKeys físicos variam).
pub const MAX_CREDENTIALS: usize = 32;

/// Tamanho máximo do nome de credencial (YKOATH §PUT).
const MAX_NAME_LEN: usize = 64;

/// Tamanho máximo do segredo aceito no PUT (HMAC-SHA512 usa ≤64B após
/// encurtamento do host; folga para chaves já encurtadas).
const MAX_SECRET_LEN: usize = 64;

/// Tamanho máximo de desafio aceito (hosts oficiais enviam 8 bytes).
const MAX_CHALLENGE_LEN: usize = 64;

/// Bytes aleatórios do ID/salt do dispositivo (regenerado no RESET).
const SALT_LEN: usize = 16;

/// Bytes aleatórios do desafio de validação (padrão YKOATH).
const CHALLENGE_LEN: usize = 8;

/// Janela máxima por resposta encadeada (forma curta: `61 XX` codifica ≤255).
const RESPONSE_WINDOW: usize = 255;

/// Versão reportada no SELECT — ver decisão no topo do módulo.
const REPORTED_VERSION: [u8; 3] = [0x03, 0x04, 0x00];

// --- Tags TLV (YKOATH §General Definitions) ---------------------------------

const TAG_NAME: u8 = 0x71;
const TAG_NAME_LIST: u8 = 0x72;
const TAG_KEY: u8 = 0x73;
const TAG_CHALLENGE: u8 = 0x74;
const TAG_RESPONSE: u8 = 0x75;
const TAG_TRUNCATED_RESPONSE: u8 = 0x76;
const TAG_NO_RESPONSE: u8 = 0x77;
const TAG_PROPERTY: u8 = 0x78;
const TAG_VERSION: u8 = 0x79;
const TAG_IMF: u8 = 0x7A;
const TAG_ALGORITHM: u8 = 0x7B;
const TAG_TOUCH_RESPONSE: u8 = 0x7C;

// --- Instruções (YKOATH §Instructions) ---------------------------------------

const INS_PUT: u8 = 0x01;
const INS_DELETE: u8 = 0x02;
const INS_SET_CODE: u8 = 0x03;
const INS_RESET: u8 = 0x04;
const INS_RENAME: u8 = 0x05;
const INS_LIST: u8 = 0xA1;
const INS_CALCULATE: u8 = 0xA2;
const INS_VALIDATE: u8 = 0xA3;
const INS_CALCULATE_ALL: u8 = 0xA4;
const INS_SEND_REMAINING: u8 = 0xA5;

// --- Algoritmos e tipos -------------------------------------------------------

const ALGO_SHA1: u8 = 0x01;
const ALGO_SHA256: u8 = 0x02;
const ALGO_SHA512: u8 = 0x03;

const TYPE_HOTP: u8 = 0x10;
const TYPE_TOTP: u8 = 0x20;

const PROP_ONLY_INCREASING: u8 = 0x01;
const PROP_TOUCH: u8 = 0x02;

// --- Status Words específicas do YKOATH --------------------------------------

/// Sem espaço (limite de credenciais).
const SW_NO_SPACE: u16 = 0x6A84;
/// Sintaxe inválida (TLV duplicado/desconhecido/tampos errados/P1P2).
const SW_WRONG_SYNTAX: u16 = 0x6A80;
/// Objeto inexistente / autenticação não configurada / resposta incorreta.
const SW_NO_SUCH_OBJECT: u16 = 0x6984;
/// Erro genérico (falha interna de cifra/persistência).
const SW_GENERIC_ERROR: u16 = 0x6581;
/// CLA diferente de `0x00`.
const SW_CLASS_NOT_SUPPORTED: u16 = 0x6E00;

// --- Modelo de domínio ---------------------------------------------------------

/// Algoritmo HMAC de uma credencial ou da chave de acesso.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OathAlgorithm {
    /// HMAC-SHA1 (padrão YKOATH; interoperação com ferramentas Yubico).
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

impl OathAlgorithm {
    fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            ALGO_SHA1 => Some(Self::Sha1),
            ALGO_SHA256 => Some(Self::Sha256),
            ALGO_SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }

    fn wire_byte(self) -> u8 {
        match self {
            Self::Sha1 => ALGO_SHA1,
            Self::Sha256 => ALGO_SHA256,
            Self::Sha512 => ALGO_SHA512,
        }
    }

    fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

/// Tipo da credencial: contador incremental (HOTP) ou baseado em tempo (TOTP).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OathType {
    /// HOTP (RFC 4226).
    Hotp,
    /// TOTP (RFC 6238).
    Totp,
}

impl OathType {
    fn from_wire(high_nibble: u8) -> Option<Self> {
        match high_nibble {
            TYPE_HOTP => Some(Self::Hotp),
            TYPE_TOTP => Some(Self::Totp),
            _ => None,
        }
    }

    fn wire_nibble(self) -> u8 {
        match self {
            Self::Hotp => TYPE_HOTP,
            Self::Totp => TYPE_TOTP,
        }
    }
}

/// Credencial OATH residente.
///
/// `Debug` derivado seria proibitivo (`secret` é material criptográfico);
/// a redação é manual como no restante do repositório.
#[derive(Clone)]
struct OathCredential {
    secret: Vec<u8>,
    oath_type: OathType,
    algorithm: OathAlgorithm,
    digits: u8,
    touch_required: bool,
    /// Propriedade "only increasing" do YKOATH (reportada na serialização).
    only_increasing: bool,
    /// Contador interno HOTP (moving factor do próximo código).
    hotp_counter: u64,
}

impl fmt::Debug for OathCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OathCredential")
            .field("oath_type", &self.oath_type)
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("touch_required", &self.touch_required)
            .field("hotp_counter", &self.hotp_counter)
            .field("secret_len", &self.secret.len())
            .finish()
    }
}

/// Configuração do código de acesso (autenticação mútua por VALIDATE).
#[derive(Clone)]
struct OathAccess {
    algorithm: OathAlgorithm,
    key: Vec<u8>,
}

impl fmt::Debug for OathAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OathAccess")
            .field("algorithm", &self.algorithm)
            .field("key_len", &self.key.len())
            .finish()
    }
}

/// Estado completo da aplicação (persistido cifrado sob `sys:oath`).
struct OathState {
    /// ID aleatório do dispositivo: salt do PBKDF2 do host (SELECT tag 0x71).
    salt: Vec<u8>,
    access: Option<OathAccess>,
    /// Desafio pendente apresentado no último SELECT (quando há acesso).
    pending_challenge: Option<Vec<u8>>,
    /// Credenciais indexadas pelo nome completo (ordem determinística).
    credentials: BTreeMap<Vec<u8>, OathCredential>,
}

impl fmt::Debug for OathState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OathState")
            .field("salt_len", &self.salt.len())
            .field("has_access", &self.access.is_some())
            .field(
                "pending_challenge",
                &self.pending_challenge.as_ref().map(|c| c.len()),
            )
            .field("credentials_count", &self.credentials.len())
            .finish()
    }
}

// --- Serialização binária do estado -------------------------------------------
//
// Layout (big-endian onde aplicável):
//
// ```text
// [0]                 versão do formato (STATE_FORMAT_VERSION)
// [1][n]              len || salt
// [1]                 flag acesso (0/1); se 1:
//     [1][n]          algoritmo || len || key
//     [1][n]          len || pending_challenge
// [2]                 contagem de credenciais
// por credencial:
//     [1][n]          len || id
//     [1]             nibble alto tipo | nibble baixo algoritmo (fio PUT)
//     [1]             digits
//     [1]             flags (bit0 touch, bit1 only-increasing reservado)
//     [8]             contador HOTP
//     [1][n]          len || secret
// ```

fn serialize_state(state: &OathState) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(STATE_FORMAT_VERSION);
    out.push(state.salt.len() as u8);
    out.extend_from_slice(&state.salt);

    match &state.access {
        None => out.push(0),
        Some(access) => {
            out.push(1);
            out.push(access.algorithm.wire_byte());
            out.push(access.key.len() as u8);
            out.extend_from_slice(&access.key);
            let challenge = state.pending_challenge.as_deref().unwrap_or(&[]);
            out.push(challenge.len() as u8);
            out.extend_from_slice(challenge);
        }
    }

    out.extend_from_slice(&(state.credentials.len() as u16).to_be_bytes());
    for (id, cred) in &state.credentials {
        out.push(id.len() as u8);
        out.extend_from_slice(id);
        out.push(cred.oath_type.wire_nibble() | cred.algorithm.wire_byte());
        out.push(cred.digits);
        let flags = u8::from(cred.touch_required) | (u8::from(cred.only_increasing) << 1);
        out.push(flags);
        out.extend_from_slice(&cred.hotp_counter.to_be_bytes());
        out.push(cred.secret.len() as u8);
        out.extend_from_slice(&cred.secret);
    }
    out
}

/// Leitor sequencial com verificação de limites para o blob do estado.
struct BlobReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BlobReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.data.len() {
            return None;
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Some(slice)
    }

    fn take_u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn take_len_prefixed(&mut self) -> Option<Vec<u8>> {
        let len = usize::from(self.take_u8()?);
        Some(self.take(len)?.to_vec())
    }

    fn at_end(&self) -> bool {
        self.pos == self.data.len()
    }
}

fn parse_state(blob: &[u8]) -> Option<OathState> {
    let mut reader = BlobReader::new(blob);

    if reader.take_u8()? != STATE_FORMAT_VERSION {
        return None;
    }
    let salt = reader.take_len_prefixed()?;
    if salt.is_empty() || salt.len() > SALT_LEN * 4 {
        return None;
    }

    let access = if reader.take_u8()? == 0 {
        None
    } else {
        let algorithm = OathAlgorithm::from_wire(reader.take_u8()?)?;
        let key = reader.take_len_prefixed()?;
        if key.is_empty() {
            return None;
        }
        let pending = reader.take_len_prefixed()?;
        let pending_challenge = if pending.is_empty() {
            None
        } else {
            Some(pending)
        };
        Some((OathAccess { algorithm, key }, pending_challenge))
    };
    let (access, pending_challenge) =
        access.map_or((None, None), |(access, pending)| (Some(access), pending));

    // Limite de sanidade contra blobs corrompidos com contagem inflada.
    let count = usize::from(reader.take_u16()?);
    if count > MAX_CREDENTIALS {
        return None;
    }
    let mut credentials = BTreeMap::new();
    for _ in 0..count {
        let id = reader.take_len_prefixed()?;
        if id.is_empty() || id.len() > MAX_NAME_LEN {
            return None;
        }
        let wire = reader.take_u8()?;
        let oath_type = OathType::from_wire(wire & 0xF0)?;
        let algorithm = OathAlgorithm::from_wire(wire & 0x0F)?;
        let digits = reader.take_u8()?;
        if !(6..=8).contains(&digits) {
            return None;
        }
        let flags = reader.take_u8()?;
        let hotp_counter = u64::from_be_bytes(reader.take(8)?.try_into().ok()?);
        let secret = reader.take_len_prefixed()?;
        if secret.is_empty() || secret.len() > MAX_SECRET_LEN {
            return None;
        }
        credentials.insert(
            id,
            OathCredential {
                secret,
                oath_type,
                algorithm,
                digits,
                touch_required: flags & 0x01 != 0,
                only_increasing: flags & 0x02 != 0,
                hotp_counter,
            },
        );
    }
    if !reader.at_end() {
        return None;
    }

    Some(OathState {
        salt,
        access,
        pending_challenge,
        credentials,
    })
}

// --- Helpers TLV ----------------------------------------------------------------

/// Empacota um TLV de forma curta (valor ≤255 bytes) ao final de `out`.
fn push_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    assert!(value.len() <= 255, "TLV value exceeds short form");
    out.push(tag);
    out.push(value.len() as u8);
    out.extend_from_slice(value);
}

/// Decodifica a lista de TLVs de uma requisição em pares possuídos.
///
/// Qualquer truncamento devolve `SW_WRONG_SYNTAX`. Valores vazios são
/// válidos (ex.: `Tlv(CHALLENGE, b"")` no CALCULATE de HOTP).
fn parse_tlvs(data: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, u16> {
    let mut tlvs = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        if data.len() - pos < 2 {
            return Err(SW_WRONG_SYNTAX);
        }
        let tag = data[pos];
        let len = usize::from(data[pos + 1]);
        let end = pos + 2 + len;
        if end > data.len() {
            return Err(SW_WRONG_SYNTAX);
        }
        tlvs.push((tag, data[pos + 2..end].to_vec()));
        pos = end;
    }
    Ok(tlvs)
}

/// Remove e retorna a única ocorrência de `tag`; duplicata → erro.
fn take_tag(tlvs: &mut Vec<(u8, Vec<u8>)>, tag: u8) -> Result<Option<Vec<u8>>, u16> {
    let mut found: Option<Vec<u8>> = None;
    let mut duplicated = false;
    tlvs.retain(|(t, v)| {
        if *t == tag {
            if found.is_some() {
                duplicated = true;
                false
            } else {
                found = Some(v.clone());
                false
            }
        } else {
            true
        }
    });
    if duplicated {
        return Err(SW_WRONG_SYNTAX);
    }
    Ok(found)
}

/// Garante que nenhum TLV desconhecido permaneça na requisição.
fn require_no_remaining_tlvs(tlvs: &[(u8, Vec<u8>)]) -> Result<(), u16> {
    if tlvs.is_empty() {
        Ok(())
    } else {
        Err(SW_WRONG_SYNTAX)
    }
}

// --- Núcleo OTP ------------------------------------------------------------------

/// Calcula HMAC conforme o algoritmo da credencial/acesso.
fn hmac_by_algorithm(
    crypto: &CryptoEngine,
    algorithm: OathAlgorithm,
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, u16> {
    let mac = match algorithm {
        OathAlgorithm::Sha1 => crypto.compute_hmac_sha1_ykoath_compat(data, key),
        OathAlgorithm::Sha256 => crypto.compute_hmac(data, key),
        OathAlgorithm::Sha512 => crypto.compute_hmac_sha512(data, key),
    };
    mac.map_err(|_| SW_GENERIC_ERROR)
}

/// Truncamento dinâmico RFC 4226 §5.3: 4 bytes brutos no offset indicado
/// pelo último dígito do digest. A máscara `& 0x7FFFFFFF` e o módulo
/// `10^digits` ficam a cargo do host (formato truncado YKOATH).
fn dynamic_truncate(digest: &[u8]) -> [u8; 4] {
    let offset = usize::from(digest[digest.len() - 1] & 0x0F);
    debug_assert!(offset + 4 <= digest.len(), "offset DT fora do digest");
    [
        digest[offset],
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]
}

// --- Applet ------------------------------------------------------------------------

/// Applet ISO 7816-4 da aplicação Yubico OATH.
///
/// Construtor para a fase de integração:
/// [`OathApplet::new(storage, crypto)`](OathApplet::new) produz um valor
/// pronto para ser registrado num
/// [`CardRouter`](transport::iso7816::CardRouter).
pub struct OathApplet<'a> {
    /// Storage compartilhado: serial/ID e credenciais vivem no mesmo kv.
    storage: &'a core::cell::RefCell<StorageEngine>,
    crypto: CryptoEngine,
    state: Option<OathState>,
    /// Sessão validada por VALIDATE (volátil: limpa em cada SELECT).
    validated: bool,
    /// Espelho da última resposta para SEND REMAINING (`buffer, posição`).
    remaining: Option<(Vec<u8>, usize)>,
}

impl fmt::Debug for OathApplet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redigido: o estado carrega segredos OATH (chaves de acesso e de
        // credenciais); nada além de contagens pode aparecer em logs.
        f.debug_struct("OathApplet")
            .field("loaded", &self.state.is_some())
            .field("validated", &self.validated)
            .field(
                "remaining",
                &self.remaining.as_ref().map(|(b, p)| (b.len(), *p)),
            )
            .finish()
    }
}

impl<'a> OathApplet<'a> {
    /// Cria o applet sobre o storage e o motor criptográfico fornecidos.
    ///
    /// Carrega (ou inicializa) o estado persistido: um registro ausente é
    /// criado imediatamente com ID aleatório para que o salt do host seja
    /// estável desde a primeira seleção. Registro ilegível (chave-mestra
    /// trocada ou dado corrompido) é substituído por estado de fábrica —
    /// mesmo comportamento de um cartão real diante de flash corrompida.
    pub fn new(
        storage: &'a core::cell::RefCell<StorageEngine>,
        crypto: CryptoEngine,
    ) -> Result<Self, Box<dyn core::error::Error>> {
        let mut applet = Self {
            storage,
            crypto,
            state: None,
            validated: false,
            remaining: None,
        };
        applet
            .ensure_loaded()
            .map_err(|sw| format!("YKOATH init failed with SW {:#06X}", sw))?;
        Ok(applet)
    }

    /// Garante o estado em memória, criando registro de fábrica se preciso.
    fn ensure_loaded(&mut self) -> Result<(), u16> {
        if self.state.is_some() {
            return Ok(());
        }
        let loaded = match self.storage.borrow().retrieve(STORAGE_KEY) {
            Ok(blob) if blob.len() > 12 => {
                let (nonce, ciphertext) = blob.split_at(12);
                match self.crypto.decrypt(ciphertext, nonce) {
                    Ok(plaintext) => parse_state(&plaintext),
                    Err(_) => None,
                }
            }
            _ => None,
        };
        match loaded {
            Some(state) => {
                self.state = Some(state);
                Ok(())
            }
            None => {
                // Chave presente porém ilegível (blob corrompido ou
                // chave-mestra trocada): registra e volta ao estado de fábrica.
                if self.storage.borrow().retrieve(STORAGE_KEY).is_ok() {
                    warn!("YKOATH state unreadable; resetting to factory state");
                }
                let state = self.factory_state()?;
                self.state = Some(state);
                self.persist_state()
            }
        }
    }

    /// Estado de fábrica: sem credenciais, sem acesso, ID aleatório novo.
    fn factory_state(&self) -> Result<OathState, u16> {
        Ok(OathState {
            salt: self.crypto.random_bytes(SALT_LEN),
            access: None,
            pending_challenge: None,
            credentials: BTreeMap::new(),
        })
    }

    /// Referência mutável ao estado já carregado (`ensure_loaded` antes).
    fn state_mut(&mut self) -> Result<&mut OathState, u16> {
        if self.state.is_none() {
            self.ensure_loaded()?;
        }
        Ok(self.state.as_mut().expect("state loaded by ensure_loaded"))
    }

    /// Serializa, cifra (nonce aleatório) e grava o estado atual.
    fn persist_state(&mut self) -> Result<(), u16> {
        let state = self.state.as_ref().ok_or(SW_GENERIC_ERROR)?;
        let plaintext = serialize_state(state);
        let (nonce, ciphertext) = self
            .crypto
            .encrypt_with_random_nonce(&plaintext)
            .map_err(|_| SW_GENERIC_ERROR)?;
        let mut blob = Vec::with_capacity(nonce.len() + ciphertext.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        self.storage
            .borrow_mut()
            .store(STORAGE_KEY, blob)
            .map_err(|e| {
                warn!("YKOATH persistence failed: {}", e);
                SW_GENERIC_ERROR
            })
    }

    /// Exige sessão validada quando um código de acesso está configurado.
    ///
    /// Garante a carga do estado antes: o bloqueio depende da presença de
    /// código de acesso, que só é conhecido após ler o storage.
    fn require_validated(&mut self) -> Result<(), u16> {
        self.ensure_loaded()?;
        let locked = self
            .state
            .as_ref()
            .and_then(|s| s.access.as_ref())
            .is_some();
        if locked && !self.validated {
            Err(transport::iso7816::SW_SECURITY_STATUS)
        } else {
            Ok(())
        }
    }

    /// Emite desafio novo por seleção quando há acesso configurado.
    fn rotate_challenge_for_select(&mut self) -> Result<(), u16> {
        let has_access = self
            .state
            .as_ref()
            .and_then(|s| s.access.as_ref())
            .is_some();
        if has_access {
            let fresh = self.crypto.random_bytes(CHALLENGE_LEN);
            self.state_mut()?.pending_challenge = Some(fresh);
            self.persist_state()?;
        }
        Ok(())
    }

    fn cmd_send_remaining(&mut self, apdu: &Apdu) -> Result<ResponseData, u16> {
        self.require_validated()?;
        let (buf_len, pos) = match &self.remaining {
            Some((buffer, pos)) => (buffer.len(), *pos),
            // SEND REMAINING sem `61 XX` prévio (fora de sequência).
            None => return Err(transport::iso7816::SW_CONDITIONS_NOT_SATISFIED),
        };
        if pos >= buf_len {
            self.remaining = None;
            return Ok(ResponseData::ok(Vec::new()));
        }
        let window = apdu.le.unwrap_or(RESPONSE_WINDOW).min(RESPONSE_WINDOW);
        let end = core::cmp::min(pos.saturating_add(window), buf_len);
        let chunk = self.remaining.as_ref().expect("checked above").0[pos..end].to_vec();
        if end < buf_len {
            self.remaining.as_mut().expect("checked above").1 = end;
            Ok(ResponseData::with_sw(chunk, sw_more_data(buf_len - end)))
        } else {
            self.remaining = None;
            Ok(ResponseData::ok(chunk))
        }
    }

    fn cmd_put(&mut self, data: &[u8]) -> Result<ResponseData, u16> {
        self.require_validated()?;
        let mut tlvs = parse_tlvs(data)?;

        let name = take_tag(&mut tlvs, TAG_NAME)?.ok_or(SW_WRONG_SYNTAX)?;
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(SW_WRONG_SYNTAX);
        }

        let key = take_tag(&mut tlvs, TAG_KEY)?.ok_or(SW_WRONG_SYNTAX)?;
        // key = [tipo|algoritmo][digits][secret…]
        if key.len() < 3 {
            return Err(SW_WRONG_SYNTAX);
        }
        let oath_type = OathType::from_wire(key[0] & 0xF0).ok_or(SW_WRONG_SYNTAX)?;
        let algorithm = OathAlgorithm::from_wire(key[0] & 0x0F).ok_or(SW_WRONG_SYNTAX)?;
        let digits = key[1];
        if !(6..=8).contains(&digits) {
            return Err(SW_WRONG_SYNTAX);
        }
        let secret = key[2..].to_vec();
        if secret.len() > MAX_SECRET_LEN {
            return Err(SW_WRONG_SYNTAX);
        }

        let mut touch_required = false;
        let mut only_increasing = false;
        if let Some(prop) = take_tag(&mut tlvs, TAG_PROPERTY)? {
            if prop.len() != 1 || prop[0] & !(PROP_ONLY_INCREASING | PROP_TOUCH) != 0 {
                return Err(SW_WRONG_SYNTAX);
            }
            only_increasing = prop[0] & PROP_ONLY_INCREASING != 0;
            touch_required = prop[0] & PROP_TOUCH != 0;
        }

        let mut counter = 0u64;
        if let Some(imf) = take_tag(&mut tlvs, TAG_IMF)? {
            if imf.len() != 4 {
                return Err(SW_WRONG_SYNTAX);
            }
            if oath_type != OathType::Hotp {
                // IMF só é válido para HOTP (YKOATH §PUT).
                return Err(SW_WRONG_SYNTAX);
            }
            counter = u64::from(u32::from_be_bytes([imf[0], imf[1], imf[2], imf[3]]));
        }

        require_no_remaining_tlvs(&tlvs)?;

        let total = {
            let state = self.state_mut()?;
            let is_new = !state.credentials.contains_key(&name);
            if is_new && state.credentials.len() >= MAX_CREDENTIALS {
                return Err(SW_NO_SPACE);
            }
            state.credentials.insert(
                name.clone(),
                OathCredential {
                    secret,
                    oath_type,
                    algorithm,
                    digits,
                    touch_required,
                    only_increasing,
                    hotp_counter: counter,
                },
            );
            state.credentials.len()
        };
        self.persist_state()?;
        debug!("YKOATH PUT stored credential (total={})", total);
        Ok(ResponseData::ok(Vec::new()))
    }

    fn cmd_delete(&mut self, data: &[u8]) -> Result<ResponseData, u16> {
        self.require_validated()?;
        let mut tlvs = parse_tlvs(data)?;
        let name = take_tag(&mut tlvs, TAG_NAME)?.ok_or(SW_WRONG_SYNTAX)?;
        require_no_remaining_tlvs(&tlvs)?;

        {
            let state = self.state_mut()?;
            if state.credentials.remove(&name).is_none() {
                return Err(SW_NO_SUCH_OBJECT);
            }
        }
        self.persist_state()?;
        debug!("YKOATH DELETE removed credential");
        Ok(ResponseData::ok(Vec::new()))
    }

    fn cmd_rename(&mut self, data: &[u8]) -> Result<ResponseData, u16> {
        self.require_validated()?;
        let mut tlvs = parse_tlvs(data)?;

        // Extensão RENAME (YubiKey ≥5.3.1): DUAS TLVs de nome — atual e nova.
        // take_tag não serve aqui: duas ocorrências da mesma tag são o formato.
        let mut names: Vec<Vec<u8>> = Vec::new();
        tlvs.retain(|(tag, value)| {
            if *tag == TAG_NAME {
                names.push(value.clone());
                false
            } else {
                true
            }
        });
        require_no_remaining_tlvs(&tlvs)?;
        if names.len() != 2 {
            return Err(SW_WRONG_SYNTAX);
        }
        let (current, new_name) = (&names[0], &names[1]);

        if new_name.is_empty() || new_name.len() > MAX_NAME_LEN {
            return Err(SW_WRONG_SYNTAX);
        }
        if current == new_name {
            return Err(SW_WRONG_SYNTAX);
        }

        {
            let state = self.state_mut()?;
            if !state.credentials.contains_key(current) {
                return Err(SW_NO_SUCH_OBJECT);
            }
            if state.credentials.contains_key(new_name) {
                // Conflito de destino: tratado como falta de espaço.
                return Err(SW_NO_SPACE);
            }
            let cred = state.credentials.remove(current).expect("checked above");
            state.credentials.insert(new_name.clone(), cred);
        }
        self.persist_state()?;
        debug!("YKOATH RENAME applied");
        Ok(ResponseData::ok(Vec::new()))
    }

    fn cmd_set_code(&mut self, data: &[u8]) -> Result<ResponseData, u16> {
        // SET CODE exige autenticação quando já existe código configurado
        // (YKOATH §Instructions — Require Auth = Y).
        self.require_validated()?;
        let mut tlvs = parse_tlvs(data)?;

        let key = take_tag(&mut tlvs, TAG_KEY)?.ok_or(SW_WRONG_SYNTAX)?;
        if key.is_empty() {
            // Valor vazio remove a autenticação (yubikit `unset_key`).
            require_no_remaining_tlvs(&tlvs)?;
            {
                let state = self.state_mut()?;
                state.access = None;
                state.pending_challenge = None;
            }
            self.validated = false;
            self.persist_state()?;
            debug!("YKOATH SET CODE removed access key");
            return Ok(ResponseData::ok(Vec::new()));
        }

        // Configuração: key = [algoritmo][chave derivada do host].
        if key.len() < 2 || key.len() > 1 + MAX_SECRET_LEN {
            return Err(SW_WRONG_SYNTAX);
        }
        let algorithm = OathAlgorithm::from_wire(key[0] & 0x0F).ok_or(SW_WRONG_SYNTAX)?;
        let access_key = key[1..].to_vec();

        let challenge = take_tag(&mut tlvs, TAG_CHALLENGE)?.ok_or(SW_WRONG_SYNTAX)?;
        let response = take_tag(&mut tlvs, TAG_RESPONSE)?.ok_or(SW_WRONG_SYNTAX)?;
        require_no_remaining_tlvs(&tlvs)?;

        if challenge.is_empty() || challenge.len() > MAX_CHALLENGE_LEN {
            return Err(SW_WRONG_SYNTAX);
        }
        if response.len() != algorithm.digest_len() {
            return Err(SW_NO_SUCH_OBJECT);
        }
        let expected = hmac_by_algorithm(&self.crypto, algorithm, &access_key, &challenge)?;
        if !constant_time_eq(&expected, &response) {
            // Confirmação não bate: host não deriva a mesma chave.
            return Err(SW_NO_SUCH_OBJECT);
        }

        let fresh = self.crypto.random_bytes(CHALLENGE_LEN);
        {
            let state = self.state_mut()?;
            state.access = Some(OathAccess {
                algorithm,
                key: access_key,
            });
            state.pending_challenge = Some(fresh);
        }
        self.persist_state()?;
        debug!("YKOATH SET CODE configured access key");
        Ok(ResponseData::ok(Vec::new()))
    }

    fn cmd_reset(&mut self, p1: u8, p2: u8) -> Result<ResponseData, u16> {
        // Sequência mágica obrigatória (YKOATH §RESET).
        if p1 != 0xDE || p2 != 0xAD {
            return Err(SW_WRONG_SYNTAX);
        }
        let fresh = self.factory_state()?;
        self.state = Some(fresh);
        self.validated = false;
        self.remaining = None;
        self.persist_state()?;
        debug!("YKOATH RESET applied (factory state)");
        Ok(ResponseData::ok(Vec::new()))
    }

    fn cmd_list(&mut self) -> Result<ResponseData, u16> {
        self.require_validated()?;
        let state = self.state_mut()?;
        let mut out = Vec::new();
        for (id, cred) in &state.credentials {
            let mut entry = vec![cred.oath_type.wire_nibble() | cred.algorithm.wire_byte()];
            entry.extend_from_slice(id);
            push_tlv(&mut out, TAG_NAME_LIST, &entry);
        }
        Ok(ResponseData::ok(out))
    }

    fn cmd_calculate(&mut self, p2: u8, data: &[u8]) -> Result<ResponseData, u16> {
        self.require_validated()?;
        if p2 > 0x01 {
            return Err(SW_WRONG_SYNTAX);
        }
        let truncated = p2 == 0x01;

        let mut tlvs = parse_tlvs(data)?;
        let name = take_tag(&mut tlvs, TAG_NAME)?.ok_or(SW_WRONG_SYNTAX)?;
        let challenge = take_tag(&mut tlvs, TAG_CHALLENGE)?.ok_or(SW_WRONG_SYNTAX)?;
        require_no_remaining_tlvs(&tlvs)?;
        if challenge.len() > MAX_CHALLENGE_LEN {
            return Err(SW_WRONG_SYNTAX);
        }

        // Clona a credencial mínima para soltar o empréstimo do estado.
        let (algorithm, digits, secret, oath_type, internal_counter) = {
            let state = self.state_mut()?;
            let cred = state.credentials.get(&name).ok_or(SW_NO_SUCH_OBJECT)?;
            (
                cred.algorithm,
                cred.digits,
                cred.secret.clone(),
                cred.oath_type,
                cred.hotp_counter,
            )
        };

        let (challenge_bytes, next_counter) = match oath_type {
            OathType::Totp => {
                if challenge.is_empty() {
                    return Err(SW_WRONG_SYNTAX);
                }
                (challenge, None)
            }
            OathType::Hotp => {
                if challenge.is_empty() {
                    // Modo interno: usa e avança o contador persistido.
                    let next = internal_counter.checked_add(1).ok_or(SW_GENERIC_ERROR)?;
                    (internal_counter.to_be_bytes().to_vec(), Some(next))
                } else {
                    // Modo absoluto: desafio é o contador (BE, até 8 bytes).
                    if challenge.len() > 8 {
                        return Err(SW_WRONG_SYNTAX);
                    }
                    let mut raw = [0u8; 8];
                    raw[8 - challenge.len()..].copy_from_slice(&challenge);
                    let used = u64::from_be_bytes(raw);
                    // Monotonicidade incondicional (decisão no topo).
                    if used < internal_counter {
                        return Err(SW_NO_SUCH_OBJECT);
                    }
                    (raw.to_vec(), Some(used.saturating_add(1)))
                }
            }
        };

        let digest = hmac_by_algorithm(&self.crypto, algorithm, &secret, &challenge_bytes)?;

        if let Some(next) = next_counter {
            // Persiste o avanço ANTES de expor qualquer byte da resposta:
            // queda de energia nunca reutiliza um código já emitido.
            let previous_counter = {
                let state = self.state_mut()?;
                let cred = state.credentials.get_mut(&name).ok_or(SW_NO_SUCH_OBJECT)?;
                let previous = cred.hotp_counter;
                cred.hotp_counter = next;
                previous
            };
            if self.persist_state().is_err() {
                // Rollback em memória; nada foi revelado ao host.
                if let Some(state) = self.state.as_mut() {
                    if let Some(cred) = state.credentials.get_mut(&name) {
                        cred.hotp_counter = previous_counter;
                    }
                }
                return Err(SW_GENERIC_ERROR);
            }
        }

        let mut value = vec![digits];
        if truncated {
            value.extend_from_slice(&dynamic_truncate(&digest));
            Ok(ResponseData::ok(push_tlv_owned(
                TAG_TRUNCATED_RESPONSE,
                &value,
            )))
        } else {
            value.extend_from_slice(&digest);
            Ok(ResponseData::ok(push_tlv_owned(TAG_RESPONSE, &value)))
        }
    }

    fn cmd_calculate_all(&mut self, p2: u8, data: &[u8]) -> Result<ResponseData, u16> {
        self.require_validated()?;
        if p2 > 0x01 {
            return Err(SW_WRONG_SYNTAX);
        }
        let truncated = p2 == 0x01;

        let mut tlvs = parse_tlvs(data)?;
        let challenge = take_tag(&mut tlvs, TAG_CHALLENGE)?.ok_or(SW_WRONG_SYNTAX)?;
        require_no_remaining_tlvs(&tlvs)?;
        if challenge.is_empty() || challenge.len() > MAX_CHALLENGE_LEN {
            return Err(SW_WRONG_SYNTAX);
        }

        // Snapshot mínimo para soltar o estado antes das operações HMAC.
        type CredentialSnapshot = (Vec<u8>, OathType, OathAlgorithm, u8, bool, Vec<u8>);
        let snapshot: Vec<CredentialSnapshot> = {
            let state = self.state_mut()?;
            state
                .credentials
                .iter()
                .map(|(id, c)| {
                    (
                        id.clone(),
                        c.oath_type,
                        c.algorithm,
                        c.digits,
                        c.touch_required,
                        c.secret.clone(),
                    )
                })
                .collect()
        };

        // BTreeMap itera ordenado: saída determinística entre comandos.
        let mut out = Vec::new();
        for (id, oath_type, algorithm, digits, touch, secret) in snapshot {
            push_tlv(&mut out, TAG_NAME, &id);
            match oath_type {
                // HOTP: apenas o nome (sem avanço de contador aqui).
                OathType::Hotp => push_tlv(&mut out, TAG_NO_RESPONSE, &[]),
                OathType::Totp if touch => push_tlv(&mut out, TAG_TOUCH_RESPONSE, &[]),
                OathType::Totp => {
                    let digest = hmac_by_algorithm(&self.crypto, algorithm, &secret, &challenge)?;
                    let mut value = vec![digits];
                    if truncated {
                        value.extend_from_slice(&dynamic_truncate(&digest));
                        push_tlv(&mut out, TAG_TRUNCATED_RESPONSE, &value);
                    } else {
                        value.extend_from_slice(&digest);
                        push_tlv(&mut out, TAG_RESPONSE, &value);
                    }
                }
            }
        }
        Ok(ResponseData::ok(out))
    }

    fn cmd_validate(&mut self, data: &[u8]) -> Result<ResponseData, u16> {
        let (algorithm, access_key, pending) = {
            let state = self.state_mut()?;
            match (&state.access, &state.pending_challenge) {
                (Some(access), Some(pending)) => {
                    (access.algorithm, access.key.clone(), pending.clone())
                }
                // Autenticação não habilitada (ou desafio perdido).
                _ => return Err(SW_NO_SUCH_OBJECT),
            }
        };

        let mut tlvs = parse_tlvs(data)?;
        let response = take_tag(&mut tlvs, TAG_RESPONSE)?.ok_or(SW_WRONG_SYNTAX)?;
        let challenge = take_tag(&mut tlvs, TAG_CHALLENGE)?.ok_or(SW_WRONG_SYNTAX)?;
        require_no_remaining_tlvs(&tlvs)?;
        if challenge.is_empty() || challenge.len() > MAX_CHALLENGE_LEN {
            return Err(SW_WRONG_SYNTAX);
        }

        // Direção host→dispositivo: HMAC do desafio emitido no último SELECT.
        let expected = hmac_by_algorithm(&self.crypto, algorithm, &access_key, &pending)?;
        if expected.len() != response.len() || !constant_time_eq(&expected, &response) {
            // Resposta incorreta: desafio pendente é preservado.
            return Err(SW_NO_SUCH_OBJECT);
        }

        {
            let state = self.state_mut()?;
            state.pending_challenge = Some(challenge);
        }
        self.persist_state()?;
        self.validated = true;

        // Direção dispositivo→host: HMAC sobre o novo desafio do host.
        let proof = {
            let state = self.state.as_ref().expect("state present");
            let new_challenge = state.pending_challenge.as_deref().expect("just set");
            hmac_by_algorithm(&self.crypto, algorithm, &access_key, new_challenge)?
        };
        let mut out = Vec::new();
        push_tlv(&mut out, TAG_RESPONSE, &proof);
        debug!("YKOATH VALIDATE succeeded");
        Ok(ResponseData::ok(out))
    }
}

/// Empacota um TLV em um buffer novo (atalho para respostas unitárias).
fn push_tlv_owned(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 2);
    push_tlv(&mut out, tag, value);
    out
}

impl<'a> OathApplet<'a> {
    /// Despacha os INS do protocolo (exceto SEND REMAINING, tratado antes).
    fn dispatch(&mut self, apdu: &Apdu) -> Result<ResponseData, u16> {
        match apdu.ins {
            INS_PUT => self.cmd_put(apdu.data),
            INS_DELETE => self.cmd_delete(apdu.data),
            INS_SET_CODE => self.cmd_set_code(apdu.data),
            INS_RESET => self.cmd_reset(apdu.p1, apdu.p2),
            INS_RENAME => self.cmd_rename(apdu.data),
            INS_LIST => self.cmd_list(),
            INS_CALCULATE => self.cmd_calculate(apdu.p2, apdu.data),
            INS_VALIDATE => self.cmd_validate(apdu.data),
            INS_CALCULATE_ALL => self.cmd_calculate_all(apdu.p2, apdu.data),
            _ => Err(transport::iso7816::SW_INS_NOT_SUPPORTED),
        }
    }
}

impl Applet for OathApplet<'_> {
    fn aid(&self) -> &[u8] {
        AID_YUBICO_OATH
    }

    fn select(&mut self) -> Result<(), u16> {
        // Nova sessão: validação anterior não sobrevive à reseleção.
        self.validated = false;
        self.ensure_loaded()?;
        self.rotate_challenge_for_select()
    }

    fn select_response(&mut self) -> Vec<u8> {
        let Ok(state) = self.state_mut() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        push_tlv(&mut out, TAG_VERSION, &REPORTED_VERSION);
        push_tlv(&mut out, TAG_NAME, &state.salt);
        if let Some(access) = &state.access {
            if let Some(challenge) = &state.pending_challenge {
                push_tlv(&mut out, TAG_CHALLENGE, challenge);
                push_tlv(&mut out, TAG_ALGORITHM, &[access.algorithm.wire_byte()]);
            }
        }
        out
    }

    fn process(&mut self, apdu: &Apdu) -> Result<ResponseData, u16> {
        // CLA fixo 0x00 no YKOATH (roteador não valida CLA por política).
        if apdu.cla != 0x00 {
            return Err(SW_CLASS_NOT_SUPPORTED);
        }

        if apdu.ins == INS_SEND_REMAINING {
            return self.cmd_send_remaining(apdu);
        }

        match self.dispatch(apdu) {
            Ok(response) => {
                // Espelha a resposta para SEND REMAINING: a posição inicial
                // é o que o roteador já entregou inline (limitado pelo Le do
                // comando). Hosts que continuam com GET RESPONSE usam a
                // cadeia do próprio roteador; hosts que usam
                // INS_SEND_REMAINING (python-yubikit) consomem este espelho
                // a partir daqui.
                self.remaining = if response.data.is_empty() {
                    None
                } else {
                    let delivered = core::cmp::min(apdu.le.unwrap_or(0), response.data.len());
                    Some((response.data.clone(), delivered))
                };
                Ok(response)
            }
            // Erro encerra qualquer continuação pendente.
            Err(sw) => {
                self.remaining = None;
                Err(sw)
            }
        }
    }
}

impl Drop for OathApplet<'_> {
    fn drop(&mut self) {
        // Zera material sensível remanescente em memória (regra do repo).
        if let Some(mut state) = self.state.take() {
            if let Some(access) = state.access.take() {
                let mut key = access.key;
                key.zeroize();
            }
            for (_, mut cred) in core::mem::take(&mut state.credentials) {
                cred.secret.zeroize();
            }
            state.salt.zeroize();
            if let Some(mut chal) = state.pending_challenge.take() {
                chal.zeroize();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use storage::{FileStorageBackend, StorageBackend};
    use transport::iso7816::{is_more_data, CardRouter, INS_GET_RESPONSE};

    /// Chave-mestra fixa: permite recriar o applet sobre o mesmo arquivo,
    /// simulando um reinício do dispositivo com a mesma chave.
    const MASTER_KEY: [u8; 32] = [7u8; 32];

    /// Chave de acesso "derivada pelo host" (papel do PBKDF2 do yubikit).
    const ACCESS_KEY: &[u8] = b"derived-access-key-16b";

    fn make_applet(storage: &core::cell::RefCell<StorageEngine>) -> OathApplet<'_> {
        OathApplet::new(storage, CryptoEngine::from_key(MASTER_KEY)).unwrap()
    }

    fn open_persistent<'a>(
        storage: &'a core::cell::RefCell<StorageEngine>,
        path: &std::path::Path,
    ) -> OathApplet<'a> {
        let backend = FileStorageBackend::new(path.to_path_buf()).unwrap();
        *storage.borrow_mut() = StorageEngine::with_backend(Box::new(backend));
        OathApplet::new(storage, CryptoEngine::from_key(MASTER_KEY)).unwrap()
    }

    fn temp_root(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("openkey-oath-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    // --- builders de APDU -------------------------------------------------------

    /// Caso 3S: CLA=0, P1=P2=0, Lc + dados, sem Le.
    fn apdu_case3(ins: u8, p2: u8, data: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, ins, 0x00, p2, data.len() as u8];
        v.extend_from_slice(data);
        v
    }

    /// Caso 2S com Le=0 (=256), formato do ShortApduFormatter do yubikit
    /// para comandos sem dados (`00 INS 00 00 00`).
    fn apdu_case2_le256(ins: u8) -> Vec<u8> {
        vec![0x00, ins, 0x00, 0x00, 0x00]
    }

    /// Caso 3E/4E do ExtendedApduFormatter do python-yubikit:
    /// `00 INS P1 P2` + `00 Lc_hi Lc_lo` + dados (+ Le_hi Le_lo).
    fn apdu_case3_extended(ins: u8, p2: u8, data: &[u8], le: Option<u16>) -> Vec<u8> {
        let mut v = vec![0x00, ins, 0x00, p2, 0x00];
        v.extend_from_slice(&(data.len() as u16).to_be_bytes());
        v.extend_from_slice(data);
        if let Some(le) = le {
            v.extend_from_slice(&le.to_be_bytes());
        }
        v
    }

    /// Processa um frame bruto com semântica de roteador: `Err(sw)` do
    /// applet vira resposta vazia com a Status Word correspondente.
    fn run(applet: &mut OathApplet, raw: &[u8]) -> ResponseData {
        let apdu = Apdu::parse(raw).unwrap();
        match applet.process(&apdu) {
            Ok(response) => response,
            Err(sw) => ResponseData::with_sw(Vec::new(), sw),
        }
    }

    // --- helpers TLV/OTP ---------------------------------------------------------

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag, value.len() as u8];
        out.extend_from_slice(value);
        out
    }

    fn parse_list(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
        parse_tlvs(data).unwrap()
    }

    fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
        CryptoEngine::from_key(MASTER_KEY)
            .compute_hmac_sha1_ykoath_compat(data, key)
            .unwrap()
    }

    fn reference_hmac(algorithm: OathAlgorithm, key: &[u8], data: &[u8]) -> Vec<u8> {
        hmac_by_algorithm(&CryptoEngine::from_key(MASTER_KEY), algorithm, key, data).unwrap()
    }

    /// Truncamento dinâmico RFC 4226 + módulo 10^digits (lado host).
    fn format_code(payload: &[u8], digits: usize) -> String {
        assert_eq!(payload.len(), 4, "truncado deve ter 4 bytes");
        let bin = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        format!(
            "{:0width$}",
            (bin & 0x7FFF_FFFF) % 10u32.pow(digits as u32),
            width = digits
        )
    }

    /// PUT bem-formado para testes.
    fn put_request(
        name: &[u8],
        type_algo: u8,
        digits: u8,
        secret: &[u8],
        property: Option<u8>,
        imf: Option<u32>,
    ) -> Vec<u8> {
        let mut data = tlv(TAG_NAME, name);
        let mut key = vec![type_algo, digits];
        key.extend_from_slice(secret);
        data.extend(tlv(TAG_KEY, &key));
        if let Some(prop) = property {
            data.extend(tlv(TAG_PROPERTY, &[prop]));
        }
        if let Some(counter) = imf {
            data.extend(tlv(TAG_IMF, &counter.to_be_bytes()));
        }
        apdu_case3(INS_PUT, 0x00, &data)
    }

    fn put_credential(applet: &mut OathApplet, name: &[u8], type_algo: u8, secret: &[u8]) {
        let request = put_request(name, type_algo, 6, secret, None, None);
        assert_eq!(run(applet, &request).sw, None);
    }

    fn calculate_request(name: &[u8], challenge: &[u8], truncated: bool) -> Vec<u8> {
        let mut data = tlv(TAG_NAME, name);
        data.extend(tlv(TAG_CHALLENGE, challenge));
        apdu_case3(INS_CALCULATE, u8::from(truncated), &data)
    }

    /// Seleciona e devolve o desafio pendente (tag 0x74 do SELECT).
    fn select_challenge(applet: &mut OathApplet) -> Option<Vec<u8>> {
        applet.select().unwrap();
        let response = applet.select_response();
        parse_tlvs(&response)
            .unwrap()
            .into_iter()
            .find(|(tag, _)| *tag == TAG_CHALLENGE)
            .map(|(_, value)| value)
    }

    /// Configura o código de acesso com confirmação correta (fluxo host).
    fn setup_access_code(applet: &mut OathApplet) {
        applet.select().unwrap();
        let challenge = [0x11u8; 8];
        let response = hmac_sha1(ACCESS_KEY, &challenge);
        let key_value = [ALGO_SHA1]
            .iter()
            .copied()
            .chain(ACCESS_KEY.iter().copied())
            .collect::<Vec<u8>>();
        let mut data = tlv(TAG_KEY, &key_value);
        data.extend(tlv(TAG_CHALLENGE, &challenge));
        data.extend(tlv(TAG_RESPONSE, &response));
        let result = run(applet, &apdu_case3(INS_SET_CODE, 0x00, &data));
        assert_eq!(result.sw, None);
    }

    /// VALIDATE correto contra o desafio pendente atual + prova mútua.
    fn validate_session(applet: &mut OathApplet, new_challenge: &[u8; 8]) {
        let pending = select_challenge(applet).expect("acesso exige desafio");
        let response = hmac_sha1(ACCESS_KEY, &pending);
        let mut data = tlv(TAG_RESPONSE, &response);
        data.extend(tlv(TAG_CHALLENGE, new_challenge));
        let result = run(applet, &apdu_case3(INS_VALIDATE, 0x00, &data));
        assert_eq!(result.sw, None, "VALIDATE correto deve passar");
        let proof = parse_list(&result.data);
        assert_eq!(proof.len(), 1);
        assert_eq!(proof[0].0, TAG_RESPONSE);
        assert_eq!(
            proof[0].1,
            hmac_sha1(ACCESS_KEY, new_challenge),
            "prova do dispositivo deve cobrir o novo desafio"
        );
    }

    // --- vetores dourados TOTP (RFC 6238 Apêndice B) -----------------------------

    const RFC_SEED_SHA1: &[u8] = b"12345678901234567890";
    const RFC_SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
    const RFC_SEED_SHA512: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    #[test]
    fn test_totp_rfc6238_golden_vectors_through_applet() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        // RFC 6238: T = 59 segundos unix com passo de 30 s → desafio = 59/30.
        let t59 = (59u64 / 30).to_be_bytes();

        // Vetores do RFC 6238 usam 8 dígitos.
        for (name, type_algo, seed) in [
            (&b"rfc-sha1"[..], TYPE_TOTP | ALGO_SHA1, RFC_SEED_SHA1),
            (&b"rfc-sha256"[..], TYPE_TOTP | ALGO_SHA256, RFC_SEED_SHA256),
            (&b"rfc-sha512"[..], TYPE_TOTP | ALGO_SHA512, RFC_SEED_SHA512),
        ] {
            let request = put_request(name, type_algo, 8, seed, None, None);
            assert_eq!(run(&mut applet, &request).sw, None);
        }

        for (name, expected) in [
            (&b"rfc-sha1"[..], "94287082"),
            (&b"rfc-sha256"[..], "46119246"),
            (&b"rfc-sha512"[..], "90693936"),
        ] {
            let frame = calculate_request(name, &t59, true);
            let response = run(&mut applet, &frame);
            assert_eq!(response.sw, None, "{}", String::from_utf8_lossy(name));
            let entries = parse_list(&response.data);
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].0, TAG_TRUNCATED_RESPONSE);
            // Valor truncado: [digits=8][4 bytes pós-DT].
            assert_eq!(entries[0].1[0], 8);
            assert_eq!(
                format_code(&entries[0].1[1..], 8),
                expected,
                "vetor RFC 6238 falhou para {}",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[test]
    fn test_calculate_full_response_matches_independent_reference() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        let secret = [0x5Au8; 32];
        put_credential(&mut applet, b"full-totp", TYPE_TOTP | ALGO_SHA256, &secret);

        let challenge = 123_456_789_012u64.to_be_bytes();
        let frame = calculate_request(b"full-totp", &challenge, false);
        let response = run(&mut applet, &frame);
        assert_eq!(response.sw, None);

        let entries = parse_list(&response.data);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, TAG_RESPONSE);

        let digest = reference_hmac(OathAlgorithm::Sha256, &secret, &challenge);
        let mut expected = vec![6]; // digits
        expected.extend_from_slice(&digest);
        assert_eq!(entries[0].1, expected);

        // Resposta truncada paralela deve modular para o mesmo código.
        let truncated = run(
            &mut applet,
            &calculate_request(b"full-totp", &challenge, true),
        );
        let entry = &parse_list(&truncated.data)[0];
        assert_eq!(
            format_code(&entry.1[1..], 6),
            format_code(&dynamic_truncate(&digest), 6)
        );
    }

    // --- persistência e reinício ---------------------------------------------------

    #[test]
    fn test_put_list_delete_roundtrip_and_restart_persistence() {
        let root = temp_root("roundtrip");
        let path = root.join("store.json");

        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = open_persistent(&storage, &path);
        put_credential(&mut applet, b"Alpha:alice", TYPE_TOTP | ALGO_SHA1, &[1; 20]);
        put_credential(
            &mut applet,
            b"Beta:bob@x.y",
            TYPE_HOTP | ALGO_SHA256,
            &[2; 32],
        );

        let list = run(&mut applet, &apdu_case2_le256(INS_LIST));
        assert_eq!(list.sw, None);
        let names: Vec<Vec<u8>> = parse_list(&list.data)
            .into_iter()
            .map(|(_, value)| value[1..].to_vec())
            .collect();
        assert_eq!(
            names,
            vec![b"Alpha:alice".to_vec(), b"Beta:bob@x.y".to_vec()]
        );
        drop(applet);

        // Reinício: mesmo arquivo, novas instâncias de storage e crypto.
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut restarted = open_persistent(&storage, &path);
        let list2 = run(&mut restarted, &apdu_case2_le256(INS_LIST));
        assert_eq!(list2.data, list.data, "LIST deve sobreviver ao reinício");

        // DELETE também persiste.
        let del = tlv(TAG_NAME, &b"Alpha:alice"[..]);
        assert_eq!(
            run(&mut restarted, &apdu_case3(INS_DELETE, 0x00, &del)).sw,
            None
        );
        drop(restarted);

        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut final_applet = open_persistent(&storage, &path);
        let list3 = run(&mut final_applet, &apdu_case2_le256(INS_LIST));
        let remaining: Vec<Vec<u8>> = parse_list(&list3.data)
            .into_iter()
            .map(|(_, value)| value[1..].to_vec())
            .collect();
        assert_eq!(remaining, vec![b"Beta:bob@x.y".to_vec()]);

        // Objeto já removido: 0x6984.
        let missing = tlv(TAG_NAME, &b"Alpha:alice"[..]);
        assert_eq!(
            run(&mut final_applet, &apdu_case3(INS_DELETE, 0x00, &missing)),
            ResponseData::with_sw(Vec::new(), SW_NO_SUCH_OBJECT)
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_hotp_counter_monotonic_across_restart() {
        let root = temp_root("hotp-restart");
        let path = root.join("store.json");

        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = open_persistent(&storage, &path);
        let secret = [0x33u8; 20];
        put_credential(&mut applet, b"work-hotp", TYPE_HOTP | ALGO_SHA1, &secret);
        // Reimporta com IMF para definir contador inicial em 5.
        let with_imf = put_request(
            b"work-hotp",
            TYPE_HOTP | ALGO_SHA1,
            6,
            &secret,
            None,
            Some(5),
        );
        assert_eq!(run(&mut applet, &with_imf).sw, None);

        let empty: &[u8] = &[];
        let code_at = |counter: u64| {
            format_code(
                &dynamic_truncate(&reference_hmac(
                    OathAlgorithm::Sha1,
                    &secret,
                    &counter.to_be_bytes(),
                )),
                6,
            )
        };

        // Dois cálculos internos consomem contadores 5 e 6.
        for expected_counter in [5u64, 6] {
            let response = run(&mut applet, &calculate_request(b"work-hotp", empty, true));
            assert_eq!(response.sw, None);
            let entry = &parse_list(&response.data)[0];
            assert_eq!(entry.0, TAG_TRUNCATED_RESPONSE);
            assert_eq!(
                format_code(&entry.1[1..], 6),
                code_at(expected_counter),
                "código deve corresponder ao contador {}",
                expected_counter
            );
        }
        drop(applet);

        // Reinício: contador continua de onde parou (7), nunca reusa.
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut restarted = open_persistent(&storage, &path);
        let response = run(
            &mut restarted,
            &calculate_request(b"work-hotp", empty, true),
        );
        let entry = &parse_list(&response.data)[0];
        assert_eq!(format_code(&entry.1[1..], 6), code_at(7));

        // Modo absoluto abaixo do interno é rejeitado (monotonicidade).
        let stale = run(
            &mut restarted,
            &calculate_request(b"work-hotp", &3u64.to_be_bytes(), true),
        );
        assert_eq!(stale.sw, Some(SW_NO_SUCH_OBJECT));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_state_blob_is_encrypted_at_rest() {
        let root = temp_root("encrypted");
        let path = root.join("store.json");

        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = open_persistent(&storage, &path);
        let secret = [0xABu8; 20];
        put_credential(
            &mut applet,
            b"secret-name-01",
            TYPE_TOTP | ALGO_SHA1,
            &secret,
        );
        drop(applet);

        let backend = FileStorageBackend::new(path.clone()).unwrap();
        let blob = backend.read(STORAGE_KEY).unwrap().expect("blob presente");

        // Nem o segredo nem o nome aparecem em claro no blob cifrado.
        assert!(
            !blob.windows(secret.len()).any(|w| w == secret),
            "segredo em claro no storage"
        );
        let name = b"secret-name-01";
        assert!(
            !blob.windows(name.len()).any(|w| w == name),
            "nome da credencial em claro no storage"
        );

        // Com outra chave-mestra o blob não decifra (confidencialidade real).
        let (nonce, ciphertext) = blob.split_at(12);
        let other = CryptoEngine::new().unwrap();
        assert!(other.decrypt(ciphertext, nonce).is_err());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_serialize_parse_state_roundtrip() {
        let state = OathState {
            salt: vec![9; SALT_LEN],
            access: Some(OathAccess {
                algorithm: OathAlgorithm::Sha512,
                key: vec![4; 64],
            }),
            pending_challenge: Some(vec![8; CHALLENGE_LEN]),
            credentials: BTreeMap::from([
                (
                    b"a-totp-touch".to_vec(),
                    OathCredential {
                        secret: vec![1; 20],
                        oath_type: OathType::Totp,
                        algorithm: OathAlgorithm::Sha1,
                        digits: 8,
                        touch_required: true,
                        only_increasing: false,
                        hotp_counter: 0,
                    },
                ),
                (
                    b"b-hotp-imf".to_vec(),
                    OathCredential {
                        secret: vec![2; 32],
                        oath_type: OathType::Hotp,
                        algorithm: OathAlgorithm::Sha256,
                        digits: 6,
                        touch_required: false,
                        only_increasing: true,
                        hotp_counter: 42,
                    },
                ),
            ]),
        };

        let parsed = parse_state(&serialize_state(&state)).expect("roundtrip válido");
        assert_eq!(parsed.salt, state.salt);
        assert_eq!(parsed.credentials.len(), 2);
        let hotp = parsed.credentials.get(&b"b-hotp-imf"[..]).unwrap();
        assert_eq!(hotp.hotp_counter, 42);
        assert!(hotp.only_increasing);
        assert!(
            parsed
                .credentials
                .get(&b"a-totp-touch"[..])
                .unwrap()
                .touch_required
        );
        let access = parsed.access.expect("acesso preservado");
        assert_eq!(access.algorithm, OathAlgorithm::Sha512);
        assert_eq!(parsed.pending_challenge, Some(vec![8; CHALLENGE_LEN]));

        // Truncamento e versão desconhecida são rejeitados.
        let mut full = serialize_state(&state);
        assert!(parse_state(&full[..full.len() - 1]).is_none());
        full[0] = 0xFF;
        assert!(parse_state(&full).is_none());
    }

    // --- código de acesso / VALIDATE -------------------------------------------------

    #[test]
    fn test_set_code_requires_matching_confirmation() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        applet.select().unwrap();
        let challenge = [0x22u8; 8];

        // Confirmação com desafio diferente → 6984 e acesso não configurado.
        let wrong = hmac_sha1(ACCESS_KEY, &[0x23u8; 8]);
        let key_value = [ALGO_SHA1]
            .iter()
            .copied()
            .chain(ACCESS_KEY.iter().copied())
            .collect::<Vec<u8>>();
        let mut bad = tlv(TAG_KEY, &key_value);
        bad.extend(tlv(TAG_CHALLENGE, &challenge));
        bad.extend(tlv(TAG_RESPONSE, &wrong));
        let rejected = run(&mut applet, &apdu_case3(INS_SET_CODE, 0x00, &bad));
        assert_eq!(rejected.sw, Some(SW_NO_SUCH_OBJECT));
        assert!(select_challenge(&mut applet).is_none());

        let good = hmac_sha1(ACCESS_KEY, &challenge);
        let key_value = [ALGO_SHA1]
            .iter()
            .copied()
            .chain(ACCESS_KEY.iter().copied())
            .collect::<Vec<u8>>();
        let mut ok = tlv(TAG_KEY, &key_value);
        ok.extend(tlv(TAG_CHALLENGE, &challenge));
        ok.extend(tlv(TAG_RESPONSE, &good));
        assert_eq!(
            run(&mut applet, &apdu_case3(INS_SET_CODE, 0x00, &ok)).sw,
            None
        );
        assert!(select_challenge(&mut applet).is_some());
    }

    #[test]
    fn test_locked_device_blocks_commands_until_validate() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        put_credential(&mut applet, b"svc", TYPE_TOTP | ALGO_SHA1, &[3; 20]);
        setup_access_code(&mut applet);

        // Sem validação: comandos protegidos devolvem 6982.
        for frame in [
            apdu_case2_le256(INS_LIST),
            apdu_case2_le256(INS_SEND_REMAINING),
            calculate_request(b"svc", &1u64.to_be_bytes(), true),
            put_request(b"x", TYPE_TOTP | ALGO_SHA1, 6, &[9; 20], None, None),
        ] {
            assert_eq!(
                run(&mut applet, &frame).sw,
                Some(transport::iso7816::SW_SECURITY_STATUS),
                "comando protegido deve exigir validação"
            );
        }

        // VALIDATE com resposta errada falha e NÃO consome o desafio.
        let pending = select_challenge(&mut applet).unwrap();
        let mut bad = tlv(TAG_RESPONSE, &hmac_sha1(ACCESS_KEY, &[0xEEu8; 8]));
        bad.extend(tlv(TAG_CHALLENGE, &[0x44u8; 8]));
        let denied = run(&mut applet, &apdu_case3(INS_VALIDATE, 0x00, &bad));
        assert_eq!(denied.sw, Some(SW_NO_SUCH_OBJECT));

        // O desafio pendente original continua válido: a resposta correta
        // sobre ELE é aceita (prova que a falha não o rotacionou).
        let mut good = tlv(TAG_RESPONSE, &hmac_sha1(ACCESS_KEY, &pending));
        good.extend(tlv(TAG_CHALLENGE, &[0x55u8; 8]));
        let accepted = run(&mut applet, &apdu_case3(INS_VALIDATE, 0x00, &good));
        assert_eq!(accepted.sw, None);

        // Sessão liberada: LIST funciona.
        let list = run(&mut applet, &apdu_case2_le256(INS_LIST));
        assert_eq!(list.sw, None);
    }

    #[test]
    fn test_unset_code_removes_authentication() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        setup_access_code(&mut applet);
        validate_session(&mut applet, &[0x77u8; 8]);

        let removed = run(
            &mut applet,
            &apdu_case3(INS_SET_CODE, 0x00, &tlv(TAG_KEY, &[])),
        );
        assert_eq!(removed.sw, None);
        assert!(select_challenge(&mut applet).is_none());

        // Sem acesso, comandos funcionam sem validação.
        let list = run(&mut applet, &apdu_case2_le256(INS_LIST));
        assert_eq!(list.sw, None);
    }

    #[test]
    fn test_validate_without_access_configured_is_rejected() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        let mut data = tlv(TAG_RESPONSE, &vec![0u8; 20]);
        data.extend(tlv(TAG_CHALLENGE, &[1u8; 8]));
        let result = run(&mut applet, &apdu_case3(INS_VALIDATE, 0x00, &data));
        assert_eq!(result.sw, Some(SW_NO_SUCH_OBJECT));
    }

    #[test]
    fn test_select_issues_fresh_challenge_only_with_access() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        assert!(
            select_challenge(&mut applet).is_none(),
            "sem acesso não há desafio"
        );
        assert!(select_challenge(&mut applet).is_none());

        setup_access_code(&mut applet);
        let first = select_challenge(&mut applet).unwrap();
        let second = select_challenge(&mut applet).unwrap();
        assert_ne!(first, second, "cada SELECT deve emitir desafio novo");
        assert_eq!(first.len(), CHALLENGE_LEN);
    }

    // --- RESET ----------------------------------------------------------------------

    #[test]
    fn test_reset_clears_everything_and_requires_magic_p1p2() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        put_credential(&mut applet, b"doomed", TYPE_TOTP | ALGO_SHA1, &[5; 20]);
        setup_access_code(&mut applet);
        validate_session(&mut applet, &[0x88u8; 8]);
        let old_salt = select_challenge_named_salt(&mut applet);

        // P1/P2 errados → sintaxe inválida.
        let wrong_p1 = vec![0x00, INS_RESET, 0x00, 0xAD, 0x00];
        assert_eq!(run(&mut applet, &wrong_p1).sw, Some(SW_WRONG_SYNTAX));
        let wrong_p2 = vec![0x00, INS_RESET, 0xDE, 0x00, 0x00];
        assert_eq!(run(&mut applet, &wrong_p2).sw, Some(SW_WRONG_SYNTAX));

        let reset = vec![0x00, INS_RESET, 0xDE, 0xAD, 0x00];
        assert_eq!(run(&mut applet, &reset).sw, None);

        // Credenciais sumiram e o acesso foi desconfigurado.
        let list = run(&mut applet, &apdu_case2_le256(INS_LIST));
        assert!(list.data.is_empty());
        assert!(select_challenge(&mut applet).is_none());

        // Salt regenerado.
        let new_salt = select_challenge_named_salt(&mut applet);
        assert_ne!(old_salt, new_salt, "RESET gera novo ID/salt");
    }

    /// Extrai a tag 0x71 (salt/ID) da resposta de SELECT.
    fn select_challenge_named_salt(applet: &mut OathApplet) -> Vec<u8> {
        applet.select().unwrap();
        parse_tlvs(&applet.select_response())
            .unwrap()
            .into_iter()
            .find(|(tag, _)| *tag == TAG_NAME)
            .map(|(_, value)| value)
            .expect("SELECT sempre devolve o salt")
    }

    #[test]
    fn test_reset_persists_across_restart() {
        let root = temp_root("reset-restart");
        let path = root.join("store.json");

        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = open_persistent(&storage, &path);
        put_credential(&mut applet, b"gone", TYPE_TOTP | ALGO_SHA1, &[6; 20]);
        let reset = vec![0x00, INS_RESET, 0xDE, 0xAD, 0x00];
        assert_eq!(run(&mut applet, &reset).sw, None);
        drop(applet);

        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut restarted = open_persistent(&storage, &path);
        let list = run(&mut restarted, &apdu_case2_le256(INS_LIST));
        assert!(list.data.is_empty(), "RESET deve ser persistido");

        let _ = std::fs::remove_dir_all(&root);
    }

    // --- sintaxe do PUT / limites -----------------------------------------------------

    #[test]
    fn test_put_rejects_invalid_syntax() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        let secret = [1u8; 20];

        let cases: Vec<Vec<u8>> = vec![
            // Digits fora de 6..=8.
            put_request(b"name", TYPE_TOTP | ALGO_SHA1, 5, &secret, None, None),
            // Algoritmo desconhecido (nibble baixo 0x04).
            put_request(b"name", TYPE_TOTP | 0x04, 6, &secret, None, None),
            // Tipo desconhecido (nibble alto 0x30).
            put_request(b"name", 0x30 | ALGO_SHA1, 6, &secret, None, None),
            // Nome acima de 64 bytes.
            put_request(
                &[b'n'; MAX_NAME_LEN + 1],
                TYPE_TOTP | ALGO_SHA1,
                6,
                &secret,
                None,
                None,
            ),
            // Propriedade com bit desconhecido.
            put_request(b"name", TYPE_TOTP | ALGO_SHA1, 6, &secret, Some(0x80), None),
            // IMF em credencial TOTP.
            put_request(b"totp", TYPE_TOTP | ALGO_SHA1, 6, &secret, None, Some(9)),
            // Tag duplicada (dois nomes).
            apdu_case3(
                INS_PUT,
                0x00,
                &[
                    tlv(TAG_NAME, b"a"),
                    tlv(TAG_NAME, b"b"),
                    tlv(
                        TAG_KEY,
                        &[TYPE_TOTP | ALGO_SHA1, 6]
                            .iter()
                            .copied()
                            .chain(secret)
                            .collect::<Vec<u8>>(),
                    ),
                ]
                .concat(),
            ),
            // TLV truncado.
            apdu_case3(INS_PUT, 0x00, &[TAG_NAME, 10, b'x']),
            // Falta a tag key.
            apdu_case3(INS_PUT, 0x00, &tlv(TAG_NAME, b"so-nome")),
        ];
        for (i, frame) in cases.iter().enumerate() {
            assert_eq!(
                run(&mut applet, frame),
                ResponseData::with_sw(Vec::new(), SW_WRONG_SYNTAX),
                "caso {} deveria virar 6A80",
                i
            );
        }
    }

    #[test]
    fn test_put_enforces_max_credentials_cap() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        for i in 0..MAX_CREDENTIALS {
            let name = format!("cred-{i:03}");
            put_credential(
                &mut applet,
                name.as_bytes(),
                TYPE_TOTP | ALGO_SHA1,
                &[i as u8; 20],
            );
        }
        // Sobrescrever existente não conta no limite.
        put_credential(&mut applet, b"cred-000", TYPE_TOTP | ALGO_SHA1, &[0xFF; 20]);

        let overflow = put_request(
            b"cred-extra",
            TYPE_TOTP | ALGO_SHA1,
            6,
            &[1; 20],
            None,
            None,
        );
        assert_eq!(run(&mut applet, &overflow).sw, Some(SW_NO_SPACE));
    }

    #[test]
    fn test_rename_updates_name_preserving_fields() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        let secret = [0x77u8; 20];
        put_credential(&mut applet, b"old:name", TYPE_TOTP | ALGO_SHA256, &secret);

        let rename_ok = [tlv(TAG_NAME, b"old:name"), tlv(TAG_NAME, b"new:name")].concat();
        assert_eq!(
            run(&mut applet, &apdu_case3(INS_RENAME, 0x00, &rename_ok)).sw,
            None
        );

        // Nome novo responde; antigo vira 6984.
        let challenge = 42u64.to_be_bytes();
        let calc_new = run(
            &mut applet,
            &calculate_request(b"new:name", &challenge, true),
        );
        assert_eq!(calc_new.sw, None);
        let calc_old = run(
            &mut applet,
            &calculate_request(b"old:name", &challenge, true),
        );
        assert_eq!(calc_old.sw, Some(SW_NO_SUCH_OBJECT));

        // Renomear para nome existente → conflito (sem espaço).
        put_credential(&mut applet, b"other", TYPE_TOTP | ALGO_SHA1, &[9; 20]);
        let collision = [tlv(TAG_NAME, b"other"), tlv(TAG_NAME, b"new:name")].concat();
        assert_eq!(
            run(&mut applet, &apdu_case3(INS_RENAME, 0x00, &collision)).sw,
            Some(SW_NO_SPACE)
        );

        // Origem inexistente → 6984.
        let missing = [tlv(TAG_NAME, b"ghost"), tlv(TAG_NAME, b"any")].concat();
        assert_eq!(
            run(&mut applet, &apdu_case3(INS_RENAME, 0x00, &missing)).sw,
            Some(SW_NO_SUCH_OBJECT)
        );

        // Renomear para o mesmo nome → sintaxe inválida.
        let same = [tlv(TAG_NAME, b"same"), tlv(TAG_NAME, b"same")].concat();
        assert_eq!(
            run(&mut applet, &apdu_case3(INS_RENAME, 0x00, &same)).sw,
            Some(SW_WRONG_SYNTAX)
        );
    }

    #[test]
    fn test_rename_reachable_via_extended_length_frames_through_router() {
        // Antes do suporte à forma estendida, o roteador rejeitava estes
        // frames com 6700 e o RENAME ficava inalcançável pelas ferramentas
        // Yubico (python-yubikit usa forma estendida no USB para versão ≥4).
        let storage: &'static core::cell::RefCell<StorageEngine> = Box::leak(Box::new(
            core::cell::RefCell::new(StorageEngine::new().unwrap()),
        ));
        let oath = Box::leak(Box::new(make_applet(storage)));
        put_credential(oath, b"old:name", TYPE_TOTP | ALGO_SHA256, &[0x33; 20]);

        let mut router = CardRouter::new();
        router.register(oath);

        // SELECT pela forma estendida (caso 3E: AID como dado, sem Le —
        // frame exato do ExtendedApduFormatter com le=0).
        let select_e =
            apdu_case3_extended(transport::iso7816::INS_SELECT, 0x04, AID_YUBICO_OATH, None);
        let resp = router.process(&select_e);
        assert_eq!(resp.sw, Some(transport::iso7816::SW_NO_ERROR));
        assert_eq!(resp.data.first(), Some(&0x79));

        // RENAME na forma estendida (caso 4E, com Le explícito): duas TLVs
        // de nome na mesma carga útil estendida.
        let data = [tlv(TAG_NAME, b"old:name"), tlv(TAG_NAME, b"new:name")].concat();
        let rename_e = apdu_case3_extended(INS_RENAME, 0x00, &data, Some(1));
        assert_eq!(
            router.process(&rename_e).sw,
            Some(transport::iso7816::SW_NO_ERROR)
        );

        // Efeito real: CALCULATE responde pelo nome novo (frame curto) e o
        // antigo desaparece (6984).
        let challenge = 7u64.to_be_bytes();
        let ok = run(oath, &calculate_request(b"new:name", &challenge, true));
        assert_eq!(ok.sw, None);
        let gone = run(oath, &calculate_request(b"old:name", &challenge, true));
        assert_eq!(gone.sw, Some(SW_NO_SUCH_OBJECT));
    }

    // --- LIST e CALCULATE ALL ----------------------------------------------------------

    #[test]
    fn test_list_entries_are_sorted_with_wire_type_byte() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        put_credential(&mut applet, b"zeta", TYPE_TOTP | ALGO_SHA1, &[1; 20]);
        put_credential(&mut applet, b"alpha", TYPE_HOTP | ALGO_SHA256, &[2; 32]);
        put_credential(&mut applet, b"mid", TYPE_TOTP | ALGO_SHA512, &[3; 64]);

        let list = run(&mut applet, &apdu_case2_le256(INS_LIST));
        let entries = parse_list(&list.data);
        let names: Vec<&[u8]> = entries.iter().map(|(_, v)| &v[1..]).collect();
        assert_eq!(names, vec![&b"alpha"[..], &b"mid"[..], &b"zeta"[..]]);
        assert_eq!(entries[0].0, TAG_NAME_LIST);
        // "alpha" é HOTP/SHA256; "mid" TOTP/SHA512; "zeta" TOTP/SHA1.
        assert_eq!(entries[0].1[0], TYPE_HOTP | ALGO_SHA256);
        assert_eq!(entries[1].1[0], TYPE_TOTP | ALGO_SHA512);
        assert_eq!(entries[2].1[0], TYPE_TOTP | ALGO_SHA1);
    }

    #[test]
    fn test_calculate_all_tags_totp_hotp_and_touch() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        put_credential(&mut applet, b"a-hot", TYPE_HOTP | ALGO_SHA1, &[1; 20]);
        put_credential(&mut applet, b"c-tot", TYPE_TOTP | ALGO_SHA256, &[2; 32]);
        // TOTP com require touch (PUT com propriedade 0x02).
        let with_touch = put_request(
            b"b-tot-touch",
            TYPE_TOTP | ALGO_SHA1,
            6,
            &[3; 20],
            Some(PROP_TOUCH),
            None,
        );
        assert_eq!(run(&mut applet, &with_touch).sw, None);

        let challenge = 1_700_000_000u64.to_be_bytes();
        let frame = apdu_case3(INS_CALCULATE_ALL, 0x01, &tlv(TAG_CHALLENGE, &challenge));
        let response = run(&mut applet, &frame);
        assert_eq!(response.sw, None);

        let entries = parse_list(&response.data);
        assert_eq!(entries.len(), 6, "três pares nome+resposta");
        assert_eq!(&entries[0].1, &b"a-hot".to_vec()); // nome primeiro
        assert_eq!(entries[1].0, TAG_NO_RESPONSE); // HOTP: tag 0x77

        assert_eq!(&entries[2].1, &b"b-tot-touch".to_vec());
        assert_eq!(entries[3].0, TAG_TOUCH_RESPONSE); // touch: tag 0x7C

        assert_eq!(&entries[4].1, &b"c-tot".to_vec());
        assert_eq!(entries[5].0, TAG_TRUNCATED_RESPONSE);
        let expected_digest = reference_hmac(OathAlgorithm::Sha256, &[2; 32], &challenge);
        assert_eq!(
            format_code(&entries[5].1[1..], 6),
            format_code(&dynamic_truncate(&expected_digest), 6)
        );

        // CALCULATE ALL não avança contador HOTP: cálculo interno seguinte
        // ainda usa o contador inicial 0.
        let empty: &[u8] = &[];
        let hotp_calc = run(&mut applet, &calculate_request(b"a-hot", empty, true));
        let entry = &parse_list(&hotp_calc.data)[0];
        let expected = format_code(
            &dynamic_truncate(&reference_hmac(
                OathAlgorithm::Sha1,
                &[1; 20],
                &0u64.to_be_bytes(),
            )),
            6,
        );
        assert_eq!(format_code(&entry.1[1..], 6), expected);
    }

    // --- encadeamento SEND REMAINING x GET RESPONSE ---------------------------------------

    fn router_with_big_list() -> (CardRouter<'static>, Vec<u8>) {
        // Monta o applet ANTES de registrá-lo no roteador: o payload
        // integral do LIST é capturado fora do encadeamento.
        // O storage é vazado junto com o applet para satisfazer 'static
        // (o processo de teste termina antes do borrow importar).
        let leaked_storage: &'static core::cell::RefCell<StorageEngine> = Box::leak(Box::new(
            core::cell::RefCell::new(StorageEngine::new().unwrap()),
        ));
        let mut boxed = Box::new(make_applet(leaked_storage));
        assert_eq!(boxed.select().unwrap(), ());
        // 24 credenciais com nomes longos → LIST > 255 bytes.
        for i in 0..24u32 {
            let name = format!("service-{i:02}@example-org-aaaaaaaaaaaa");
            put_credential(
                &mut boxed,
                name.as_bytes(),
                TYPE_TOTP | ALGO_SHA1,
                &[i as u8; 20],
            );
        }
        let direct = boxed
            .process(&Apdu::parse(&apdu_case2_le256(INS_LIST)).unwrap())
            .unwrap();
        assert_eq!(direct.sw, None);

        let applet = Box::leak(boxed);
        let mut router = CardRouter::new();
        router.register(applet);
        let mut select = vec![
            0x00,
            transport::iso7816::INS_SELECT,
            0x04,
            0x00,
            AID_YUBICO_OATH.len() as u8,
        ];
        select.extend_from_slice(AID_YUBICO_OATH);
        assert_eq!(
            router.process(&select).sw,
            Some(transport::iso7816::SW_NO_ERROR)
        );
        (router, direct.data)
    }

    #[test]
    fn test_large_list_drains_via_send_remaining_like_yubikit() {
        let (mut router, expected) = router_with_big_list();
        assert!(
            expected.len() > RESPONSE_WINDOW + 255,
            "payload precisa estourar a janela"
        );

        // LIST no formato do python-yubikit (Le=256).
        let first = router.process(&apdu_case2_le256(INS_LIST));
        assert!(is_more_data(first.sw.unwrap()));
        assert_eq!(first.data.len(), 256);
        let mut assembled = first.data;

        loop {
            let chunk = router.process(&apdu_case2_le256(INS_SEND_REMAINING));
            let sw = chunk.sw.unwrap();
            assembled.extend_from_slice(&chunk.data);
            if !is_more_data(sw) {
                break;
            }
        }
        assert_eq!(
            assembled, expected,
            "encadeamento 0xA5 sem duplicação ou lacuna"
        );
    }

    #[test]
    fn test_large_list_drains_via_get_response() {
        let (mut router, expected) = router_with_big_list();

        let first = router.process(&apdu_case2_le256(INS_LIST));
        assert!(is_more_data(first.sw.unwrap()));
        let mut assembled = first.data;
        loop {
            let get_response = vec![0x00, INS_GET_RESPONSE, 0x00, 0x00, 0x00];
            let chunk = router.process(&get_response);
            let sw = chunk.sw.unwrap();
            assembled.extend_from_slice(&chunk.data);
            if !is_more_data(sw) {
                break;
            }
        }
        assert_eq!(assembled, expected, "encadeamento GET RESPONSE intacto");
    }

    // --- despacho e CLA -------------------------------------------------------------------

    #[test]
    fn test_non_zero_cla_rejected_and_unknown_ins_not_supported() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        let cla_frame = vec![0x80, INS_LIST, 0x00, 0x00, 0x00];
        assert_eq!(
            run(&mut applet, &cla_frame),
            ResponseData::with_sw(Vec::new(), SW_CLASS_NOT_SUPPORTED)
        );

        let unknown = vec![0x00, 0x6F, 0x00, 0x00, 0x00];
        assert_eq!(
            run(&mut applet, &unknown),
            ResponseData::with_sw(Vec::new(), transport::iso7816::SW_INS_NOT_SUPPORTED)
        );
    }

    #[test]
    fn test_send_remaining_without_pending_chain_is_conditions_not_satisfied() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        let result = run(&mut applet, &apdu_case2_le256(INS_SEND_REMAINING));
        assert_eq!(
            result.sw,
            Some(transport::iso7816::SW_CONDITIONS_NOT_SATISFIED)
        );
    }
}
