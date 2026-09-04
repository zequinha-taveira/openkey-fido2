//! Aplicação PIV (Personal Identity Verification) como applet ISO/IEC 7816-4.
//!
//! Expõe o AID `A000000308000010000100` (NIST SP 800-73 PIV Card Application)
//! no `CardRouter` para roteamento multi-protocolo (ADR-0024).
//!
//! # Comandos suportados (Fase F1)
//!
//! | Comando               | INS    | P1/P2            | Resposta                    |
//! |-----------------------|--------|------------------|-----------------------------|
//! | GET DATA              | `0xCB` | `0x3F/0xFF`      | objeto descoberto/CHUID     |
//! | VERIFY                | `0x20` | `0x00/0x80` (PIN)| `9000` / `63Cx` / `6982`    |
//! | CHANGE REFERENCE DATA | `0x24` | `0x00/0x80` (PIN)| `9000` / `63Cx` / `6982`    |
//! | GENERATE ASYMMETRIC   | `0x47` | `0x00/slot`      | objeto `7F49` + `9000`      |
//! | GENERAL AUTHENTICATE  | `0x87` | `alg/slot`       | assinatura + `9000`         |
//! | PUT DATA              | `0xDB` | `0x3F/0xFF`      | `9000` / `6A80` / `6982`    |
//!
//! Slots de chave (F2a): `9A` (PIV Authentication), `9C` (Digital Signature),
//! `9D` (Key Management), `9E` (Card Authentication). Algoritmos: P-256
//! (`0x11`) e Ed25519 (`0xE0`, IDs Yubico).
//!
//! # Política de autenticação por slot (F2a, estendida na F2d)
//!
//! - Slot `9A` exige `VERIFY` prévio com o PIN: sem sessão verificada,
//!   `AUTHENTICATE` e `PUT DATA` respondem `6982`.
//! - Slots `9C`/`9D`/`9E` não exigem `VERIFY` (assinam/armazenam sempre;
//!   desvio consciente simplificado — política PIN exacta por slot fica
//!   para fase futura).
//! - `GET DATA` é leitura pública (sem gate): com certificado devolve os
//!   bytes armazenados; senão, com chave, devolve o objeto `7F49`; sem
//!   nenhum dos dois responde `6982` (convenção herdada da F2a).
//!
//! # Formato no fio (F2a, subconjunto do SP 800-73; F2d acrescenta `PUT DATA`)
//!
//! - `GENERATE`: `P1=0x00`, `P2=slot`, dados `AC 03 80 01 <alg>` (também
//!   aceita o byte único `<alg>`). Resposta: objeto `7F49` =
//!   `7F49 <len> [80 01 <alg>] [86 <len> <pubkey>]`.
//! - `AUTHENTICATE`: `P1=<alg|0x00>`, `P2=slot`, dados = desafio bruto ou
//!   `7C <len> 81 <len> <desafio>`. Resposta: assinatura bruta (Ed25519 64B,
//!   P-256 DER); o invólucro `7C/82` completo fica para fase futura.
//! - `GET DATA` de chave: mesma P1/P2 (`3F/FF`), tag no campo de dados:
//!   `9A→5FC105`, `9C→5FC10A`, `9D→5FC10B`, `9E→5FC10C`. Com certificado
//!   armazenado (F2d) devolve os bytes do certificado; senão, com chave,
//!   o objeto `7F49`; sem nenhum, `6982`.
//! - `PUT DATA` (F2d): `P1=0x3F`, `P2=0xFF`, dados =
//!   `<tag-cert-3B> <len-BER> <bytes-do-certificado>` (mesmas tags do
//!   `GET DATA`; comprimentos curto `len` ou longo `81 len` / `82 lenHi
//!   lenLo`, sem sobra). Os bytes são guardados verbatim — em geral o
//!   objeto `70` do SP 800-73 contendo o DER, mas DER cru também é aceito
//!   (o roundtrip é byte-idêntico em ambos os casos). Teto de 2048 bytes
//!   por certificado (ver `MAX_CERT_LEN`); acima disso `6A80`.
//!
//! `GET DATA` aceita a tag de descoberta (`0x7E`) e a tag do CHUID
//! (`0x5FC102`), devolvendo placeholders determinísticos; qualquer outra tag
//! responde `6A82`. `VERIFY` vazio consulta as tentativas restantes (`63Cx`);
//! PIN correto autentica (`9000`) e restaura as tentativas; PIN errado
//! decrementa e persiste (`63Cx`, `6982` ao esgotar). `CHANGE REFERENCE DATA`
//! recebe `PIN_atual(8B, `0xFF`-padded) || PIN_novo(8B, `0xFF`-padded)`.
//!
//! # Persistência cifrada
//!
//! PIN e tentativas são serializados em formato binário próprio, cifrados com
//! ChaCha20-Poly1305 (nonce aleatório de 12 bytes via `SystemRandom`) e
//! gravados sob a chave reservada `sys:piv` do [`StorageEngine`] — encryption
//! at rest idêntico ao do applet OATH. Blob ilegível volta aos padrões de
//! fábrica (PIN `"123456"`, 3 tentativas) com log.
//!
//! # Limites da fase F2d (certificados PIV, sem OpenPGP)
//!
//! `PUT DATA` importa apenas certificados (sem importação de chaves
//! privadas, sem DEC/AUT); o certificado não é validado contra a chave do
//! slot (parse X.509 completo fica para fase futura). Regenerar a chave de
//! um slot apaga o certificado dele (vínculo obsoleto). OpenPGP segue
//! intocado (F2b).

use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;
use core::fmt;

use crypto::{constant_time_eq, CryptoEngine};
use log::{debug, warn};
use storage::StorageEngine;
use transport::iso7816::{Apdu, Applet, ResponseData};
use zeroize::Zeroize;

extern crate alloc;

/// AID da aplicação PIV (NIST SP 800-73).
pub const AID_PIV: &[u8] = &[
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];

/// Chave reservada no [`StorageEngine`] para o estado cifrado do applet.
const STORAGE_KEY: &str = "sys:piv";

/// Versão do formato de serialização do estado (F2d; F2a usava `2`, F1 `1`).
const STATE_FORMAT_VERSION: u8 = 3;

/// PIN padrão de fábrica (igual ao dos YubiKeys físicos).
const DEFAULT_PIN: &[u8] = b"123456";

/// Tentativas máximas do PIN (padrão PIV/YubiKey).
const MAX_RETRIES: u8 = 3;

/// Tamanho do PIN no fio (preenchido com `0xFF`, conforme SP 800-73).
const PIN_WIRE_LEN: usize = 8;

/// Comprimento mínimo aceito para um PIN novo.
const MIN_PIN_LEN: usize = 6;

/// Comprimento máximo aceito para um PIN novo.
const MAX_PIN_LEN: usize = 8;

// --- Instruções (NIST SP 800-73, PIV Card Application) --------------------------

/// VERIFY: autentica o titular com o PIN.
const INS_VERIFY: u8 = 0x20;
/// CHANGE REFERENCE DATA: troca o PIN (PIN atual + PIN novo).
const INS_CHANGE_REFERENCE_DATA: u8 = 0x24;
/// GET DATA: lê um objeto de dados pela tag.
const INS_GET_DATA: u8 = 0xCB;
/// GENERATE ASYMMETRIC KEY PAIR: gera chave no slot (SP 800-73 §3.2.5).
const INS_GENERATE: u8 = 0x47;
/// GENERAL AUTHENTICATE: assina desafio com a chave do slot (SP 800-73 §3.2.6).
const INS_AUTHENTICATE: u8 = 0x87;
/// PUT DATA: grava o certificado do slot (SP 800-73 §3.2.4, F2d).
const INS_PUT_DATA: u8 = 0xDB;

// --- Slots e algoritmos (F2a) ----------------------------------------------------

/// Slot PIV Authentication (exige VERIFY no AUTHENTICATE).
const SLOT_PIV_AUTH: u8 = 0x9A;
/// Slot Digital Signature.
const SLOT_DIG_SIG: u8 = 0x9C;
/// Slot Key Management.
const SLOT_KEY_MGMT: u8 = 0x9D;
/// Slot Card Authentication.
const SLOT_CARD_AUTH: u8 = 0x9E;

/// Algoritmo P-256 (ECCP256, ID PIV `0x11`).
const ALG_P256: u8 = 0x11;
/// Algoritmo Ed25519 (ID Yubico `0xE0`).
const ALG_ED25519: u8 = 0xE0;

/// Desafio máximo aceito no AUTHENTICATE (bytes).
const MAX_CHALLENGE_LEN: usize = 512;

/// Teto do certificado por slot no PUT DATA (bytes).
///
/// Cobre DERs típicos de RSA-2048 (~1–1,5 KB) com folga para o invólucro
/// `70` do SP 800-73, sem deixar o blob cifrado `sys:piv` crescer sem
/// limite na flash. Acima disso `6A80` (dado inaceitável com framing
/// válido — mesma escolha do GENERATE para algoritmo inválido), nunca
/// `6700` (reservado a erro de Lc no nível da APDU, já tratado no
/// roteador).
const MAX_CERT_LEN: usize = 2048;

// --- Tags de objetos de dados ---------------------------------------------------

/// Objeto de descoberta PIV (Discovery Object).
const TAG_DISCOVERY: u8 = 0x7E;
/// Tag do Card Holder Unique Identifier (CHUID).
const TAG_CHUID: &[u8] = &[0x5F, 0xC1, 0x02];

// --- Status Words -----------------------------------------------------------------

/// CLA diferente de `0x00` (mesma política do applet OATH).
const SW_CLASS_NOT_SUPPORTED: u16 = 0x6E00;
/// Dados/formato inválidos (ex.: CHANGE com tamanho errado, PIN novo curto).
const SW_WRONG_SYNTAX: u16 = 0x6A80;

/// Codifica as tentativas restantes como `63Cx` (verificação falhou / status).
const fn sw_retries(left: u8) -> u16 {
    0x63C0 | (left & 0x0F) as u16
}

// --- Estado -------------------------------------------------------------------------}

/// Chave PIV residente num slot (material privado cifrado em repouso).
struct PivKey {
    /// Slot (`9A`/`9C`/`9D`/`9E`).
    slot: u8,
    /// Algoritmo (`0x11` P-256, `0xE0` Ed25519).
    alg: u8,
    /// Privada: seed Ed25519 (32B) ou PKCS#8 P-256.
    priv_key: Vec<u8>,
    /// Pública: 32B (Ed25519) ou `04||x||y` 65B (P-256).
    pub_key: Vec<u8>,
}

/// Certificado PIV residente num slot (bytes guardados verbatim, F2d).
struct PivCert {
    /// Slot (`9A`/`9C`/`9D`/`9E`).
    slot: u8,
    /// Objeto do certificado (em geral `70…` do SP 800-73, ou DER cru).
    der: Vec<u8>,
}

/// Estado do applet PIV (persistido cifrado sob `sys:piv`).
struct PivState {
    /// PIN atual (bytes significativos, sem preenchimento `0xFF`).
    pin: Vec<u8>,
    /// Tentativas restantes (`0` = bloqueado até troca bem-sucedida).
    retries: u8,
    /// Chaves residentes por slot (F2a).
    keys: Vec<PivKey>,
    /// Certificados residentes por slot (F2d).
    certs: Vec<PivCert>,
}

impl fmt::Debug for PivState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redigido: PIN, chaves e certificados nunca aparecem em logs.
        let slots: Vec<u8> = self.keys.iter().map(|k| k.slot).collect();
        let cert_slots: Vec<u8> = self.certs.iter().map(|c| c.slot).collect();
        let cert_lens: Vec<usize> = self.certs.iter().map(|c| c.der.len()).collect();
        f.debug_struct("PivState")
            .field("pin_len", &self.pin.len())
            .field("retries", &self.retries)
            .field("key_count", &self.keys.len())
            .field("slots", &slots)
            .field("cert_count", &self.certs.len())
            .field("cert_slots", &cert_slots)
            .field("cert_lens", &cert_lens)
            .finish()
    }
}

/// Serializa (F2d, versão `3`):
/// `[03][pin_len u8][pin][retries u8][num_keys u8][slot u8][alg u8]
///  [priv_len u16BE][priv][pub_len u16BE][pub]…[num_certs u8]
///  [slot u8][cert_len u16BE][cert]…`.
fn serialize_state(state: &PivState) -> Vec<u8> {
    let mut out = Vec::with_capacity(state.pin.len() + 4);
    out.push(STATE_FORMAT_VERSION);
    out.push(state.pin.len() as u8);
    out.extend_from_slice(&state.pin);
    out.push(state.retries);
    out.push(state.keys.len() as u8);
    for key in &state.keys {
        out.push(key.slot);
        out.push(key.alg);
        out.extend_from_slice(&(key.priv_key.len() as u16).to_be_bytes());
        out.extend_from_slice(&key.priv_key);
        out.extend_from_slice(&(key.pub_key.len() as u16).to_be_bytes());
        out.extend_from_slice(&key.pub_key);
    }
    out.push(state.certs.len() as u8);
    for cert in &state.certs {
        out.push(cert.slot);
        out.extend_from_slice(&(cert.der.len() as u16).to_be_bytes());
        out.extend_from_slice(&cert.der);
    }
    out
}

/// Rejeita blobs com versão desconhecida, PIN fora de `6..=8` ou sobra de bytes.
fn parse_state(blob: &[u8]) -> Option<PivState> {
    if blob.is_empty() {
        return None;
    }
    match blob[0] {
        1 => parse_state_v1(blob),
        2 => parse_state_v2(blob),
        STATE_FORMAT_VERSION => parse_state_v3(blob),
        _ => None,
    }
}

/// Formato F1 (`v1`): `[01][pin_len u8][pin][retries u8]`; migra para F2a
/// com a lista de chaves vazia.
fn parse_state_v1(blob: &[u8]) -> Option<PivState> {
    if blob.len() < 3 || blob[0] != 1 {
        return None;
    }
    let pin_len = usize::from(blob[1]);
    if !(MIN_PIN_LEN..=MAX_PIN_LEN).contains(&pin_len) {
        return None;
    }
    if blob.len() != 2 + pin_len + 1 {
        return None;
    }
    let pin = blob[2..2 + pin_len].to_vec();
    let retries = blob[2 + pin_len];
    if retries > MAX_RETRIES {
        return None;
    }
    Some(PivState {
        pin,
        retries,
        keys: Vec::new(),
        certs: Vec::new(),
    })
}

/// Formato F2a (`v2`, como [`serialize_state`] sem o sufixo de certs).
fn parse_state_v2(blob: &[u8]) -> Option<PivState> {
    if blob.len() < 4 || blob[0] != 2 {
        return None;
    }
    let pin_len = usize::from(blob[1]);
    if !(MIN_PIN_LEN..=MAX_PIN_LEN).contains(&pin_len) {
        return None;
    }
    if blob.len() < 2 + pin_len + 2 {
        return None;
    }
    let pin = blob[2..2 + pin_len].to_vec();
    let retries = blob[2 + pin_len];
    if retries > MAX_RETRIES {
        return None;
    }
    let num_keys = usize::from(blob[2 + pin_len + 1]);
    let mut cursor = 2 + pin_len + 2;
    let mut keys = Vec::new();
    for _ in 0..num_keys {
        if blob.len() < cursor + 2 + 2 {
            return None;
        }
        let slot = blob[cursor];
        let alg = blob[cursor + 1];
        if !is_valid_slot(slot) || !is_valid_alg(alg) {
            return None;
        }
        let priv_len = u16::from_be_bytes([blob[cursor + 2], blob[cursor + 3]]) as usize;
        cursor += 4;
        if blob.len() < cursor + priv_len + 2 {
            return None;
        }
        let priv_key = blob[cursor..cursor + priv_len].to_vec();
        cursor += priv_len;
        let pub_len = u16::from_be_bytes([blob[cursor], blob[cursor + 1]]) as usize;
        cursor += 2;
        if blob.len() < cursor + pub_len {
            return None;
        }
        let pub_key = blob[cursor..cursor + pub_len].to_vec();
        cursor += pub_len;
        if !key_lengths_ok(alg, priv_key.len(), pub_key.len()) {
            return None;
        }
        keys.push(PivKey {
            slot,
            alg,
            priv_key,
            pub_key,
        });
    }
    if cursor != blob.len() {
        return None;
    }
    // Sem slots duplicados.
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            if keys[i].slot == keys[j].slot {
                return None;
            }
        }
    }
    Some(PivState {
        pin,
        retries,
        keys,
        certs: Vec::new(),
    })
}

/// Formato F2d (`v3`, ver [`serialize_state`]).
fn parse_state_v3(blob: &[u8]) -> Option<PivState> {
    if blob.len() < 5 || blob[0] != STATE_FORMAT_VERSION {
        return None;
    }
    let pin_len = usize::from(blob[1]);
    if !(MIN_PIN_LEN..=MAX_PIN_LEN).contains(&pin_len) {
        return None;
    }
    if blob.len() < 2 + pin_len + 2 {
        return None;
    }
    let pin = blob[2..2 + pin_len].to_vec();
    let retries = blob[2 + pin_len];
    if retries > MAX_RETRIES {
        return None;
    }
    let num_keys = usize::from(blob[2 + pin_len + 1]);
    let mut cursor = 2 + pin_len + 2;
    let mut keys = Vec::new();
    for _ in 0..num_keys {
        if blob.len() < cursor + 2 + 2 {
            return None;
        }
        let slot = blob[cursor];
        let alg = blob[cursor + 1];
        if !is_valid_slot(slot) || !is_valid_alg(alg) {
            return None;
        }
        let priv_len = u16::from_be_bytes([blob[cursor + 2], blob[cursor + 3]]) as usize;
        cursor += 4;
        if blob.len() < cursor + priv_len + 2 {
            return None;
        }
        let priv_key = blob[cursor..cursor + priv_len].to_vec();
        cursor += priv_len;
        let pub_len = u16::from_be_bytes([blob[cursor], blob[cursor + 1]]) as usize;
        cursor += 2;
        if blob.len() < cursor + pub_len {
            return None;
        }
        let pub_key = blob[cursor..cursor + pub_len].to_vec();
        cursor += pub_len;
        if !key_lengths_ok(alg, priv_key.len(), pub_key.len()) {
            return None;
        }
        keys.push(PivKey {
            slot,
            alg,
            priv_key,
            pub_key,
        });
    }
    if blob.len() < cursor + 1 {
        return None;
    }
    let num_certs = usize::from(blob[cursor]);
    cursor += 1;
    let mut certs = Vec::new();
    for _ in 0..num_certs {
        if blob.len() < cursor + 1 + 2 {
            return None;
        }
        let slot = blob[cursor];
        if !is_valid_slot(slot) {
            return None;
        }
        let cert_len = u16::from_be_bytes([blob[cursor + 1], blob[cursor + 2]]) as usize;
        cursor += 3;
        if cert_len == 0 || cert_len > MAX_CERT_LEN {
            return None;
        }
        if blob.len() < cursor + cert_len {
            return None;
        }
        let der = blob[cursor..cursor + cert_len].to_vec();
        cursor += cert_len;
        certs.push(PivCert { slot, der });
    }
    if cursor != blob.len() {
        return None;
    }
    // Sem slots duplicados (chaves e certificados, separadamente).
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            if keys[i].slot == keys[j].slot {
                return None;
            }
        }
    }
    for i in 0..certs.len() {
        for j in (i + 1)..certs.len() {
            if certs[i].slot == certs[j].slot {
                return None;
            }
        }
    }
    Some(PivState {
        pin,
        retries,
        keys,
        certs,
    })
}

/// Slot conhecido da F2a.
const fn is_valid_slot(slot: u8) -> bool {
    matches!(
        slot,
        SLOT_PIV_AUTH | SLOT_DIG_SIG | SLOT_KEY_MGMT | SLOT_CARD_AUTH
    )
}

/// Algoritmo suportado na F2a.
const fn is_valid_alg(alg: u8) -> bool {
    matches!(alg, ALG_P256 | ALG_ED25519)
}

/// Sanidade dos comprimentos por algoritmo (evita blob adulterado).
const fn key_lengths_ok(alg: u8, priv_len: usize, pub_len: usize) -> bool {
    match alg {
        ALG_ED25519 => priv_len == 32 && pub_len == 32,
        ALG_P256 => priv_len > 32 && priv_len <= 256 && pub_len == 65,
        _ => false,
    }
}

/// Tag de objeto de chave por slot (`GET DATA`).
const fn slot_tag(slot: u8) -> Option<&'static [u8]> {
    match slot {
        SLOT_PIV_AUTH => Some(&[0x5F, 0xC1, 0x05]),
        SLOT_DIG_SIG => Some(&[0x5F, 0xC1, 0x0A]),
        SLOT_KEY_MGMT => Some(&[0x5F, 0xC1, 0x0B]),
        SLOT_CARD_AUTH => Some(&[0x5F, 0xC1, 0x0C]),
        _ => None,
    }
}

/// Slot a partir da tag do `GET DATA` (`None` = tag fora do mapa de chaves).
fn slot_from_tag(tag: &[u8]) -> Option<u8> {
    [SLOT_PIV_AUTH, SLOT_DIG_SIG, SLOT_KEY_MGMT, SLOT_CARD_AUTH]
        .into_iter()
        .find(|&slot| slot_tag(slot) == Some(tag))
}

/// Extrai o ID do algoritmo do campo de dados do `GENERATE`:
/// `AC 03 80 01 <alg>` ou o byte único `<alg>`.
fn parse_generate_alg(data: &[u8]) -> Option<u8> {
    if data.len() == 1 && is_valid_alg(data[0]) {
        return Some(data[0]);
    }
    if data.len() == 5 && data[0] == 0xAC && data[1] == 0x03 && data[2] == 0x80 && data[3] == 0x01 {
        return is_valid_alg(data[4]).then_some(data[4]);
    }
    None
}

/// Monta o objeto de chave pública `7F49 [80 01 alg][86 pubkey]`.
fn pubkey_object(alg: u8, pub_key: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(3 + 2 + pub_key.len());
    inner.extend_from_slice(&[0x80, 0x01, alg]);
    inner.push(0x86);
    inner.push(pub_key.len() as u8);
    inner.extend_from_slice(pub_key);
    let mut out = Vec::with_capacity(inner.len() + 3);
    out.extend_from_slice(&[0x7F, 0x49, inner.len() as u8]);
    out.extend_from_slice(&inner);
    out
}

/// Extrai o desafio do `AUTHENTICATE`: bruto ou `7C <len> 81 <len> <desafio>`.
fn extract_challenge(data: &[u8]) -> Option<&[u8]> {
    if data.is_empty() || data.len() > MAX_CHALLENGE_LEN {
        return None;
    }
    if data[0] != 0x7C {
        return Some(data);
    }
    if data.len() < 2 || usize::from(data[1]) + 2 != data.len() {
        return None;
    }
    let inner = &data[2..];
    if inner.len() < 2 || inner[0] != 0x81 {
        return None;
    }
    let len = usize::from(inner[1]);
    if inner.len() < 2 + len || len == 0 {
        return None;
    }
    Some(&inner[2..2 + len])
}

/// Empacota um TLV de forma curta (valor ≤255 bytes) ao final de `out`.
fn push_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    assert!(value.len() <= 255, "TLV value exceeds short form");
    out.push(tag);
    out.push(value.len() as u8);
    out.extend_from_slice(value);
}

/// Remove o preenchimento `0xFF` do PIN no fio (SP 800-73 §3.2).
fn strip_pin_padding(padded: &[u8]) -> &[u8] {
    let mut end = padded.len();
    while end > 0 && padded[end - 1] == 0xFF {
        end -= 1;
    }
    &padded[..end]
}

// --- Applet ---------------------------------------------------------------------------

/// Applet ISO 7816-4 da aplicação PIV (fase F2a: PIN + chaves Ed25519/P-256).
pub struct PivApplet<'a> {
    /// Storage compartilhado com os demais applets (mesmo kv).
    storage: &'a core::cell::RefCell<StorageEngine>,
    crypto: CryptoEngine,
    state: Option<PivState>,
    /// Sessão verificada via VERIFY (volátil: não persiste; nasce `false`).
    verified: bool,
}

impl fmt::Debug for PivApplet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redigido: o estado carrega PIN e chaves; nada além de contagens.
        f.debug_struct("PivApplet")
            .field("loaded", &self.state.is_some())
            .field("retries", &self.state.as_ref().map(|s| s.retries))
            .field("key_count", &self.state.as_ref().map(|s| s.keys.len()))
            .field("cert_count", &self.state.as_ref().map(|s| s.certs.len()))
            .field("verified", &self.verified)
            .finish()
    }
}

/// Extrai `(slot, bytes-do-certificado)` do campo de dados do `PUT DATA`.
///
/// Layout: `<tag-cert 3B> <len-BER> <bytes>` com a tag no mapa de
/// `slot_tag`, comprimento curto (`len < 0x80`), `81 len` ou `82 lenHi
/// lenLo`, e consumo exato (sem sobra). Rejeita valor vazio ou acima de
/// [`MAX_CERT_LEN`].
fn parse_put_data(data: &[u8]) -> Option<(u8, &[u8])> {
    if data.len() < 4 {
        return None;
    }
    let slot = slot_from_tag(&data[..3])?;
    let (value_len, header_len) = match data[3] {
        short if short < 0x80 => (usize::from(short), 4),
        0x81 => {
            if data.len() < 5 {
                return None;
            }
            (usize::from(data[4]), 5)
        }
        0x82 => {
            if data.len() < 6 {
                return None;
            }
            (usize::from(u16::from_be_bytes([data[4], data[5]])), 6)
        }
        _ => return None,
    };
    if value_len == 0 || value_len > MAX_CERT_LEN {
        return None;
    }
    if data.len() != header_len + value_len {
        return None;
    }
    Some((slot, &data[header_len..]))
}

impl<'a> PivApplet<'a> {
    /// Cria o applet sobre o storage e o motor criptográfico fornecidos.
    ///
    /// Carrega (ou inicializa) o estado persistido: registro ausente é criado
    /// com o PIN padrão de fábrica; registro ilegível (chave-mestra trocada
    /// ou dado corrompido) volta ao estado de fábrica com log — mesma
    /// política dos applets OATH/Management.
    pub fn new(
        storage: &'a core::cell::RefCell<StorageEngine>,
        crypto: CryptoEngine,
    ) -> Result<Self, Box<dyn core::error::Error>> {
        let mut applet = Self {
            storage,
            crypto,
            state: None,
            verified: false,
        };
        applet
            .ensure_loaded()
            .map_err(|sw| format!("PIV init failed with SW {:#06X}", sw))?;
        Ok(applet)
    }

    /// Garante o estado em memória, criando registro de fábrica se preciso.
    ///
    /// Blobs F1 (`versão 1`, só PIN) e F2a (`versão 2`, PIN + chaves)
    /// migram para F2d com os campos ausentes vazios (PIN/retries/chaves
    /// preservados) e são regravados já no formato `3`.
    fn ensure_loaded(&mut self) -> Result<(), u16> {
        if self.state.is_some() {
            return Ok(());
        }
        let mut migrated = false;
        let loaded = match self.storage.borrow().retrieve(STORAGE_KEY) {
            Ok(blob) if blob.len() > 12 => {
                let (nonce, ciphertext) = blob.split_at(12);
                match self.crypto.decrypt(ciphertext, nonce) {
                    Ok(plaintext) => {
                        migrated =
                            !plaintext.is_empty() && (plaintext[0] == 1 || plaintext[0] == 2);
                        parse_state(&plaintext)
                    }
                    Err(_) => None,
                }
            }
            _ => None,
        };
        match loaded {
            Some(state) => {
                self.state = Some(state);
                if migrated {
                    self.persist_state()?;
                }
                Ok(())
            }
            None => {
                if self.storage.borrow().retrieve(STORAGE_KEY).is_ok() {
                    warn!("PIV state unreadable; resetting to factory defaults");
                }
                let state = PivState {
                    pin: DEFAULT_PIN.to_vec(),
                    retries: MAX_RETRIES,
                    keys: Vec::new(),
                    certs: Vec::new(),
                };
                self.state = Some(state);
                self.persist_state()
            }
        }
    }

    /// Referência mutável ao estado já carregado (`ensure_loaded` antes).
    fn state_mut(&mut self) -> Result<&mut PivState, u16> {
        if self.state.is_none() {
            self.ensure_loaded()?;
        }
        Ok(self.state.as_mut().expect("state loaded by ensure_loaded"))
    }

    /// Serializa, cifra (nonce aleatório) e grava o estado atual.
    fn persist_state(&mut self) -> Result<(), u16> {
        let plaintext = serialize_state(
            self.state
                .as_ref()
                .ok_or(transport::iso7816::SW_CONDITIONS_NOT_SATISFIED)?,
        );
        let (nonce, ciphertext) = self
            .crypto
            .encrypt_with_random_nonce(&plaintext)
            .map_err(|_| transport::iso7816::SW_CONDITIONS_NOT_SATISFIED)?;
        let mut blob = Vec::with_capacity(nonce.len() + ciphertext.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        self.storage
            .borrow_mut()
            .store(STORAGE_KEY, blob)
            .map_err(|e| {
                warn!("PIV persistence failed: {}", e);
                transport::iso7816::SW_CONDITIONS_NOT_SATISFIED
            })
    }

    /// Consome uma tentativa e persiste; esgotadas, bloqueia (`6982`) e
    /// derruba a sessão verificada.
    fn consume_retry(&mut self) -> Result<u16, u16> {
        let sw = {
            let state = self.state_mut()?;
            state.retries = state.retries.saturating_sub(1);
            if state.retries == 0 {
                transport::iso7816::SW_SECURITY_STATUS
            } else {
                sw_retries(state.retries)
            }
        };
        if sw == transport::iso7816::SW_SECURITY_STATUS {
            self.verified = false;
        }
        self.persist_state()?;
        Ok(sw)
    }

    /// Busca pública da chave do slot: `(alg, pubkey)`.
    fn find_key_public(&mut self, slot: u8) -> Result<Option<(u8, Vec<u8>)>, u16> {
        self.ensure_loaded()?;
        let state = self.state.as_ref().expect("loaded above");
        Ok(state
            .keys
            .iter()
            .find(|k| k.slot == slot)
            .map(|k| (k.alg, k.pub_key.clone())))
    }

    /// Busca pública do certificado do slot (bytes verbatim, F2d).
    fn find_cert(&mut self, slot: u8) -> Result<Option<Vec<u8>>, u16> {
        self.ensure_loaded()?;
        let state = self.state.as_ref().expect("loaded above");
        Ok(state
            .certs
            .iter()
            .find(|c| c.slot == slot)
            .map(|c| c.der.clone()))
    }

    /// Monta o objeto de descoberta (placeholder F1: AID dentro de `0x7E`).
    fn discovery_object() -> Vec<u8> {
        let mut inner = Vec::new();
        push_tlv(&mut inner, 0x4F, AID_PIV);
        let mut out = Vec::with_capacity(inner.len() + 2);
        push_tlv(&mut out, TAG_DISCOVERY, &inner);
        out
    }

    /// Monta o CHUID (placeholder F1: rótulo fixo dentro da tag `0x5FC102`).
    fn chuid_object() -> Vec<u8> {
        let mut content = Vec::new();
        push_tlv(&mut content, 0x30, b"OpenKey-PIV-F1");
        let mut out = Vec::with_capacity(content.len() + 4);
        out.extend_from_slice(TAG_CHUID);
        out.push(content.len() as u8);
        out.extend_from_slice(&content);
        out
    }

    fn cmd_get_data(&mut self, apdu: &Apdu) -> Result<ResponseData, u16> {
        // SP 800-73: GET DATA usa P1=0x3F P2=0xFF com a tag no campo de dados.
        if apdu.p1 != 0x3F || apdu.p2 != 0xFF {
            return Err(transport::iso7816::SW_WRONG_P1_P2);
        }
        if apdu.data == [TAG_DISCOVERY] {
            Ok(ResponseData::ok(Self::discovery_object()))
        } else if apdu.data == TAG_CHUID {
            Ok(ResponseData::ok(Self::chuid_object()))
        } else if let Some(slot) = slot_from_tag(apdu.data) {
            // F2d: o certificado vence o objeto de chave (é o que hosts
            // como `ykman piv` leem após `import-certificate`).
            if let Some(der) = self.find_cert(slot)? {
                return Ok(ResponseData::ok(der));
            }
            match self.find_key_public(slot)? {
                Some((alg, pub_key)) => Ok(ResponseData::ok(pubkey_object(alg, &pub_key))),
                // Slot conhecido sem chave nem certificado: condição de
                // segurança, não ausência.
                None => Err(transport::iso7816::SW_SECURITY_STATUS),
            }
        } else {
            // Tag desconhecida: objeto inexistente.
            Err(transport::iso7816::SW_FILE_NOT_FOUND)
        }
    }

    /// PUT DATA (`0xDB`, F2d): grava o certificado do slot.
    ///
    /// `P1=0x3F`, `P2=0xFF`; tag fora do mapa → `6A82`; TLV malformado,
    /// valor vazio ou acima de [`MAX_CERT_LEN`] → `6A80`. Slot `9A` exige
    /// sessão verificada (`6982`); demais slots seguem a política F2a
    /// (abertos, como no AUTHENTICATE). Sobrescreve o certificado do slot
    /// (bytes antigos zeroizados); não exige chave residente.
    fn cmd_put_data(&mut self, apdu: &Apdu) -> Result<ResponseData, u16> {
        if apdu.p1 != 0x3F || apdu.p2 != 0xFF {
            return Err(transport::iso7816::SW_WRONG_P1_P2);
        }
        // Tag fora do mapa de certificados: objeto inexistente.
        if apdu.data.len() >= 3 && slot_from_tag(&apdu.data[..3]).is_none() {
            return Err(transport::iso7816::SW_FILE_NOT_FOUND);
        }
        let (slot, der) = parse_put_data(apdu.data).ok_or_else(|| {
            if apdu.data.len() >= 3 && slot_from_tag(&apdu.data[..3]).is_some() {
                SW_WRONG_SYNTAX
            } else {
                transport::iso7816::SW_FILE_NOT_FOUND
            }
        })?;
        if slot == SLOT_PIV_AUTH && !self.verified {
            return Err(transport::iso7816::SW_SECURITY_STATUS);
        }
        {
            let state = self.state_mut()?;
            if let Some(existing) = state.certs.iter_mut().find(|c| c.slot == slot) {
                existing.der.zeroize();
                existing.der = der.to_vec();
            } else {
                state.certs.push(PivCert {
                    slot,
                    der: der.to_vec(),
                });
            }
        }
        if let Err(sw) = self.persist_state() {
            // Rollback em memória se a persistência falhar.
            if let Ok(state) = self.state_mut() {
                state.certs.retain(|c| c.slot != slot);
            }
            return Err(sw);
        }
        debug!(
            "PIV PUT DATA succeeded (slot={:#04X}, len={})",
            slot,
            der.len()
        );
        Ok(ResponseData::ok(Vec::new()))
    }

    /// GENERATE ASYMMETRIC KEY PAIR (`0x47`): `P1=0x00`, `P2=slot`.
    fn cmd_generate(&mut self, apdu: &Apdu) -> Result<ResponseData, u16> {
        if apdu.p1 != 0x00 {
            return Err(transport::iso7816::SW_WRONG_P1_P2);
        }
        if !is_valid_slot(apdu.p2) {
            return Err(transport::iso7816::SW_FILE_NOT_FOUND);
        }
        let alg = parse_generate_alg(apdu.data).ok_or(SW_WRONG_SYNTAX)?;
        let (priv_key, pub_key) = match alg {
            ALG_ED25519 => self
                .crypto
                .generate_key_pair()
                .map_err(|_| transport::iso7816::SW_CONDITIONS_NOT_SATISFIED)?,
            ALG_P256 => self
                .crypto
                .generate_p256_key_pair()
                .map_err(|_| transport::iso7816::SW_CONDITIONS_NOT_SATISFIED)?,
            _ => return Err(SW_WRONG_SYNTAX),
        };
        let slot = apdu.p2;
        {
            let state = self.state_mut()?;
            // Regeneração sobrescreve: zera a privada antiga antes de trocar
            // e apaga o certificado do slot (vinculava a chave anterior).
            if let Some(existing) = state.keys.iter_mut().find(|k| k.slot == slot) {
                existing.priv_key.zeroize();
                existing.alg = alg;
                existing.priv_key = priv_key;
                existing.pub_key = pub_key.clone();
            } else {
                state.keys.push(PivKey {
                    slot,
                    alg,
                    priv_key,
                    pub_key: pub_key.clone(),
                });
            }
            for cert in &mut state.certs {
                if cert.slot == slot {
                    cert.der.zeroize();
                }
            }
            state.certs.retain(|c| c.slot != slot);
        }
        if let Err(sw) = self.persist_state() {
            // Rollback em memória se a persistência falhar: remove a chave
            // recém-gravada para não divergir do storage.
            if let Ok(state) = self.state_mut() {
                state.keys.retain(|k| k.slot != slot);
            }
            return Err(sw);
        }
        debug!("PIV GENERATE succeeded (slot={:#04X})", slot);
        Ok(ResponseData::ok(pubkey_object(alg, &pub_key)))
    }

    /// GENERAL AUTHENTICATE (`0x87`): assina o desafio com a chave do slot.
    ///
    /// `P1=<alg|0x00>`, `P2=slot`. Slot `9A` exige sessão verificada
    /// (`6982` caso contrário); slot desconhecido → `6A82`; sem chave →
    /// `6982`; `P1` divergente do algoritmo residente → `6A80`.
    fn cmd_authenticate(&mut self, apdu: &Apdu) -> Result<ResponseData, u16> {
        let slot = apdu.p2;
        if !is_valid_slot(slot) {
            return Err(transport::iso7816::SW_FILE_NOT_FOUND);
        }
        if slot == SLOT_PIV_AUTH && !self.verified {
            return Err(transport::iso7816::SW_SECURITY_STATUS);
        }
        let challenge = extract_challenge(apdu.data).ok_or(SW_WRONG_SYNTAX)?;
        // Escopo do borrow da chave: a assinatura sai owned, sem reter refs.
        let (alg, mut priv_copy) = {
            self.ensure_loaded()?;
            let state = self.state.as_ref().expect("loaded above");
            let key = state
                .keys
                .iter()
                .find(|k| k.slot == slot)
                .ok_or(transport::iso7816::SW_SECURITY_STATUS)?;
            if apdu.p1 != 0x00 && apdu.p1 != key.alg {
                return Err(SW_WRONG_SYNTAX);
            }
            (key.alg, key.priv_key.clone())
        };
        let sig = match alg {
            ALG_ED25519 => self.crypto.sign(challenge, &priv_copy),
            ALG_P256 => self.crypto.sign_p256(&priv_copy, challenge),
            _ => return Err(SW_WRONG_SYNTAX),
        };
        priv_copy.zeroize();
        match sig {
            Ok(signature) => {
                debug!("PIV AUTHENTICATE succeeded (slot={:#04X})", slot);
                Ok(ResponseData::ok(signature))
            }
            Err(_) => Err(transport::iso7816::SW_CONDITIONS_NOT_SATISFIED),
        }
    }

    fn cmd_verify(&mut self, apdu: &Apdu) -> Result<ResponseData, u16> {
        if apdu.p1 != 0x00 || apdu.p2 != 0x80 {
            return Err(transport::iso7816::SW_WRONG_P1_P2);
        }
        self.ensure_loaded()?;
        let blocked = self.state.as_ref().expect("loaded above").retries == 0;
        if blocked {
            return Err(transport::iso7816::SW_SECURITY_STATUS);
        }
        if apdu.data.is_empty() {
            // Consulta de status: tentativas restantes, sem consumir.
            let left = self.state.as_ref().expect("loaded above").retries;
            debug!("PIV VERIFY status query (retries={})", left);
            return Ok(ResponseData::with_sw(Vec::new(), sw_retries(left)));
        }
        let candidate = strip_pin_padding(apdu.data).to_vec();
        let matches = {
            let state = self.state_mut()?;
            constant_time_eq(&candidate, &state.pin)
        };
        if matches {
            {
                let state = self.state_mut()?;
                state.retries = MAX_RETRIES;
            }
            self.persist_state()?;
            self.verified = true;
            debug!("PIV VERIFY succeeded");
            Ok(ResponseData::ok(Vec::new()))
        } else {
            debug!("PIV VERIFY failed");
            Err(self.consume_retry()?)
        }
    }

    fn cmd_change_reference_data(&mut self, apdu: &Apdu) -> Result<ResponseData, u16> {
        if apdu.p1 != 0x00 || apdu.p2 != 0x80 {
            return Err(transport::iso7816::SW_WRONG_P1_P2);
        }
        self.ensure_loaded()?;
        if self.state.as_ref().expect("loaded above").retries == 0 {
            return Err(transport::iso7816::SW_SECURITY_STATUS);
        }
        // Layout F1: `PIN_atual(8B FF-padded) || PIN_novo(8B FF-padded)`.
        if apdu.data.len() != 2 * PIN_WIRE_LEN {
            return Err(SW_WRONG_SYNTAX);
        }
        let new_pin = strip_pin_padding(&apdu.data[PIN_WIRE_LEN..]).to_vec();
        if !(MIN_PIN_LEN..=MAX_PIN_LEN).contains(&new_pin.len()) {
            // Formato do PIN novo inválido: rejeita sem consumir tentativa.
            return Err(SW_WRONG_SYNTAX);
        }
        let old_pin = strip_pin_padding(&apdu.data[..PIN_WIRE_LEN]).to_vec();
        let matches = {
            let state = self.state_mut()?;
            constant_time_eq(&old_pin, &state.pin)
        };
        if !matches {
            debug!("PIV CHANGE REFERENCE DATA failed (wrong current PIN)");
            return Err(self.consume_retry()?);
        }
        {
            let state = self.state_mut()?;
            state.pin = new_pin;
            state.retries = MAX_RETRIES;
        }
        self.persist_state()?;
        self.verified = true;
        debug!("PIV CHANGE REFERENCE DATA applied");
        Ok(ResponseData::ok(Vec::new()))
    }
}

impl Applet for PivApplet<'_> {
    fn aid(&self) -> &[u8] {
        AID_PIV
    }

    fn select(&mut self) -> Result<(), u16> {
        self.ensure_loaded()
    }

    fn process(&mut self, apdu: &Apdu) -> Result<ResponseData, u16> {
        if apdu.cla != 0x00 {
            return Err(SW_CLASS_NOT_SUPPORTED);
        }
        match apdu.ins {
            INS_VERIFY => self.cmd_verify(apdu),
            INS_CHANGE_REFERENCE_DATA => self.cmd_change_reference_data(apdu),
            INS_GET_DATA => self.cmd_get_data(apdu),
            INS_GENERATE => self.cmd_generate(apdu),
            INS_AUTHENTICATE => self.cmd_authenticate(apdu),
            INS_PUT_DATA => self.cmd_put_data(apdu),
            _ => Err(transport::iso7816::SW_INS_NOT_SUPPORTED),
        }
    }
}

impl Drop for PivApplet<'_> {
    fn drop(&mut self) {
        // Zera PIN, chaves privadas e certificados remanescentes em
        // memória (regra do repo).
        if let Some(mut state) = self.state.take() {
            state.pin.zeroize();
            for key in &mut state.keys {
                key.priv_key.zeroize();
            }
            for cert in &mut state.certs {
                cert.der.zeroize();
            }
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use storage::FileStorageBackend;
    use transport::iso7816::{CardRouter, INS_SELECT, SW_NO_ERROR};

    /// Chave-mestra fixa: permite recriar o applet sobre o mesmo arquivo,
    /// simulando um reinício do dispositivo com a mesma chave.
    const MASTER_KEY: [u8; 32] = [21u8; 32];

    fn make_applet(storage: &core::cell::RefCell<StorageEngine>) -> PivApplet<'_> {
        PivApplet::new(storage, CryptoEngine::from_key(MASTER_KEY)).unwrap()
    }

    fn open_persistent<'a>(
        storage: &'a core::cell::RefCell<StorageEngine>,
        path: &std::path::Path,
    ) -> PivApplet<'a> {
        let backend = FileStorageBackend::new(path.to_path_buf()).unwrap();
        *storage.borrow_mut() = StorageEngine::with_backend(Box::new(backend));
        PivApplet::new(storage, CryptoEngine::from_key(MASTER_KEY)).unwrap()
    }

    fn temp_root(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("openkey-piv-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    /// Processa um frame bruto com semântica de applet: `Err(sw)` vira
    /// resposta vazia com a Status Word correspondente.
    fn run(applet: &mut PivApplet, raw: &[u8]) -> ResponseData {
        let apdu = Apdu::parse(raw).unwrap();
        match applet.process(&apdu) {
            Ok(response) => response,
            Err(sw) => ResponseData::with_sw(Vec::new(), sw),
        }
    }

    /// VERIFY caso 3S/2S: `00 20 00 80 [Lc pin]`.
    fn verify(pin: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, INS_VERIFY, 0x00, 0x80];
        if pin.is_empty() {
            return v;
        }
        v.push(pin.len() as u8);
        v.extend_from_slice(pin);
        v
    }

    /// CHANGE REFERENCE DATA: `00 24 00 80 10 old(8B) new(8B)`.
    fn change_ref(old_pin: &[u8], new_pin: &[u8]) -> Vec<u8> {
        let mut data = [0xFFu8; 16];
        data[..old_pin.len().min(8)].copy_from_slice(&old_pin[..old_pin.len().min(8)]);
        data[8..8 + new_pin.len().min(8)].copy_from_slice(&new_pin[..new_pin.len().min(8)]);
        let mut v = vec![0x00, INS_CHANGE_REFERENCE_DATA, 0x00, 0x80, 0x10];
        v.extend_from_slice(&data);
        v
    }

    /// GET DATA caso 3S: `00 CB 3F FF Lc tag`.
    fn get_data(tag: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, INS_GET_DATA, 0x3F, 0xFF, tag.len() as u8];
        v.extend_from_slice(tag);
        v
    }

    fn select_frame(aid: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, INS_SELECT, 0x04, 0x00, aid.len() as u8];
        v.extend_from_slice(aid);
        v
    }

    // --- helpers da fase F2a ---------------------------------------------------------

    /// GENERATE caso 3S: `00 47 00 <slot> Lc [AC 03 80 01 <alg>]`.
    fn generate(slot: u8, alg: u8) -> Vec<u8> {
        let data = [0xAC, 0x03, 0x80, 0x01, alg];
        let mut v = vec![0x00, INS_GENERATE, 0x00, slot, data.len() as u8];
        v.extend_from_slice(&data);
        v
    }

    /// AUTHENTICATE caso 3S: `00 87 <alg|00> <slot> Lc <challenge>`.
    fn authenticate(slot: u8, p1: u8, challenge: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, INS_AUTHENTICATE, p1, slot, challenge.len() as u8];
        v.extend_from_slice(challenge);
        v
    }

    /// AUTHENTICATE com desafio em invólucro `7C`: `7C <len> 81 <len> <c>`.
    fn authenticate_wrapped(slot: u8, challenge: &[u8]) -> Vec<u8> {
        let mut inner = vec![0x81, challenge.len() as u8];
        inner.extend_from_slice(challenge);
        let mut data = vec![0x7C, inner.len() as u8];
        data.extend_from_slice(&inner);
        let mut v = vec![0x00, INS_AUTHENTICATE, 0x00, slot, data.len() as u8];
        v.extend_from_slice(&data);
        v
    }

    /// VERIFY com o PIN padrão já com padding `0xFF`.
    fn verify_default() -> Vec<u8> {
        let mut pin = DEFAULT_PIN.to_vec();
        pin.extend_from_slice(&[0xFF, 0xFF]);
        verify(&pin)
    }

    /// Extrai `(alg, pubkey)` do objeto `7F49` devolvido por GENERATE/GET DATA.
    fn parse_pubkey_object(obj: &[u8]) -> (u8, Vec<u8>) {
        assert!(obj.len() >= 7);
        assert_eq!(&obj[..2], &[0x7F, 0x49]);
        let len = usize::from(obj[2]);
        assert_eq!(obj.len(), 3 + len);
        let inner = &obj[3..];
        assert_eq!(&inner[..3], &[0x80, 0x01, inner[2]]);
        let alg = inner[2];
        assert_eq!(inner[3], 0x86);
        let pub_len = usize::from(inner[4]);
        assert_eq!(inner.len(), 5 + pub_len);
        (alg, inner[5..].to_vec())
    }

    // --- ciclo de vida do PIN ------------------------------------------------------

    #[test]
    fn test_piv_aid_is_correct() {
        assert_eq!(
            AID_PIV,
            &[0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00]
        );
    }

    #[test]
    fn test_verify_lifecycle_status_success_and_retry_reset() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        // Status inicial: 3 tentativas, sem consumir.
        assert_eq!(run(&mut applet, &verify(&[])).sw, Some(sw_retries(3)));

        // PIN errado ("000000" FF-padded): consome uma tentativa.
        let mut wrong = b"000000".to_vec();
        wrong.extend_from_slice(&[0xFF, 0xFF]);
        assert_eq!(run(&mut applet, &verify(&wrong)).sw, Some(sw_retries(2)));
        assert_eq!(run(&mut applet, &verify(&[])).sw, Some(sw_retries(2)));

        // PIN padrão de fábrica autentica e restaura as tentativas.
        let mut good = DEFAULT_PIN.to_vec();
        good.extend_from_slice(&[0xFF, 0xFF]);
        assert_eq!(run(&mut applet, &verify(&good)).sw, None);
        assert_eq!(run(&mut applet, &verify(&[])).sw, Some(sw_retries(3)));
    }

    #[test]
    fn test_verify_blocked_returns_security_status() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        let mut wrong = b"000000".to_vec();
        wrong.extend_from_slice(&[0xFF, 0xFF]);
        assert_eq!(run(&mut applet, &verify(&wrong)).sw, Some(sw_retries(2)));
        assert_eq!(run(&mut applet, &verify(&wrong)).sw, Some(sw_retries(1)));
        // Terceira falha esgota: bloqueado.
        assert_eq!(
            run(&mut applet, &verify(&wrong)).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );
        // Bloqueado: até o PIN correto é rejeitado e o status confirma.
        let mut good = DEFAULT_PIN.to_vec();
        good.extend_from_slice(&[0xFF, 0xFF]);
        assert_eq!(
            run(&mut applet, &verify(&good)).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );
        assert_eq!(
            run(&mut applet, &verify(&[])).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );
    }

    #[test]
    fn test_change_reference_data_lifecycle() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        // PIN atual errado consome tentativa sem trocar.
        assert_eq!(
            run(&mut applet, &change_ref(b"000000", b"654321")).sw,
            Some(sw_retries(2))
        );

        // Troca com o PIN atual correto.
        assert_eq!(
            run(&mut applet, &change_ref(DEFAULT_PIN, b"654321")).sw,
            None
        );

        // PIN novo autentica; PIN antigo não.
        let mut new_padded = b"654321".to_vec();
        new_padded.extend_from_slice(&[0xFF, 0xFF]);
        assert_eq!(run(&mut applet, &verify(&new_padded)).sw, None);
        let mut old_padded = DEFAULT_PIN.to_vec();
        old_padded.extend_from_slice(&[0xFF, 0xFF]);
        assert_eq!(
            run(&mut applet, &verify(&old_padded)).sw,
            Some(sw_retries(2))
        );
    }

    #[test]
    fn test_change_reference_data_rejects_short_new_pin_without_retry() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        // PIN novo de 2 bytes: formato inválido, sem consumir tentativa.
        assert_eq!(
            run(&mut applet, &change_ref(DEFAULT_PIN, b"12")).sw,
            Some(SW_WRONG_SYNTAX)
        );
        assert_eq!(run(&mut applet, &verify(&[])).sw, Some(sw_retries(3)));
    }

    // --- persistência entre reinícios ------------------------------------------------

    #[test]
    fn test_retries_persist_across_restart() {
        let root = temp_root("retries");
        let path = root.join("store.json");

        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut first = open_persistent(&storage, &path);
        let mut wrong = b"000000".to_vec();
        wrong.extend_from_slice(&[0xFF, 0xFF]);
        assert_eq!(run(&mut first, &verify(&wrong)).sw, Some(sw_retries(2)));
        drop(first);

        // Recria o applet sobre o mesmo arquivo: contador não ressuscita.
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut second = open_persistent(&storage, &path);
        assert_eq!(run(&mut second, &verify(&[])).sw, Some(sw_retries(2)));

        // PIN correto ainda funciona e restaura — e a restauração persiste.
        let mut good = DEFAULT_PIN.to_vec();
        good.extend_from_slice(&[0xFF, 0xFF]);
        assert_eq!(run(&mut second, &verify(&good)).sw, None);
        drop(second);

        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut third = open_persistent(&storage, &path);
        assert_eq!(run(&mut third, &verify(&[])).sw, Some(sw_retries(3)));
    }

    #[test]
    fn test_changed_pin_persists_across_restart() {
        let root = temp_root("changed-pin");
        let path = root.join("store.json");

        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut first = open_persistent(&storage, &path);
        assert_eq!(
            run(&mut first, &change_ref(DEFAULT_PIN, b"654321")).sw,
            None
        );
        drop(first);

        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut second = open_persistent(&storage, &path);
        let mut new_padded = b"654321".to_vec();
        new_padded.extend_from_slice(&[0xFF, 0xFF]);
        assert_eq!(run(&mut second, &verify(&new_padded)).sw, None);
    }

    // --- objetos de dados e erros -----------------------------------------------------

    #[test]
    fn test_get_data_placeholders() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        let resp = run(&mut applet, &get_data(&[TAG_DISCOVERY]));
        assert_eq!(resp.sw, None);
        assert!(!resp.data.is_empty());
        assert_eq!(resp.data[0], TAG_DISCOVERY);

        let resp = run(&mut applet, &get_data(TAG_CHUID));
        assert_eq!(resp.sw, None);
        assert!(!resp.data.is_empty());
        assert_eq!(&resp.data[..3], TAG_CHUID);
    }

    #[test]
    fn test_get_data_unknown_tag_returns_file_not_found() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        assert_eq!(
            run(&mut applet, &get_data(&[0x5F, 0xC1, 0x01])).sw,
            Some(transport::iso7816::SW_FILE_NOT_FOUND)
        );
        assert_eq!(
            run(&mut applet, &get_data(&[0x01])).sw,
            Some(transport::iso7816::SW_FILE_NOT_FOUND)
        );
    }

    #[test]
    fn test_unknown_ins_returns_ins_not_supported() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        let apdu = Apdu::parse(&[0x00, 0x42, 0x00, 0x00]).unwrap();
        assert_eq!(
            applet.process(&apdu).unwrap_err(),
            transport::iso7816::SW_INS_NOT_SUPPORTED
        );
        // GENERATE com slot desconhecido é roteado ao handler (6A82, não 6D00).
        let apdu = Apdu::parse(&[0x00, 0x47, 0x00, 0x00, 0x01, 0xE0]).unwrap();
        assert_eq!(
            applet.process(&apdu).unwrap_err(),
            transport::iso7816::SW_FILE_NOT_FOUND
        );
    }

    #[test]
    fn test_wrong_p1p2_and_cla_are_rejected() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        // P2 errado no VERIFY.
        let raw = vec![0x00, INS_VERIFY, 0x00, 0x81, 0x00];
        assert_eq!(
            run(&mut applet, &raw).sw,
            Some(transport::iso7816::SW_WRONG_P1_P2)
        );
        // CLA errado.
        let raw = vec![0x80, INS_VERIFY, 0x00, 0x80, 0x00];
        assert_eq!(run(&mut applet, &raw).sw, Some(SW_CLASS_NOT_SUPPORTED));
    }

    // --- chaves F2a: GENERATE / GET DATA / AUTHENTICATE -------------------------------

    #[test]
    fn test_generate_ed25519_roundtrip_via_get_data_and_authenticate() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        let engine = CryptoEngine::from_key(MASTER_KEY);

        // Slot 9C não exige VERIFY: gera, lê e autentica direto.
        let resp = run(&mut applet, &generate(SLOT_DIG_SIG, ALG_ED25519));
        assert_eq!(resp.sw, None);
        let (alg, pubkey) = parse_pubkey_object(&resp.data);
        assert_eq!(alg, ALG_ED25519);
        assert_eq!(pubkey.len(), 32);

        // GET DATA do slot devolve o mesmo objeto.
        let tag = slot_tag(SLOT_DIG_SIG).unwrap().to_vec();
        let resp = run(&mut applet, &get_data(&tag));
        assert_eq!(resp.sw, None);
        assert_eq!(parse_pubkey_object(&resp.data), (alg, pubkey.clone()));

        // AUTHENTICATE assina; verificação independente confere.
        let challenge = b"piv-auth-challenge-ed25519";
        let resp = run(&mut applet, &authenticate(SLOT_DIG_SIG, 0x00, challenge));
        assert_eq!(resp.sw, None);
        assert_eq!(resp.data.len(), 64);
        assert!(engine.verify(challenge, &resp.data, &pubkey).unwrap());

        // Invólucro 7C/81 também é aceito.
        let resp = run(&mut applet, &authenticate_wrapped(SLOT_DIG_SIG, challenge));
        assert_eq!(resp.sw, None);
        assert!(engine.verify(challenge, &resp.data, &pubkey).unwrap());
    }

    #[test]
    fn test_generate_p256_roundtrip_via_get_data_and_authenticate() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        let engine = CryptoEngine::from_key(MASTER_KEY);

        let resp = run(&mut applet, &generate(SLOT_KEY_MGMT, ALG_P256));
        assert_eq!(resp.sw, None);
        let (alg, pubkey) = parse_pubkey_object(&resp.data);
        assert_eq!(alg, ALG_P256);
        assert_eq!(pubkey.len(), 65);
        assert_eq!(pubkey[0], 0x04);

        let tag = slot_tag(SLOT_KEY_MGMT).unwrap().to_vec();
        let resp = run(&mut applet, &get_data(&tag));
        assert_eq!(resp.sw, None);
        assert_eq!(parse_pubkey_object(&resp.data), (alg, pubkey.clone()));

        let challenge = b"piv-auth-challenge-p256";
        let resp = run(
            &mut applet,
            &authenticate(SLOT_KEY_MGMT, ALG_P256, challenge),
        );
        assert_eq!(resp.sw, None);
        engine.verify_p256(&pubkey, challenge, &resp.data).unwrap();

        // P1 divergente do algoritmo residente é sintaxe inválida.
        let resp = run(
            &mut applet,
            &authenticate(SLOT_KEY_MGMT, ALG_ED25519, challenge),
        );
        assert_eq!(resp.sw, Some(SW_WRONG_SYNTAX));
    }

    #[test]
    fn test_slot_9a_requires_verify_for_authenticate() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        let engine = CryptoEngine::from_key(MASTER_KEY);

        let resp = run(&mut applet, &generate(SLOT_PIV_AUTH, ALG_ED25519));
        assert_eq!(resp.sw, None);
        let (_, pubkey) = parse_pubkey_object(&resp.data);

        // Sem VERIFY: 9A nega com 6982.
        let challenge = b"challenge-9a-gated";
        assert_eq!(
            run(&mut applet, &authenticate(SLOT_PIV_AUTH, 0x00, challenge)).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );

        // Após VERIFY correto: assina.
        assert_eq!(run(&mut applet, &verify_default()).sw, None);
        let resp = run(&mut applet, &authenticate(SLOT_PIV_AUTH, 0x00, challenge));
        assert_eq!(resp.sw, None);
        assert!(engine.verify(challenge, &resp.data, &pubkey).unwrap());
    }

    #[test]
    fn test_keys_persist_across_restart_and_require_reverify_for_9a() {
        let root = temp_root("piv-keys");
        let path = root.join("store.json");

        let (alg_before, pub_before) = {
            let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
            let mut first = open_persistent(&storage, &path);
            let resp = run(&mut first, &generate(SLOT_PIV_AUTH, ALG_ED25519));
            assert_eq!(resp.sw, None);
            assert_eq!(run(&mut first, &verify_default()).sw, None);
            let resp9c = run(&mut first, &generate(SLOT_DIG_SIG, ALG_P256));
            assert_eq!(resp9c.sw, None);
            parse_pubkey_object(&resp.data)
        };

        // Reabre sobre o mesmo arquivo: chaves sobrevivem, sessão não.
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut second = open_persistent(&storage, &path);
        let engine = CryptoEngine::from_key(MASTER_KEY);

        let tag = slot_tag(SLOT_PIV_AUTH).unwrap().to_vec();
        let resp = run(&mut second, &get_data(&tag));
        assert_eq!(resp.sw, None);
        assert_eq!(
            parse_pubkey_object(&resp.data),
            (alg_before, pub_before.clone())
        );

        // 9A exige novo VERIFY após reinício.
        let challenge = b"persist-9a-reverify";
        assert_eq!(
            run(&mut second, &authenticate(SLOT_PIV_AUTH, 0x00, challenge)).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );
        assert_eq!(run(&mut second, &verify_default()).sw, None);
        let resp = run(&mut second, &authenticate(SLOT_PIV_AUTH, 0x00, challenge));
        assert_eq!(resp.sw, None);
        assert!(engine.verify(challenge, &resp.data, &pub_before).unwrap());

        // 9C (P-256) também persistiu e autentica sem VERIFY.
        let tag9c = slot_tag(SLOT_DIG_SIG).unwrap().to_vec();
        let resp = run(&mut second, &get_data(&tag9c));
        assert_eq!(resp.sw, None);
        let (alg9c, pub9c) = parse_pubkey_object(&resp.data);
        assert_eq!(alg9c, ALG_P256);
        let resp = run(&mut second, &authenticate(SLOT_DIG_SIG, 0x00, challenge));
        assert_eq!(resp.sw, None);
        engine.verify_p256(&pub9c, challenge, &resp.data).unwrap();
    }

    #[test]
    fn test_slot_isolation_between_keys() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        let resp_a = run(&mut applet, &generate(SLOT_DIG_SIG, ALG_ED25519));
        assert_eq!(resp_a.sw, None);
        let resp_b = run(&mut applet, &generate(SLOT_CARD_AUTH, ALG_P256));
        assert_eq!(resp_b.sw, None);
        assert_ne!(resp_a.data, resp_b.data);

        // Cada GET DATA devolve a sua chave.
        let tag_a = slot_tag(SLOT_DIG_SIG).unwrap().to_vec();
        let tag_b = slot_tag(SLOT_CARD_AUTH).unwrap().to_vec();
        assert_eq!(run(&mut applet, &get_data(&tag_a)).data, resp_a.data);
        assert_eq!(run(&mut applet, &get_data(&tag_b)).data, resp_b.data);

        // Regenerar um slot não afeta o outro.
        let resp_a2 = run(&mut applet, &generate(SLOT_DIG_SIG, ALG_ED25519));
        assert_eq!(resp_a2.sw, None);
        assert_ne!(resp_a2.data, resp_a.data);
        assert_eq!(run(&mut applet, &get_data(&tag_b)).data, resp_b.data);
    }

    #[test]
    fn test_unknown_slot_returns_file_not_found_and_empty_slot_security_status() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        // Slot desconhecido: 6A82 nas três portas.
        assert_eq!(
            run(&mut applet, &generate(0x82, ALG_ED25519)).sw,
            Some(transport::iso7816::SW_FILE_NOT_FOUND)
        );
        assert_eq!(
            run(&mut applet, &authenticate(0x82, 0x00, b"c")).sw,
            Some(transport::iso7816::SW_FILE_NOT_FOUND)
        );

        // Slot conhecido sem chave: GET DATA e AUTHENTICATE → 6982.
        let tag = slot_tag(SLOT_KEY_MGMT).unwrap().to_vec();
        assert_eq!(
            run(&mut applet, &get_data(&tag)).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );
        assert_eq!(
            run(&mut applet, &authenticate(SLOT_KEY_MGMT, 0x00, b"c")).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );

        // Algoritmo desconhecido no GENERATE: 6A80.
        assert_eq!(
            run(&mut applet, &generate(SLOT_DIG_SIG, 0x07)).sw,
            Some(SW_WRONG_SYNTAX)
        );
        // Desafio vazio no AUTHENTICATE (com chave): 6A80.
        assert_eq!(
            run(&mut applet, &generate(SLOT_DIG_SIG, ALG_ED25519)).sw,
            None
        );
        assert_eq!(
            run(&mut applet, &authenticate(SLOT_DIG_SIG, 0x00, b"")).sw,
            Some(SW_WRONG_SYNTAX)
        );
    }

    // --- certificados F2d: PUT DATA / GET DATA -------------------------------------

    /// PUT DATA caso 3S/3E: `00 DB 3F FF [Lc] tag+len-BER+cert` (forma
    /// estendida automática quando o corpo passa de 255B).
    fn put_data(tag: &[u8], value: &[u8]) -> Vec<u8> {
        let mut body = Vec::with_capacity(tag.len() + 3 + value.len());
        body.extend_from_slice(tag);
        if value.len() < 0x80 {
            body.push(value.len() as u8);
        } else if value.len() <= 0xFF {
            body.extend_from_slice(&[0x81, value.len() as u8]);
        } else {
            let len = value.len() as u16;
            body.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
        }
        body.extend_from_slice(value);
        let mut v = vec![0x00, INS_PUT_DATA, 0x3F, 0xFF];
        if body.len() <= 255 {
            v.push(body.len() as u8);
        } else {
            let len = body.len() as u16;
            v.extend_from_slice(&[0x00, (len >> 8) as u8, len as u8]);
        }
        v.extend_from_slice(&body);
        v
    }

    /// DER mínimo válido (`SEQUENCE { INTEGER 5 }`) como certificado falso.
    fn fake_der() -> Vec<u8> {
        vec![0x30, 0x03, 0x02, 0x01, 0x05]
    }

    /// Mesmo DER dentro do invólucro `70` do SP 800-73 (estilo `ykman`).
    fn fake_wrapped_cert() -> Vec<u8> {
        let der = fake_der();
        let mut inner = vec![0x71, 0x01, 0x00, 0xFE, der.len() as u8];
        inner.extend_from_slice(&der);
        let mut out = vec![0x70, inner.len() as u8];
        out.extend_from_slice(&inner);
        out
    }

    #[test]
    fn test_put_data_roundtrip_and_cert_wins_over_key_object() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        // Slot 9C com chave: GET DATA devolve o objeto 7F49 (F2a).
        let resp = run(&mut applet, &generate(SLOT_DIG_SIG, ALG_ED25519));
        assert_eq!(resp.sw, None);
        let tag = slot_tag(SLOT_DIG_SIG).unwrap().to_vec();
        let before = run(&mut applet, &get_data(&tag));
        assert_eq!(before.sw, None);
        assert_eq!(&before.data[..2], &[0x7F, 0x49]);

        // PUT DATA grava o certificado verbatim (9C não exige VERIFY).
        let cert = fake_wrapped_cert();
        assert_eq!(run(&mut applet, &put_data(&tag, &cert)).sw, None);
        let resp = run(&mut applet, &get_data(&tag));
        assert_eq!(resp.sw, None);
        assert_eq!(resp.data, cert);

        // DER cru também é aceito e devolvido byte-idêntico.
        let der = fake_der();
        assert_eq!(run(&mut applet, &put_data(&tag, &der)).sw, None);
        assert_eq!(run(&mut applet, &get_data(&tag)).data, der);

        // Sobrescrita funciona (segunda importação troca a primeira).
        let other = vec![0x30, 0x03, 0x02, 0x01, 0x09];
        assert_eq!(run(&mut applet, &put_data(&tag, &other)).sw, None);
        assert_eq!(run(&mut applet, &get_data(&tag)).data, other);
    }

    #[test]
    fn test_put_data_9a_requires_verify() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        let tag = slot_tag(SLOT_PIV_AUTH).unwrap().to_vec();
        let cert = fake_der();
        // Sem VERIFY: 9A nega com 6982 (mesma política do AUTHENTICATE).
        assert_eq!(
            run(&mut applet, &put_data(&tag, &cert)).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );
        // GET DATA segue sem nada: 6982 (nem chave nem certificado).
        assert_eq!(
            run(&mut applet, &get_data(&tag)).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );

        assert_eq!(run(&mut applet, &verify_default()).sw, None);
        assert_eq!(run(&mut applet, &put_data(&tag, &cert)).sw, None);
        assert_eq!(run(&mut applet, &get_data(&tag)).data, cert);
    }

    #[test]
    fn test_put_data_rejects_oversize_empty_and_unknown_tag() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        let tag = slot_tag(SLOT_KEY_MGMT).unwrap().to_vec();
        // Acima do teto (2049B, frame estendido): 6A80, nunca 6700.
        let big = vec![0x30u8; MAX_CERT_LEN + 1];
        assert_eq!(
            run(&mut applet, &put_data(&tag, &big)).sw,
            Some(SW_WRONG_SYNTAX)
        );
        // Exatamente no teto passa.
        let max = vec![0x30u8; MAX_CERT_LEN];
        assert_eq!(run(&mut applet, &put_data(&tag, &max)).sw, None);
        assert_eq!(run(&mut applet, &get_data(&tag)).data, max);
        // Valor vazio: 6A80.
        assert_eq!(
            run(&mut applet, &put_data(&tag, &[])).sw,
            Some(SW_WRONG_SYNTAX)
        );
        // Tag fora do mapa: 6A82.
        assert_eq!(
            run(&mut applet, &put_data(&[0x5F, 0xC1, 0x01], &fake_der())).sw,
            Some(transport::iso7816::SW_FILE_NOT_FOUND)
        );
        // P1/P2 errados: 6B00.
        let raw = vec![0x00, INS_PUT_DATA, 0x00, 0xFF, 0x01, 0x00];
        assert_eq!(
            run(&mut applet, &raw).sw,
            Some(transport::iso7816::SW_WRONG_P1_P2)
        );
    }

    #[test]
    fn test_certs_persist_across_restart_and_9a_needs_reverify() {
        let root = temp_root("piv-certs");
        let path = root.join("store.json");

        let cert_9c = fake_wrapped_cert();
        let cert_9a = fake_der();
        {
            let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
            let mut first = open_persistent(&storage, &path);
            assert_eq!(run(&mut first, &verify_default()).sw, None);
            let tag9a = slot_tag(SLOT_PIV_AUTH).unwrap().to_vec();
            assert_eq!(run(&mut first, &put_data(&tag9a, &cert_9a)).sw, None);
            let tag9c = slot_tag(SLOT_DIG_SIG).unwrap().to_vec();
            assert_eq!(run(&mut first, &put_data(&tag9c, &cert_9c)).sw, None);
        }

        // Reabre: certificados sobrevivem, sessão verificada não.
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut second = open_persistent(&storage, &path);
        let tag9c = slot_tag(SLOT_DIG_SIG).unwrap().to_vec();
        assert_eq!(run(&mut second, &get_data(&tag9c)).data, cert_9c);
        let tag9a = slot_tag(SLOT_PIV_AUTH).unwrap().to_vec();
        assert_eq!(run(&mut second, &get_data(&tag9a)).data, cert_9a);

        // 9A exige novo VERIFY para um segundo PUT após reinício.
        let other = vec![0x30, 0x03, 0x02, 0x01, 0x07];
        assert_eq!(
            run(&mut second, &put_data(&tag9a, &other)).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );
        assert_eq!(run(&mut second, &verify_default()).sw, None);
        assert_eq!(run(&mut second, &put_data(&tag9a, &other)).sw, None);
        assert_eq!(run(&mut second, &get_data(&tag9a)).data, other);
    }

    #[test]
    fn test_cert_slot_isolation() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        let tag_c = slot_tag(SLOT_DIG_SIG).unwrap().to_vec();
        let tag_d = slot_tag(SLOT_KEY_MGMT).unwrap().to_vec();
        let cert_c = fake_der();
        let cert_d = fake_wrapped_cert();
        assert_eq!(run(&mut applet, &put_data(&tag_c, &cert_c)).sw, None);
        assert_eq!(run(&mut applet, &put_data(&tag_d, &cert_d)).sw, None);
        assert_eq!(run(&mut applet, &get_data(&tag_c)).data, cert_c);
        assert_eq!(run(&mut applet, &get_data(&tag_d)).data, cert_d);

        // Slot 9E sem chave nem certificado: 6982 (convenção F2a).
        let tag_e = slot_tag(SLOT_CARD_AUTH).unwrap().to_vec();
        assert_eq!(
            run(&mut applet, &get_data(&tag_e)).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );
    }

    #[test]
    fn test_regenerate_key_clears_slot_cert() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        let tag = slot_tag(SLOT_DIG_SIG).unwrap().to_vec();
        assert_eq!(
            run(&mut applet, &generate(SLOT_DIG_SIG, ALG_ED25519)).sw,
            None
        );
        let cert = fake_der();
        assert_eq!(run(&mut applet, &put_data(&tag, &cert)).sw, None);
        assert_eq!(run(&mut applet, &get_data(&tag)).data, cert);

        // Nova chave no slot: certificado obsoleto some, volta o 7F49 novo.
        let resp = run(&mut applet, &generate(SLOT_DIG_SIG, ALG_ED25519));
        assert_eq!(resp.sw, None);
        let after = run(&mut applet, &get_data(&tag));
        assert_eq!(after.sw, None);
        assert_eq!(&after.data[..2], &[0x7F, 0x49]);
        assert_eq!(after.data, resp.data);
    }

    #[test]
    fn test_f1_blob_migrates_to_f2_preserving_pin() {
        let root = temp_root("piv-migrate");
        let path = root.join("store.json");

        // Forja um blob F1 (versão 1): PIN "654321", 2 tentativas, sem chaves.
        let engine = CryptoEngine::from_key(MASTER_KEY);
        let mut plaintext = vec![0x01, 0x06];
        plaintext.extend_from_slice(b"654321");
        plaintext.push(0x02);
        let (nonce, ciphertext) = engine.encrypt_with_random_nonce(&plaintext).unwrap();
        let mut blob = nonce;
        blob.extend_from_slice(&ciphertext);
        {
            let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
            let backend = FileStorageBackend::new(path.clone()).unwrap();
            *storage.borrow_mut() = StorageEngine::with_backend(Box::new(backend));
            storage.borrow_mut().store(STORAGE_KEY, blob).unwrap();
        }

        // Reabre: migra para F2a preservando PIN e tentativas.
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = open_persistent(&storage, &path);
        assert_eq!(run(&mut applet, &verify(&[])).sw, Some(sw_retries(2)));
        let mut pin = b"654321".to_vec();
        pin.extend_from_slice(&[0xFF, 0xFF]);
        assert_eq!(run(&mut applet, &verify(&pin)).sw, None);
        // Sem chaves após migração: 6982.
        let tag = slot_tag(SLOT_DIG_SIG).unwrap().to_vec();
        assert_eq!(
            run(&mut applet, &get_data(&tag)).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );
    }

    #[test]
    fn test_f2a_blob_migrates_to_f3_preserving_keys_pin_and_retries() {
        let root = temp_root("piv-migrate-f2a");
        let path = root.join("store.json");

        // Forja um blob F2a (versão 2): PIN "654321", 2 tentativas, uma
        // chave Ed25519 no slot 9C, sem certificados.
        let engine = CryptoEngine::from_key(MASTER_KEY);
        let (priv_key, pub_key) = engine.generate_key_pair().unwrap();
        let mut plaintext = vec![0x02, 0x06];
        plaintext.extend_from_slice(b"654321");
        plaintext.push(0x02);
        plaintext.push(0x01);
        plaintext.push(SLOT_DIG_SIG);
        plaintext.push(ALG_ED25519);
        plaintext.extend_from_slice(&(priv_key.len() as u16).to_be_bytes());
        plaintext.extend_from_slice(&priv_key);
        plaintext.extend_from_slice(&(pub_key.len() as u16).to_be_bytes());
        plaintext.extend_from_slice(&pub_key);
        let (nonce, ciphertext) = engine.encrypt_with_random_nonce(&plaintext).unwrap();
        let mut blob = nonce;
        blob.extend_from_slice(&ciphertext);
        {
            let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
            let backend = FileStorageBackend::new(path.clone()).unwrap();
            *storage.borrow_mut() = StorageEngine::with_backend(Box::new(backend));
            storage.borrow_mut().store(STORAGE_KEY, blob).unwrap();
        }

        // Reabre: migra para F2d preservando PIN, tentativas e chave.
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = open_persistent(&storage, &path);
        assert_eq!(run(&mut applet, &verify(&[])).sw, Some(sw_retries(2)));
        let tag = slot_tag(SLOT_DIG_SIG).unwrap().to_vec();
        let resp = run(&mut applet, &get_data(&tag));
        assert_eq!(resp.sw, None);
        assert_eq!(
            parse_pubkey_object(&resp.data),
            (ALG_ED25519, pub_key.clone())
        );

        // Chave migrada autentica sem VERIFY (política do slot 9C).
        let challenge = b"migrated-f2a-key";
        let resp = run(&mut applet, &authenticate(SLOT_DIG_SIG, 0x00, challenge));
        assert_eq!(resp.sw, None);
        assert!(engine.verify(challenge, &resp.data, &pub_key).unwrap());

        // Sem certificados após migração: PUT continua funcional.
        let cert = fake_der();
        assert_eq!(run(&mut applet, &put_data(&tag, &cert)).sw, None);
        assert_eq!(run(&mut applet, &get_data(&tag)).data, cert);
    }

    // --- roteador -----------------------------------------------------------------------

    #[test]
    fn test_piv_select_succeeds_through_router() {
        let storage: &'static core::cell::RefCell<StorageEngine> = Box::leak(Box::new(
            core::cell::RefCell::new(StorageEngine::new().unwrap()),
        ));
        let applet = Box::leak(Box::new(
            PivApplet::new(storage, CryptoEngine::from_key(MASTER_KEY)).unwrap(),
        ));
        let mut router = CardRouter::new();
        router.register(applet);

        let resp = router.process(&select_frame(AID_PIV));
        assert_eq!(resp.sw, Some(SW_NO_ERROR));

        // GET DATA com Le folgado sai inline pelo roteador.
        let mut frame = get_data(&[TAG_DISCOVERY]);
        frame.push(0x00);
        let resp = router.process(&frame);
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        assert_eq!(resp.data[0], TAG_DISCOVERY);

        // Tag desconhecida pelo roteador: 6A82.
        let mut frame = get_data(&[0x01]);
        frame.push(0x00);
        let resp = router.process(&frame);
        assert_eq!(resp.sw, Some(transport::iso7816::SW_FILE_NOT_FOUND));
    }
}
