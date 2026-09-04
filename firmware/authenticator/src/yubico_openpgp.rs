//! Aplicação OpenPGP Card como applet ISO/IEC 7816-4.
//!
//! Expõe o AID `D27600012401` (OpenPGP Card 3.x) no `CardRouter` para
//! roteamento multi-protocolo (ADR-0024), suficiente para
//! `gpg --card-status` detectar o AID.
//!
//! # Comandos suportados (Fase F2b)
//!
//! | Comando  | INS    | P1/P2                    | Resposta                          |
//! |----------|--------|--------------------------|-----------------------------------|
//! | SELECT   | `0xA4` | (roteador)               | `0x6F` dados da aplicação         |
//! | GET DATA | `0xCA` | tag: `004F`/`5F52`/`007A`/`B600`/`00C5` | ver abaixo / `6A82` / `6982` |
//! | VERIFY   | `0x20` | `81`/`82` (PW1), `83` (PW3)| `9000` / `63Cx` / `6982`          |
//! | GENERATE | `0x47` | `P1∈{00,80,81}`, `P2=00`   | objeto `7F49` + `9000`            |
//! | PSO      | `0x2A` | `9E9A` SIGN / `8086` DECIPHER | assinatura / `6982`            |
//!
//! O seletor de senha é lido de P1 (quando diferente de zero) ou de P2,
//! cobrindo hosts que enviam `P1=81/82/83` e os que seguem a OpenPGP Card
//! spec (`P1=00`, `P2=81/82/83`). `VERIFY` vazio consulta as tentativas
//! restantes (`63Cx`); senha correta autentica (`9000`) e restaura as
//! tentativas; senha errada decrementa e persiste (`63Cx`, `6982` ao
//! esgotar).
//!
//! # Chaves do slot SIG (F2b, somente SIG)
//!
//! - `GENERATE ASYMMETRIC KEY PAIR` (`0x47`, `P1∈{0x00,0x80,0x81}`,
//!   `P2=0x00`): dados = byte único `<alg>` ou CRT `B6 03 80 01 <alg>`,
//!   com `<alg>` ∈ {`0x11` P-256, `0xE0` Ed25519} (mesmos IDs da fase PIV
//!   F2a). Gera via `CryptoEngine` (`generate_p256_key_pair` /
//!   `generate_key_pair`), persiste cifrado e devolve o objeto `7F49` =
//!   `7F49 <len> [80 01 <alg>][86 <len> <pubkey>]`. Regeneração sobrescreve
//!   (privada antiga zeroizada); falha de persistência faz rollback em
//!   memória. CRT `B8`/`A4` (DEC/AUT) → `6A82` (fora do escopo SIG);
//!   algoritmo inválido → `6A80`; `P1/P2` fora do mapa → `6B00`.
//! - `PSO SIGN` (`0x2A`, `P1=0x9E`, `P2=0x9A`): dados = bytes a assinar
//!   (brutos, 1..=512B); assina com a chave SIG residente (`sign` /
//!   `sign_p256`) e devolve a assinatura bruta (Ed25519 64B, P-256 DER).
//!   Exige sessão PW1 verificada e chave residente — sem qualquer dos dois,
//!   `6982`. Dados vazios/grandes demais → `6A80`.
//! - `PSO DECIPHER` (`0x2A`, `P1=0x80`, `P2=0x86`) → sempre `6982` (sem
//!   slot DEC nesta fase); demais `P1/P2` no PSO → `6B00`.
//! - Sessão PW1 volátil (`pw1_verified: bool`, não persistida): `VERIFY`
//!   correto de PW1 (`81`/`82`) ativa; esgotamento de retries do PW1
//!   derruba; reinício exige novo `VERIFY`. `VERIFY` de PW3 não ativa a
//!   sessão de assinatura. `SELECT` não altera a sessão.
//!
//! # GET DATA (F2b)
//!
//! - `004F`: AID (com tag, como no SELECT).
//! - `5F52`: bytes históricos (valor direto, placeholder F1).
//! - `007A`: atributos de algoritmo do slot SIG — refletem a chave
//!   residente (Ed25519/P-256) ou o placeholder RSA-2048 da F1 quando vazio.
//! - `B600`: objeto `7F49` da chave SIG quando presente; sem chave → `6982`.
//! - `00C5`: impressão digital = `SHA-256(pubkey)` (32B) quando há chave;
//!   sem chave → `6982`. Desvio consciente: a spec usa SHA-1 sobre o pacote
//!   de chave; aqui o hash é sobre a pública bruta, suficiente como
//!   identificador estável sem confinar SHA-1 novo à `crypto`.
//! - Tag desconhecida → `6A82`.
//!
//! # Persistência cifrada
//!
//! Senhas, tentativas e a chave SIG são serializadas em formato binário
//! próprio (versão `2` na F2b), cifradas com ChaCha20-Poly1305 (nonce
//! aleatório de 12 bytes via `SystemRandom`) e gravadas sob a chave
//! reservada `sys:openpgp` do [`StorageEngine`] — encryption at rest
//! idêntico ao do applet OATH. Blob ilegível volta aos padrões de fábrica
//! (PW1 `"123456"`, PW3 `"12345678"`, 3 tentativas, sem chave) com log.
//! Blobs F1 (`versão 1`, só senhas) migram preservando PINs/retries, com a
//! chave ausente, e são regravados em `2` já na carga.

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

/// AID da aplicação OpenPGP Card (prefixo de 6 bytes).
///
/// Hosts selecionam tanto este prefixo quanto AIDs estendidos com bytes de
/// versão/instância; o roteador casa por prefixo quando o AID registrado
/// começa com o requisitado, por isso o AID completo registrado é
/// [`AID_OPENPGP_FULL`].
pub const AID_OPENPGP: &[u8] = &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

/// AID completo registrado no roteador: prefixo + versão `03 00` +
/// placeholders de fabricante/serial/RFU (16 bytes).
///
/// Registrar a forma estendida faz o `CardRouter` aceitar tanto o SELECT do
/// prefixo curto (`aid.starts_with(requested)`) quanto o do AID completo
/// (casamento exato) — sem nenhuma mudança no roteador.
pub const AID_OPENPGP_FULL: &[u8] = &[
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Chave reservada no [`StorageEngine`] para o estado cifrado do applet.
const STORAGE_KEY: &str = "sys:openpgp";

/// Versão do formato de serialização do estado (F2b; F1 usava `1`).
const STATE_FORMAT_VERSION: u8 = 2;

/// PW1 padrão de fábrica (PIN do usuário, igual ao dos YubiKeys físicos).
const DEFAULT_PW1: &[u8] = b"123456";

/// PW3 padrão de fábrica (PIN do admin, igual ao dos YubiKeys físicos).
const DEFAULT_PW3: &[u8] = b"12345678";

/// Tentativas máximas por senha.
const MAX_RETRIES: u8 = 3;

/// Tamanho máximo aceito de senha (folga sobre os 8 do PW3 padrão).
const MAX_PW_LEN: usize = 32;

// --- Instruções (OpenPGP Card 3.x) ----------------------------------------------------

/// VERIFY: autentica PW1/PW3.
const INS_VERIFY: u8 = 0x20;
/// PERFORM SECURITY OPERATION: SIGN (`9E9A`) / DECIPHER (`8086`).
const INS_PSO: u8 = 0x2A;
/// GENERATE ASYMMETRIC KEY PAIR: gera a chave do slot SIG.
const INS_GENERATE: u8 = 0x47;
/// GET DATA: lê um objeto de dados pela tag em P1P2.
const INS_GET_DATA: u8 = 0xCA;

// --- Seletores de senha (P1 ou P2 do VERIFY) -------------------------------------------

/// PW1 para assinatura.
const PW_SIGN: u8 = 0x81;
/// PW1 para outras operações.
const PW_OTHER: u8 = 0x82;
/// PW3 (admin).
const PW_ADMIN: u8 = 0x83;

// --- Slots, CRTs e algoritmos (F2b: somente SIG) ---------------------------------------

/// CRT do slot de assinatura (único suportado na F2b).
const CRT_SIG: u8 = 0xB6;
/// CRT do slot de decifração (fora de escopo → `6A82`).
const CRT_DEC: u8 = 0xB8;
/// CRT do slot de autenticação (fora de escopo → `6A82`).
const CRT_AUT: u8 = 0xA4;

/// PSO SIGN: `P1=0x9E`, `P2=0x9A`.
const PSO_P1_SIGN: u8 = 0x9E;
const PSO_P2_SIGN: u8 = 0x9A;

/// PSO DECIPHER (sempre `6982` nesta fase): `P1=0x80`, `P2=0x86`.
const PSO_P1_DECIPHER: u8 = 0x80;
const PSO_P2_DECIPHER: u8 = 0x86;

/// Algoritmo P-256 (mesmo ID da fase PIV F2a).
const ALG_P256: u8 = 0x11;
/// Algoritmo Ed25519 (ID Yubico, mesmo da fase PIV F2a).
const ALG_ED25519: u8 = 0xE0;

/// Tamanho máximo aceito de dados no PSO SIGN (bytes).
const MAX_SIGN_DATA_LEN: usize = 512;

// --- Status Words -----------------------------------------------------------------------

/// CLA diferente de `0x00` (mesma política do applet OATH).
const SW_CLASS_NOT_SUPPORTED: u16 = 0x6E00;
/// Dados/formato inválidos (ex.: algoritmo desconhecido, dados vazios).
const SW_WRONG_SYNTAX: u16 = 0x6A80;

/// Codifica as tentativas restantes como `63Cx` (verificação falhou / status).
const fn sw_retries(left: u8) -> u16 {
    0x63C0 | (left & 0x0F) as u16
}

// --- Estado -------------------------------------------------------------------------------

/// Chave de assinatura residente no slot SIG (material privado cifrado em repouso).
struct SigKey {
    /// Algoritmo (`0x11` P-256, `0xE0` Ed25519).
    alg: u8,
    /// Privada: seed Ed25519 (32B) ou PKCS#8 P-256.
    priv_key: Vec<u8>,
    /// Pública: 32B (Ed25519) ou `04||x||y` 65B (P-256).
    pub_key: Vec<u8>,
}

/// Estado do applet OpenPGP (persistido cifrado sob `sys:openpgp`).
struct OpenPgpState {
    /// PW1 atual (bytes exatos, sem preenchimento).
    pw1: Vec<u8>,
    /// Tentativas restantes do PW1.
    pw1_retries: u8,
    /// PW3 atual (bytes exatos, sem preenchimento).
    pw3: Vec<u8>,
    /// Tentativas restantes do PW3.
    pw3_retries: u8,
    /// Chave de assinatura residente (F2b; `None` = slot vazio).
    sig_key: Option<SigKey>,
}

impl fmt::Debug for OpenPgpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redigido: senhas e chaves nunca aparecem em logs.
        f.debug_struct("OpenPgpState")
            .field("pw1_len", &self.pw1.len())
            .field("pw1_retries", &self.pw1_retries)
            .field("pw3_len", &self.pw3.len())
            .field("pw3_retries", &self.pw3_retries)
            .field("sig_present", &self.sig_key.is_some())
            .field("sig_alg", &self.sig_key.as_ref().map(|k| k.alg))
            .finish()
    }
}

/// Serializa (F2b, versão `2`):
/// `[02][pw1_len u8][pw1][pw1_ret u8][pw3_len u8][pw3][pw3_ret u8]
///  [has_key u8][alg u8][priv_len u16BE][priv][pub_len u16BE][pub]`
/// (`has_key == 0` → nada após o flag).
fn serialize_state(state: &OpenPgpState) -> Vec<u8> {
    let mut out = Vec::with_capacity(state.pw1.len() + state.pw3.len() + 6);
    out.push(STATE_FORMAT_VERSION);
    out.push(state.pw1.len() as u8);
    out.extend_from_slice(&state.pw1);
    out.push(state.pw1_retries);
    out.push(state.pw3.len() as u8);
    out.extend_from_slice(&state.pw3);
    out.push(state.pw3_retries);
    match &state.sig_key {
        Some(key) => {
            out.push(1);
            out.push(key.alg);
            out.extend_from_slice(&(key.priv_key.len() as u16).to_be_bytes());
            out.extend_from_slice(&key.priv_key);
            out.extend_from_slice(&(key.pub_key.len() as u16).to_be_bytes());
            out.extend_from_slice(&key.pub_key);
        }
        None => out.push(0),
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

    fn take_len_prefixed(&mut self) -> Option<Vec<u8>> {
        let len = usize::from(self.take_u8()?);
        Some(self.take(len)?.to_vec())
    }

    fn take_u16be(&mut self) -> Option<usize> {
        let bytes = self.take(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
    }

    fn at_end(&self) -> bool {
        self.pos == self.data.len()
    }
}

/// Rejeita blobs com versão desconhecida, senhas vazias/grandes demais,
/// tentativas acima do máximo, chave malformada ou sobra de bytes.
fn parse_state(blob: &[u8]) -> Option<OpenPgpState> {
    if blob.is_empty() {
        return None;
    }
    match blob[0] {
        1 => parse_state_v1(blob),
        STATE_FORMAT_VERSION => parse_state_v2(blob),
        _ => None,
    }
}

/// Formato F1 (`v1`): `[01][pw1_len][pw1][pw1_ret][pw3_len][pw3][pw3_ret]`;
/// migra para F2b com o slot SIG vazio.
fn parse_state_v1(blob: &[u8]) -> Option<OpenPgpState> {
    let mut reader = BlobReader::new(blob);
    if reader.take_u8()? != 1 {
        return None;
    }
    let pw1 = reader.take_len_prefixed()?;
    if pw1.is_empty() || pw1.len() > MAX_PW_LEN {
        return None;
    }
    let pw1_retries = reader.take_u8()?;
    if pw1_retries > MAX_RETRIES {
        return None;
    }
    let pw3 = reader.take_len_prefixed()?;
    if pw3.is_empty() || pw3.len() > MAX_PW_LEN {
        return None;
    }
    let pw3_retries = reader.take_u8()?;
    if pw3_retries > MAX_RETRIES {
        return None;
    }
    if !reader.at_end() {
        return None;
    }
    Some(OpenPgpState {
        pw1,
        pw1_retries,
        pw3,
        pw3_retries,
        sig_key: None,
    })
}

/// Formato F2b (`v2`, ver [`serialize_state`]).
fn parse_state_v2(blob: &[u8]) -> Option<OpenPgpState> {
    let mut reader = BlobReader::new(blob);
    if reader.take_u8()? != STATE_FORMAT_VERSION {
        return None;
    }
    let pw1 = reader.take_len_prefixed()?;
    if pw1.is_empty() || pw1.len() > MAX_PW_LEN {
        return None;
    }
    let pw1_retries = reader.take_u8()?;
    if pw1_retries > MAX_RETRIES {
        return None;
    }
    let pw3 = reader.take_len_prefixed()?;
    if pw3.is_empty() || pw3.len() > MAX_PW_LEN {
        return None;
    }
    let pw3_retries = reader.take_u8()?;
    if pw3_retries > MAX_RETRIES {
        return None;
    }
    let has_key = reader.take_u8()?;
    let sig_key = match has_key {
        0 => None,
        1 => {
            let alg = reader.take_u8()?;
            if !is_valid_alg(alg) {
                return None;
            }
            let priv_len = reader.take_u16be()?;
            let priv_key = reader.take(priv_len)?.to_vec();
            let pub_len = reader.take_u16be()?;
            let pub_key = reader.take(pub_len)?.to_vec();
            if !key_lengths_ok(alg, priv_key.len(), pub_key.len()) {
                return None;
            }
            Some(SigKey {
                alg,
                priv_key,
                pub_key,
            })
        }
        _ => return None,
    };
    if !reader.at_end() {
        return None;
    }
    Some(OpenPgpState {
        pw1,
        pw1_retries,
        pw3,
        pw3_retries,
        sig_key,
    })
}

/// Algoritmo suportado na F2b (somente slot SIG).
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

/// Extrai o ID do algoritmo do campo de dados do `GENERATE` (slot SIG):
/// byte único `<alg>` ou CRT `B6 03 80 01 <alg>`. CRTs `B8`/`A4`
/// (DEC/AUT, fora de escopo) retornam `Err(true)` = slot desconhecido
/// (`6A82`); demais formatos, `Err(false)` = sintaxe inválida (`6A80`).
fn parse_generate_alg(data: &[u8]) -> Result<u8, bool> {
    if data.len() == 1 {
        if is_valid_alg(data[0]) {
            return Ok(data[0]);
        }
        return Err(false);
    }
    if data.len() == 5
        && data[1] == 0x03
        && data[2] == 0x80
        && data[3] == 0x01
        && is_valid_alg(data[4])
    {
        match data[0] {
            CRT_SIG => return Ok(data[4]),
            CRT_DEC | CRT_AUT => return Err(true),
            _ => return Err(false),
        }
    }
    // CRT nu (`B8 00` / `A4 00`) ou prefixo DEC/AUT: slot fora de escopo.
    if data.first() == Some(&CRT_DEC) || data.first() == Some(&CRT_AUT) {
        return Err(true);
    }
    Err(false)
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

/// Empacota um TLV de forma curta (valor ≤255 bytes) ao final de `out`.
fn push_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    assert!(value.len() <= 255, "TLV value exceeds short form");
    out.push(tag);
    out.push(value.len() as u8);
    out.extend_from_slice(value);
}

/// Bytes históricos (placeholder F1) devolvidos na tag `0x5F52`.
const HISTORICAL_BYTES: &[u8] = &[0x00, 0x73, 0x00, 0x00];

/// Atributos de algoritmo quando o slot SIG está vazio (placeholder F1: RSA-2048).
const SIG_ALGO_ATTRIBUTES_EMPTY: &[u8] = &[0x01, 0x08, 0x00, 0x00];

/// Atributos de algoritmo com chave Ed25519 residente (subconjunto: ID EdDSA).
const SIG_ALGO_ATTRIBUTES_ED25519: &[u8] = &[0x16, 0x20, 0x00, 0x00];

/// Atributos de algoritmo com chave P-256 residente (subconjunto: ID ECDSA).
const SIG_ALGO_ATTRIBUTES_P256: &[u8] = &[0x13, 0x2A, 0x00, 0x00];

/// Atributos de algoritmo conforme a chave residente (`None` = slot vazio).
fn sig_algo_attributes(alg: Option<u8>) -> &'static [u8] {
    match alg {
        Some(ALG_ED25519) => SIG_ALGO_ATTRIBUTES_ED25519,
        Some(ALG_P256) => SIG_ALGO_ATTRIBUTES_P256,
        _ => SIG_ALGO_ATTRIBUTES_EMPTY,
    }
}

// --- Applet ---------------------------------------------------------------------------------

/// Applet ISO 7816-4 da aplicação OpenPGP Card (fase F2b: senhas + chave SIG).
pub struct OpenPgpApplet<'a> {
    /// Storage compartilhado com os demais applets (mesmo kv).
    storage: &'a core::cell::RefCell<StorageEngine>,
    crypto: CryptoEngine,
    state: Option<OpenPgpState>,
    /// Sessão PW1 verificada (volátil: não persiste; nasce `false`).
    pw1_verified: bool,
}

impl fmt::Debug for OpenPgpApplet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redigido: o estado carrega senhas e chave; nada além de contagens.
        f.debug_struct("OpenPgpApplet")
            .field("loaded", &self.state.is_some())
            .field(
                "retries",
                &self.state.as_ref().map(|s| (s.pw1_retries, s.pw3_retries)),
            )
            .field(
                "sig_present",
                &self.state.as_ref().map(|s| s.sig_key.is_some()),
            )
            .field("pw1_verified", &self.pw1_verified)
            .finish()
    }
}

impl<'a> OpenPgpApplet<'a> {
    /// Cria o applet sobre o storage e o motor criptográfico fornecidos.
    ///
    /// Carrega (ou inicializa) o estado persistido: registro ausente é criado
    /// com as senhas padrão de fábrica; registro ilegível (chave-mestra
    /// trocada ou dado corrompido) volta ao estado de fábrica com log — mesma
    /// política dos applets OATH/Management.
    pub fn new(
        storage: &'a core::cell::RefCell<StorageEngine>,
        crypto: CryptoEngine,
    ) -> Result<Self, Box<dyn core::error::Error>> {
        let mut applet = Self {
            storage,
            crypto,
            state: None,
            pw1_verified: false,
        };
        applet
            .ensure_loaded()
            .map_err(|sw| format!("OpenPGP init failed with SW {:#06X}", sw))?;
        Ok(applet)
    }

    /// Garante o estado em memória, criando registro de fábrica se preciso.
    ///
    /// Blobs F1 (`versão 1`, só senhas) migram para F2b com o slot SIG vazio
    /// e são regravados já no formato `2`.
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
                        migrated = !plaintext.is_empty() && plaintext[0] == 1;
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
                    warn!("OpenPGP state unreadable; resetting to factory defaults");
                }
                let state = OpenPgpState {
                    pw1: DEFAULT_PW1.to_vec(),
                    pw1_retries: MAX_RETRIES,
                    pw3: DEFAULT_PW3.to_vec(),
                    pw3_retries: MAX_RETRIES,
                    sig_key: None,
                };
                self.state = Some(state);
                self.persist_state()
            }
        }
    }

    /// Referência mutável ao estado já carregado (`ensure_loaded` antes).
    fn state_mut(&mut self) -> Result<&mut OpenPgpState, u16> {
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
                warn!("OpenPGP persistence failed: {}", e);
                transport::iso7816::SW_CONDITIONS_NOT_SATISFIED
            })
    }

    /// Monta os dados da aplicação (`0x6F`) devolvidos no SELECT.
    fn application_data() -> Vec<u8> {
        let mut inner = Vec::new();
        push_tlv(&mut inner, 0x4F, AID_OPENPGP_FULL);
        inner.push(0x5F);
        inner.push(0x52);
        inner.push(HISTORICAL_BYTES.len() as u8);
        inner.extend_from_slice(HISTORICAL_BYTES);
        let mut out = Vec::with_capacity(inner.len() + 2);
        push_tlv(&mut out, 0x6F, &inner);
        out
    }

    fn cmd_get_data(&mut self, apdu: &Apdu) -> Result<ResponseData, u16> {
        match (apdu.p1, apdu.p2) {
            // Tag 0x4F: AID (com tag, como no SELECT).
            (0x00, 0x4F) => {
                let mut out = Vec::with_capacity(AID_OPENPGP_FULL.len() + 2);
                push_tlv(&mut out, 0x4F, AID_OPENPGP_FULL);
                Ok(ResponseData::ok(out))
            }
            // Tag 0x5F52: bytes históricos (valor direto, placeholder F1).
            (0x5F, 0x52) => Ok(ResponseData::ok(HISTORICAL_BYTES.to_vec())),
            // Tag 0x7A: atributos de algoritmo do slot SIG (dinâmicos na F2b).
            (0x00, 0x7A) => {
                self.ensure_loaded()?;
                let alg = self
                    .state
                    .as_ref()
                    .expect("loaded above")
                    .sig_key
                    .as_ref()
                    .map(|k| k.alg);
                Ok(ResponseData::ok(sig_algo_attributes(alg).to_vec()))
            }
            // Tag 0xB600: objeto 7F49 da chave SIG; sem chave → 6982.
            (0xB6, 0x00) => {
                self.ensure_loaded()?;
                let state = self.state.as_ref().expect("loaded above");
                match &state.sig_key {
                    Some(key) => Ok(ResponseData::ok(pubkey_object(key.alg, &key.pub_key))),
                    None => Err(transport::iso7816::SW_SECURITY_STATUS),
                }
            }
            // Tag 0xC5: impressão digital SHA-256(pubkey); sem chave → 6982.
            (0x00, 0xC5) => {
                self.ensure_loaded()?;
                let state = self.state.as_ref().expect("loaded above");
                match &state.sig_key {
                    Some(key) => Ok(ResponseData::ok(self.crypto.sha256(&key.pub_key))),
                    None => Err(transport::iso7816::SW_SECURITY_STATUS),
                }
            }
            // Tag desconhecida: objeto inexistente.
            _ => Err(transport::iso7816::SW_FILE_NOT_FOUND),
        }
    }

    /// Resolve o seletor de senha: P1 quando diferente de zero, senão P2.
    fn password_slot(apdu: &Apdu) -> Result<u8, u16> {
        let selector = if apdu.p1 != 0x00 { apdu.p1 } else { apdu.p2 };
        match selector {
            PW_SIGN | PW_OTHER | PW_ADMIN => Ok(selector),
            _ => Err(transport::iso7816::SW_WRONG_P1_P2),
        }
    }

    fn cmd_verify(&mut self, apdu: &Apdu) -> Result<ResponseData, u16> {
        let slot = Self::password_slot(apdu)?;
        self.ensure_loaded()?;
        let is_admin = slot == PW_ADMIN;
        let (expected, left) = {
            let state = self.state.as_ref().expect("loaded above");
            if is_admin {
                (state.pw3.clone(), state.pw3_retries)
            } else {
                (state.pw1.clone(), state.pw1_retries)
            }
        };
        if left == 0 {
            return Err(transport::iso7816::SW_SECURITY_STATUS);
        }
        if apdu.data.is_empty() {
            // Consulta de status: tentativas restantes, sem consumir.
            debug!("OpenPGP VERIFY status query");
            return Ok(ResponseData::with_sw(Vec::new(), sw_retries(left)));
        }
        if constant_time_eq(apdu.data, &expected) {
            {
                let state = self.state.as_mut().expect("loaded above");
                if is_admin {
                    state.pw3_retries = MAX_RETRIES;
                } else {
                    state.pw1_retries = MAX_RETRIES;
                }
            }
            self.persist_state()?;
            if !is_admin {
                self.pw1_verified = true;
            }
            debug!("OpenPGP VERIFY succeeded");
            Ok(ResponseData::ok(Vec::new()))
        } else {
            let sw = {
                let state = self.state.as_mut().expect("loaded above");
                let retries = if is_admin {
                    &mut state.pw3_retries
                } else {
                    &mut state.pw1_retries
                };
                *retries = retries.saturating_sub(1);
                if *retries == 0 {
                    transport::iso7816::SW_SECURITY_STATUS
                } else {
                    sw_retries(*retries)
                }
            };
            if sw == transport::iso7816::SW_SECURITY_STATUS && !is_admin {
                self.pw1_verified = false;
            }
            self.persist_state()?;
            debug!("OpenPGP VERIFY failed");
            Err(sw)
        }
    }

    /// GENERATE ASYMMETRIC KEY PAIR (`0x47`): gera a chave do slot SIG.
    ///
    /// `P1∈{0x00,0x80,0x81}`, `P2=0x00`. CRTs `B8`/`A4` (DEC/AUT) → `6A82`;
    /// algoritmo inválido → `6A80`.
    fn cmd_generate(&mut self, apdu: &Apdu) -> Result<ResponseData, u16> {
        if !matches!(apdu.p1, 0x00 | 0x80 | 0x81) || apdu.p2 != 0x00 {
            return Err(transport::iso7816::SW_WRONG_P1_P2);
        }
        let alg = match parse_generate_alg(apdu.data) {
            Ok(alg) => alg,
            Err(unknown_slot) => {
                return Err(if unknown_slot {
                    transport::iso7816::SW_FILE_NOT_FOUND
                } else {
                    SW_WRONG_SYNTAX
                });
            }
        };
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
        {
            let state = self.state_mut()?;
            // Regeneração sobrescreve: zera a privada antiga antes de trocar.
            if let Some(existing) = state.sig_key.as_mut() {
                existing.priv_key.zeroize();
                existing.alg = alg;
                existing.priv_key = priv_key;
                existing.pub_key = pub_key.clone();
            } else {
                state.sig_key = Some(SigKey {
                    alg,
                    priv_key,
                    pub_key: pub_key.clone(),
                });
            }
        }
        if let Err(sw) = self.persist_state() {
            // Rollback em memória se a persistência falhar: remove a chave
            // recém-gravada para não divergir do storage.
            if let Ok(state) = self.state_mut() {
                if let Some(key) = state.sig_key.as_mut() {
                    key.priv_key.zeroize();
                }
                state.sig_key = None;
            }
            return Err(sw);
        }
        debug!("OpenPGP GENERATE succeeded");
        Ok(ResponseData::ok(pubkey_object(alg, &pub_key)))
    }

    /// PERFORM SECURITY OPERATION (`0x2A`): SIGN (`9E9A`) / DECIPHER (`8086`).
    ///
    /// SIGN exige sessão PW1 verificada e chave residente (`6982` sem
    /// qualquer dos dois); DECIPHER sempre `6982` nesta fase.
    fn cmd_pso(&mut self, apdu: &Apdu) -> Result<ResponseData, u16> {
        match (apdu.p1, apdu.p2) {
            (PSO_P1_SIGN, PSO_P2_SIGN) => {
                if !self.pw1_verified {
                    return Err(transport::iso7816::SW_SECURITY_STATUS);
                }
                if apdu.data.is_empty() || apdu.data.len() > MAX_SIGN_DATA_LEN {
                    return Err(SW_WRONG_SYNTAX);
                }
                // Escopo do borrow da chave: a assinatura sai owned, sem reter refs.
                let (alg, mut priv_copy) = {
                    self.ensure_loaded()?;
                    let state = self.state.as_ref().expect("loaded above");
                    let key = state
                        .sig_key
                        .as_ref()
                        .ok_or(transport::iso7816::SW_SECURITY_STATUS)?;
                    (key.alg, key.priv_key.clone())
                };
                let sig = match alg {
                    ALG_ED25519 => self.crypto.sign(apdu.data, &priv_copy),
                    ALG_P256 => self.crypto.sign_p256(&priv_copy, apdu.data),
                    _ => return Err(SW_WRONG_SYNTAX),
                };
                priv_copy.zeroize();
                match sig {
                    Ok(signature) => {
                        debug!("OpenPGP PSO SIGN succeeded");
                        Ok(ResponseData::ok(signature))
                    }
                    Err(_) => Err(transport::iso7816::SW_CONDITIONS_NOT_SATISFIED),
                }
            }
            (PSO_P1_DECIPHER, PSO_P2_DECIPHER) => {
                // Sem slot DEC na F2b: condição de segurança, não ausência.
                Err(transport::iso7816::SW_SECURITY_STATUS)
            }
            _ => Err(transport::iso7816::SW_WRONG_P1_P2),
        }
    }
}

impl Applet for OpenPgpApplet<'_> {
    fn aid(&self) -> &[u8] {
        AID_OPENPGP_FULL
    }

    fn select(&mut self) -> Result<(), u16> {
        self.ensure_loaded()
    }

    /// Dados da aplicação (`0x6F` com AID + bytes históricos) — o que o
    /// `gpg --card-status` espera encontrar após o SELECT.
    fn select_response(&mut self) -> Vec<u8> {
        Self::application_data()
    }

    fn process(&mut self, apdu: &Apdu) -> Result<ResponseData, u16> {
        if apdu.cla != 0x00 {
            return Err(SW_CLASS_NOT_SUPPORTED);
        }
        match apdu.ins {
            INS_VERIFY => self.cmd_verify(apdu),
            INS_GET_DATA => self.cmd_get_data(apdu),
            INS_GENERATE => self.cmd_generate(apdu),
            INS_PSO => self.cmd_pso(apdu),
            _ => Err(transport::iso7816::SW_INS_NOT_SUPPORTED),
        }
    }
}

impl Drop for OpenPgpApplet<'_> {
    fn drop(&mut self) {
        // Zera senhas e chave privada remanescentes em memória (regra do repo).
        if let Some(mut state) = self.state.take() {
            state.pw1.zeroize();
            state.pw3.zeroize();
            if let Some(mut key) = state.sig_key.take() {
                key.priv_key.zeroize();
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
    const MASTER_KEY: [u8; 32] = [22u8; 32];

    fn make_applet(storage: &core::cell::RefCell<StorageEngine>) -> OpenPgpApplet<'_> {
        OpenPgpApplet::new(storage, CryptoEngine::from_key(MASTER_KEY)).unwrap()
    }

    fn open_persistent<'a>(
        storage: &'a core::cell::RefCell<StorageEngine>,
        path: &std::path::Path,
    ) -> OpenPgpApplet<'a> {
        let backend = FileStorageBackend::new(path.to_path_buf()).unwrap();
        *storage.borrow_mut() = StorageEngine::with_backend(Box::new(backend));
        OpenPgpApplet::new(storage, CryptoEngine::from_key(MASTER_KEY)).unwrap()
    }

    fn temp_root(tag: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("openkey-openpgp-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    /// Processa um frame bruto com semântica de applet: `Err(sw)` vira
    /// resposta vazia com a Status Word correspondente.
    fn run(applet: &mut OpenPgpApplet, raw: &[u8]) -> ResponseData {
        let apdu = Apdu::parse(raw).unwrap();
        match applet.process(&apdu) {
            Ok(response) => response,
            Err(sw) => ResponseData::with_sw(Vec::new(), sw),
        }
    }

    /// VERIFY caso 3S/2S com o seletor em P1: `00 20 slot 00 [Lc pw]`.
    fn verify_p1(slot: u8, pw: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, INS_VERIFY, slot, 0x00];
        if pw.is_empty() {
            return v;
        }
        v.push(pw.len() as u8);
        v.extend_from_slice(pw);
        v
    }

    /// VERIFY no formato da spec (seletor em P2): `00 20 00 slot [Lc pw]`.
    fn verify_p2(slot: u8, pw: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, INS_VERIFY, 0x00, slot];
        if pw.is_empty() {
            return v;
        }
        v.push(pw.len() as u8);
        v.extend_from_slice(pw);
        v
    }

    /// GET DATA caso 2S: `00 CA P1 P2 Le`.
    fn get_data(p1: u8, p2: u8) -> Vec<u8> {
        vec![0x00, INS_GET_DATA, p1, p2, 0x00]
    }

    fn select_frame(aid: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, INS_SELECT, 0x04, 0x00, aid.len() as u8];
        v.extend_from_slice(aid);
        v
    }

    // --- helpers da fase F2b ---------------------------------------------------------

    /// GENERATE caso 3S com byte único de algoritmo: `00 47 P1 00 01 <alg>`.
    fn generate(p1: u8, alg: u8) -> Vec<u8> {
        vec![0x00, INS_GENERATE, p1, 0x00, 0x01, alg]
    }

    /// GENERATE com CRT `B6 03 80 01 <alg>`.
    fn generate_crt(crt: u8, alg: u8) -> Vec<u8> {
        let data = [crt, 0x03, 0x80, 0x01, alg];
        let mut v = vec![0x00, INS_GENERATE, 0x80, 0x00, data.len() as u8];
        v.extend_from_slice(&data);
        v
    }

    /// PSO SIGN caso 3S: `00 2A 9E 9A Lc <dados>`.
    fn pso_sign(data: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, INS_PSO, PSO_P1_SIGN, PSO_P2_SIGN, data.len() as u8];
        v.extend_from_slice(data);
        v
    }

    /// PSO DECIPHER caso 3S: `00 2A 80 86 Lc <dados>`.
    fn pso_decipher(data: &[u8]) -> Vec<u8> {
        let mut v = vec![
            0x00,
            INS_PSO,
            PSO_P1_DECIPHER,
            PSO_P2_DECIPHER,
            data.len() as u8,
        ];
        v.extend_from_slice(data);
        v
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

    // --- ciclo de vida das senhas ------------------------------------------------------

    #[test]
    fn test_openpgp_aid_prefix_is_prefix_of_full() {
        assert_eq!(&AID_OPENPGP_FULL[..AID_OPENPGP.len()], AID_OPENPGP);
        assert_eq!(AID_OPENPGP, &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]);
    }

    #[test]
    fn test_verify_lifecycle_pw1_and_pw3() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        // Status inicial das duas senhas, sem consumir.
        assert_eq!(
            run(&mut applet, &verify_p1(PW_SIGN, &[])).sw,
            Some(sw_retries(3))
        );
        assert_eq!(
            run(&mut applet, &verify_p2(PW_ADMIN, &[])).sw,
            Some(sw_retries(3))
        );

        // PW1 errado consome só do PW1.
        assert_eq!(
            run(&mut applet, &verify_p1(PW_SIGN, b"000000")).sw,
            Some(sw_retries(2))
        );
        assert_eq!(
            run(&mut applet, &verify_p2(PW_ADMIN, &[])).sw,
            Some(sw_retries(3))
        );

        // PW1 padrão autentica e restaura; formato P2 da spec também vale.
        assert_eq!(run(&mut applet, &verify_p2(PW_OTHER, DEFAULT_PW1)).sw, None);
        assert_eq!(
            run(&mut applet, &verify_p1(PW_SIGN, &[])).sw,
            Some(sw_retries(3))
        );

        // PW3 padrão autentica.
        assert_eq!(run(&mut applet, &verify_p1(PW_ADMIN, DEFAULT_PW3)).sw, None);
    }

    #[test]
    fn test_verify_blocked_returns_security_status() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        assert_eq!(
            run(&mut applet, &verify_p1(PW_SIGN, b"000000")).sw,
            Some(sw_retries(2))
        );
        assert_eq!(
            run(&mut applet, &verify_p1(PW_SIGN, b"000000")).sw,
            Some(sw_retries(1))
        );
        assert_eq!(
            run(&mut applet, &verify_p1(PW_SIGN, b"000000")).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );
        // Bloqueado: até a senha correta é rejeitada.
        assert_eq!(
            run(&mut applet, &verify_p1(PW_SIGN, DEFAULT_PW1)).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );
        // PW3 segue independente.
        assert_eq!(
            run(&mut applet, &verify_p1(PW_ADMIN, &[])).sw,
            Some(sw_retries(3))
        );
    }

    #[test]
    fn test_verify_invalid_selector_is_rejected() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        assert_eq!(
            run(&mut applet, &verify_p1(0x80, b"123456")).sw,
            Some(transport::iso7816::SW_WRONG_P1_P2)
        );
    }

    // --- persistência entre reinícios ---------------------------------------------------

    #[test]
    fn test_retries_persist_across_restart() {
        let root = temp_root("retries");
        let path = root.join("store.json");

        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut first = open_persistent(&storage, &path);
        assert_eq!(
            run(&mut first, &verify_p1(PW_SIGN, b"000000")).sw,
            Some(sw_retries(2))
        );
        drop(first);

        // Recria o applet sobre o mesmo arquivo: contador não ressuscita.
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut second = open_persistent(&storage, &path);
        assert_eq!(
            run(&mut second, &verify_p1(PW_SIGN, &[])).sw,
            Some(sw_retries(2))
        );

        // Senha correta ainda funciona e a restauração persiste.
        assert_eq!(run(&mut second, &verify_p1(PW_SIGN, DEFAULT_PW1)).sw, None);
        drop(second);

        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut third = open_persistent(&storage, &path);
        assert_eq!(
            run(&mut third, &verify_p1(PW_SIGN, &[])).sw,
            Some(sw_retries(3))
        );
    }

    // --- SELECT, objetos de dados e erros -------------------------------------------------

    #[test]
    fn test_select_returns_6f_application_data() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        applet.select().unwrap();
        let data = applet.select_response();
        assert_eq!(data[0], 0x6F);
        assert!(!data.is_empty());
    }

    #[test]
    fn test_get_data_known_tags() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        let resp = run(&mut applet, &get_data(0x00, 0x4F));
        assert_eq!(resp.sw, None);
        assert_eq!(resp.data[0], 0x4F);

        let resp = run(&mut applet, &get_data(0x5F, 0x52));
        assert_eq!(resp.sw, None);
        assert_eq!(resp.data, HISTORICAL_BYTES);

        // Slot vazio: atributos placeholder da F1.
        let resp = run(&mut applet, &get_data(0x00, 0x7A));
        assert_eq!(resp.sw, None);
        assert_eq!(resp.data, SIG_ALGO_ATTRIBUTES_EMPTY);

        // Slot vazio: B600 e C5 negam com 6982.
        assert_eq!(
            run(&mut applet, &get_data(0xB6, 0x00)).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );
        assert_eq!(
            run(&mut applet, &get_data(0x00, 0xC5)).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );
    }

    #[test]
    fn test_get_data_unknown_tag_returns_file_not_found() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        assert_eq!(
            run(&mut applet, &get_data(0x5F, 0x50)).sw,
            Some(transport::iso7816::SW_FILE_NOT_FOUND)
        );
        assert_eq!(
            run(&mut applet, &get_data(0x00, 0x00)).sw,
            Some(transport::iso7816::SW_FILE_NOT_FOUND)
        );
    }

    #[test]
    fn test_pso_sign_without_key_or_verify_returns_security_status() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        // Sem chave e sem sessão: 6982.
        let apdu = Apdu::parse(&[0x00, INS_PSO, 0x9E, 0x9A, 0x01, 0xAA]).unwrap();
        assert_eq!(
            applet.process(&apdu).unwrap_err(),
            transport::iso7816::SW_SECURITY_STATUS
        );

        // DECIPHER sempre 6982, mesmo sem chave.
        let apdu = Apdu::parse(&[0x00, INS_PSO, 0x80, 0x86, 0x01, 0xAA]).unwrap();
        assert_eq!(
            applet.process(&apdu).unwrap_err(),
            transport::iso7816::SW_SECURITY_STATUS
        );
    }

    #[test]
    fn test_unknown_ins_returns_ins_not_supported() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        // INS arbitrário fora do mapa: 6D00.
        let raw = [0x00, 0x42u8, 0x00, 0x00];
        let apdu = Apdu::parse(&raw).unwrap();
        assert_eq!(
            applet.process(&apdu).unwrap_err(),
            transport::iso7816::SW_INS_NOT_SUPPORTED
        );
        // GENERATE agora é roteado ao handler: CRT DEC fora de escopo → 6A82.
        assert_eq!(
            run(&mut applet, &generate_crt(CRT_DEC, ALG_ED25519)).sw,
            Some(transport::iso7816::SW_FILE_NOT_FOUND)
        );
    }

    #[test]
    fn test_wrong_cla_is_rejected() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        let raw = vec![0x80, INS_VERIFY, 0x00, 0x81, 0x00];
        assert_eq!(run(&mut applet, &raw).sw, Some(SW_CLASS_NOT_SUPPORTED));
        let raw = vec![0x80, INS_GENERATE, 0x00, 0x00, 0x01, ALG_ED25519];
        assert_eq!(run(&mut applet, &raw).sw, Some(SW_CLASS_NOT_SUPPORTED));
        let raw = vec![0x80, INS_PSO, 0x9E, 0x9A, 0x01, 0xAA];
        assert_eq!(run(&mut applet, &raw).sw, Some(SW_CLASS_NOT_SUPPORTED));
    }

    // --- chaves F2b: GENERATE / GET DATA / PSO SIGN -------------------------------------

    #[test]
    fn test_generate_ed25519_sign_roundtrip_with_independent_verify() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        let engine = CryptoEngine::from_key(MASTER_KEY);

        // Gera Ed25519 (byte único); CRT B6 equivalente também vale.
        let resp = run(&mut applet, &generate(0x00, ALG_ED25519));
        assert_eq!(resp.sw, None);
        let (alg, pubkey) = parse_pubkey_object(&resp.data);
        assert_eq!(alg, ALG_ED25519);
        assert_eq!(pubkey.len(), 32);

        // GET DATA B600 devolve o mesmo objeto; C5 a impressão SHA-256.
        let resp = run(&mut applet, &get_data(0xB6, 0x00));
        assert_eq!(resp.sw, None);
        assert_eq!(parse_pubkey_object(&resp.data), (alg, pubkey.clone()));
        let resp = run(&mut applet, &get_data(0x00, 0xC5));
        assert_eq!(resp.sw, None);
        assert_eq!(resp.data, engine.sha256(&pubkey));

        // Atributos de algoritmo refletem a chave residente.
        let resp = run(&mut applet, &get_data(0x00, 0x7A));
        assert_eq!(resp.sw, None);
        assert_eq!(resp.data, SIG_ALGO_ATTRIBUTES_ED25519);

        // Sem VERIFY: SIGN nega com 6982.
        let digest = b"openpgp-sign-digest-ed25519";
        assert_eq!(
            run(&mut applet, &pso_sign(digest)).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );

        // Após VERIFY PW1: assina; verificação independente confere.
        assert_eq!(run(&mut applet, &verify_p2(PW_SIGN, DEFAULT_PW1)).sw, None);
        let resp = run(&mut applet, &pso_sign(digest));
        assert_eq!(resp.sw, None);
        assert_eq!(resp.data.len(), 64);
        assert!(engine.verify(digest, &resp.data, &pubkey).unwrap());

        // DECIPHER segue 6982 mesmo com chave e sessão.
        assert_eq!(
            run(&mut applet, &pso_decipher(digest)).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );
    }

    #[test]
    fn test_generate_p256_sign_roundtrip_with_independent_verify() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        let engine = CryptoEngine::from_key(MASTER_KEY);

        // Gera P-256 via CRT B6.
        let resp = run(&mut applet, &generate_crt(CRT_SIG, ALG_P256));
        assert_eq!(resp.sw, None);
        let (alg, pubkey) = parse_pubkey_object(&resp.data);
        assert_eq!(alg, ALG_P256);
        assert_eq!(pubkey.len(), 65);
        assert_eq!(pubkey[0], 0x04);

        let resp = run(&mut applet, &get_data(0x00, 0x7A));
        assert_eq!(resp.sw, None);
        assert_eq!(resp.data, SIG_ALGO_ATTRIBUTES_P256);

        assert_eq!(run(&mut applet, &verify_p1(PW_OTHER, DEFAULT_PW1)).sw, None);
        let digest = b"openpgp-sign-digest-p256";
        let resp = run(&mut applet, &pso_sign(digest));
        assert_eq!(resp.sw, None);
        engine.verify_p256(&pubkey, digest, &resp.data).unwrap();

        // Regenerar troca a chave (objeto difere) e a antiga não verifica mais.
        let resp2 = run(&mut applet, &generate(0x80, ALG_ED25519));
        assert_eq!(resp2.sw, None);
        assert_ne!(resp2.data, resp.data);
        let resp = run(&mut applet, &pso_sign(digest));
        assert_eq!(resp.sw, None);
        assert!(engine
            .verify(digest, &resp.data, &parse_pubkey_object(&resp2.data).1)
            .unwrap());
    }

    #[test]
    fn test_pso_sign_requires_pw1_session_not_pw3() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        assert_eq!(run(&mut applet, &generate(0x00, ALG_ED25519)).sw, None);
        let digest = b"pw1-gate-probe";

        // VERIFY PW3 não libera SIGN.
        assert_eq!(run(&mut applet, &verify_p1(PW_ADMIN, DEFAULT_PW3)).sw, None);
        assert_eq!(
            run(&mut applet, &pso_sign(digest)).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );

        // VERIFY PW1 libera.
        assert_eq!(run(&mut applet, &verify_p1(PW_SIGN, DEFAULT_PW1)).sw, None);
        assert_eq!(run(&mut applet, &pso_sign(digest)).sw, None);
    }

    #[test]
    fn test_keys_persist_across_restart_and_require_reverify() {
        let root = temp_root("openpgp-keys");
        let path = root.join("store.json");

        let pub_before = {
            let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
            let mut first = open_persistent(&storage, &path);
            let resp = run(&mut first, &generate(0x00, ALG_ED25519));
            assert_eq!(resp.sw, None);
            let (_, pubkey) = parse_pubkey_object(&resp.data);
            assert_eq!(run(&mut first, &verify_p1(PW_SIGN, DEFAULT_PW1)).sw, None);
            let resp = run(&mut first, &pso_sign(b"pre-restart"));
            assert_eq!(resp.sw, None);
            pubkey
        };

        // Reabre sobre o mesmo arquivo: chave sobrevive, sessão não.
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut second = open_persistent(&storage, &path);
        let engine = CryptoEngine::from_key(MASTER_KEY);

        let resp = run(&mut second, &get_data(0xB6, 0x00));
        assert_eq!(resp.sw, None);
        assert_eq!(parse_pubkey_object(&resp.data).1, pub_before);
        let resp = run(&mut second, &get_data(0x00, 0xC5));
        assert_eq!(resp.sw, None);
        assert_eq!(resp.data, engine.sha256(&pub_before));

        // SIGN sem novo VERIFY: 6982; após VERIFY: assina e verifica.
        let digest = b"post-restart";
        assert_eq!(
            run(&mut second, &pso_sign(digest)).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );
        assert_eq!(run(&mut second, &verify_p1(PW_SIGN, DEFAULT_PW1)).sw, None);
        let resp = run(&mut second, &pso_sign(digest));
        assert_eq!(resp.sw, None);
        assert!(engine.verify(digest, &resp.data, &pub_before).unwrap());
    }

    #[test]
    fn test_unknown_slot_and_empty_codes() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);

        // CRTs DEC/AUT fora de escopo: 6A82.
        assert_eq!(
            run(&mut applet, &generate_crt(CRT_DEC, ALG_ED25519)).sw,
            Some(transport::iso7816::SW_FILE_NOT_FOUND)
        );
        assert_eq!(
            run(&mut applet, &generate_crt(CRT_AUT, ALG_ED25519)).sw,
            Some(transport::iso7816::SW_FILE_NOT_FOUND)
        );

        // Algoritmo desconhecido: 6A80; P1/P2 fora do mapa: 6B00.
        assert_eq!(
            run(&mut applet, &generate(0x00, 0x07)).sw,
            Some(SW_WRONG_SYNTAX)
        );
        let raw = vec![0x00, INS_GENERATE, 0x00, 0x01, 0x01, ALG_ED25519];
        assert_eq!(
            run(&mut applet, &raw).sw,
            Some(transport::iso7816::SW_WRONG_P1_P2)
        );

        // PSO com P1/P2 fora do mapa: 6B00.
        let raw = vec![0x00, INS_PSO, 0x00, 0x00, 0x01, 0xAA];
        assert_eq!(
            run(&mut applet, &raw).sw,
            Some(transport::iso7816::SW_WRONG_P1_P2)
        );

        // Slot vazio com sessão: GET DATA e SIGN → 6982.
        assert_eq!(run(&mut applet, &verify_p1(PW_SIGN, DEFAULT_PW1)).sw, None);
        assert_eq!(
            run(&mut applet, &get_data(0xB6, 0x00)).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );
        // PSO SIGN vazio (caso 1, sem dados): parse entrega data vazio → 6A80
        // tem precedência de sintaxe; com dados e sem chave → 6982.
        let raw = vec![0x00, INS_PSO, PSO_P1_SIGN, PSO_P2_SIGN];
        assert_eq!(run(&mut applet, &raw).sw, Some(SW_WRONG_SYNTAX));
        assert_eq!(
            run(&mut applet, &pso_sign(b"c")).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );
    }

    #[test]
    fn test_f1_blob_migrates_to_f2_preserving_passwords() {
        let root = temp_root("openpgp-migrate");
        let path = root.join("store.json");

        // Forja um blob F1 (versão 1): PW1 "654321" (2 retries), PW3 padrão.
        let engine = CryptoEngine::from_key(MASTER_KEY);
        let mut plaintext = vec![0x01, 0x06];
        plaintext.extend_from_slice(b"654321");
        plaintext.push(0x02);
        plaintext.push(DEFAULT_PW3.len() as u8);
        plaintext.extend_from_slice(DEFAULT_PW3);
        plaintext.push(MAX_RETRIES);
        let (nonce, ciphertext) = engine.encrypt_with_random_nonce(&plaintext).unwrap();
        let mut blob = nonce;
        blob.extend_from_slice(&ciphertext);
        {
            let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
            let backend = FileStorageBackend::new(path.clone()).unwrap();
            *storage.borrow_mut() = StorageEngine::with_backend(Box::new(backend));
            storage.borrow_mut().store(STORAGE_KEY, blob).unwrap();
        }

        // Reabre: migra para F2b preservando senhas e tentativas.
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = open_persistent(&storage, &path);
        assert_eq!(
            run(&mut applet, &verify_p1(PW_SIGN, &[])).sw,
            Some(sw_retries(2))
        );
        assert_eq!(run(&mut applet, &verify_p1(PW_SIGN, b"654321")).sw, None);
        // Sem chave após migração: B600/C5 → 6982; gerar passa a funcionar.
        assert_eq!(
            run(&mut applet, &get_data(0xB6, 0x00)).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );
        assert_eq!(run(&mut applet, &generate(0x00, ALG_ED25519)).sw, None);
    }

    // --- roteador: prefixo curto e AID estendido --------------------------------------------

    #[test]
    fn test_router_selects_short_prefix_and_extended_aid() {
        let storage: &'static core::cell::RefCell<StorageEngine> = Box::leak(Box::new(
            core::cell::RefCell::new(StorageEngine::new().unwrap()),
        ));
        let applet = Box::leak(Box::new(
            OpenPgpApplet::new(storage, CryptoEngine::from_key(MASTER_KEY)).unwrap(),
        ));
        let mut router = CardRouter::new();
        router.register(applet);

        // Prefixo curto de 6 bytes casa por prefixo.
        let resp = router.process(&select_frame(AID_OPENPGP));
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        assert_eq!(resp.data[0], 0x6F);

        // AID estendido completo casa por igualdade exata.
        let resp = router.process(&select_frame(AID_OPENPGP_FULL));
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        assert_eq!(resp.data[0], 0x6F);
    }
}
