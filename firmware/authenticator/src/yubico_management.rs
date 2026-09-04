//! Aplicação Yubico Management como applet ISO/IEC 7816-4.
//!
//! Implementa o subconjunto da YubiKey Management Application exigido pelo
//! python-yubikit/ykman (`ManagementSession` sobre `SmartCardConnection`,
//! backend `_ManagementSmartCardBackend`) para que `ykman info` e a detecção
//! de serial em `ykman list` funcionem sobre CCID. Registrada no
//! [`CardRouter`](transport::iso7816::CardRouter) sob o AID
//! `A000000527471117`.
//!
//! # Comandos suportados
//!
//! Descoberta pelo host mais escrita de configuração (aba Interfaces do
//! Yubico Authenticator / `ykman config usb`), sem código de bloqueio por
//! padrão:
//!
//! | Comando     | INS    | P1                | Resposta / efeito                 |
//! |-------------|--------|-------------------|-----------------------------------|
//! | SELECT AID  | `0xA4` | `0x04` (roteador) | ASCII da versão, ex. `"5.4.0"`    |
//! | READ CONFIG | `0x1D` | página (`0x00`)   | `[len][TLVs…]` (DeviceInfo)       |
//! | SET MODE    | `0x16` | `0x11`            | persiste `usb_enabled` + timeouts |
//! | WRITE CONFIG| `0x1C` | `0x00`            | persiste `DeviceConfig` TLVs        |
//!
//! `DEVICE RESET` (`0x1F`) não é implementado (só existe no YubiKey Bio):
//! responde `6D00`, como qualquer outro INS desconhecido.
//!
//! # Layout da resposta de READ CONFIG
//!
//! Byte único de comprimento seguido de TLVs de forma curta; o comprimento
//! deve ser exatamente o total dos TLVs (`len(encoded) - 1 == encoded[0]`),
//! senão o ykman rejeita com `BadResponseError("Invalid length")`. TLVs
//! emitidos (ordem crescente de tag, como nas chaves físicas):
//!
//! | Tag    | Campo            | Valor                                                  |
//! |--------|------------------|--------------------------------------------------------|
//! | `0x01` | USB supported    | bitmask CAPABILITY big-endian (obrigatório ao parser)  |
//! | `0x02` | Serial           | u32 big-endian estável                                 |
//! | `0x03` | USB enabled      | mesma bitmask (honrada apenas com versão >= 5.0.0)     |
//! | `0x04` | Form factor      | código de 1 byte (nibble alto = flags FIPS/SKY)        |
//! | `0x05` | Firmware version | 3 bytes, igual ao SELECT                               |
//!
//! Demais campos do `DeviceInfo` usam default no parser quando ausentes
//! (verificado no código-fonte do python-yubikit): NFC, timeouts, flags,
//! lock code, part number, versões FPS/STM e `TAG_MORE_DATA` são omitidos —
//! sem `TAG_MORE_DATA` o ykman encerra a paginação após a página 0.
//!
//! # Decisões registradas
//!
//! - **Versão reportada `(5,4,0)`, não `(3,4,0)`**: diferente do applet OATH,
//!   o backend smartcard do Management exige versão >= `(4,1,0)`
//!   (`require_version` em `read_device_info`) e desvia para workarounds de
//!   NEO quando major == 3; abaixo de `(5,0,0)` o ykman ignora
//!   `TAG_USB_ENABLED` ("broken on YK4"). `(5,4,0)` também evita as faixas
//!   "preview" e o touch-workaround de `4.2.x`. Nenhum comando implementado
//!   carrega dados na forma estendida que o yubikit passa a usar no USB para
//!   v >= 4 — todos chegam como casos 1/2S (`00 1D P1 00`), aceitos pelo
//!   roteador atual.
//! - **Serial pseudo-aleatório persistido**: não há wiring de unique-id de
//!   hardware ainda; um u32 não nulo é gerado com `SystemRandom` no primeiro
//!   uso e gravado cifrado sob a chave reservada `sys:mgmt`. Placeholder até
//!   existir acesso ao chip ID real. Blob ilegível (chave-mestra trocada ou
//!   dado corrompido) regenera o serial com log — mesma política de fábrica
//!   do applet OATH. O serial é informação pública impressa pelo ykman; o
//!   estado deste applet não carrega segredo (zeroize desnecessário).
//! - **Form factor `USB_A_KEYCHAIN` (0x01)**: valor mais próximo do hardware
//!   alvo (dongle USB-A); qualquer código 0–7 é aceito pela enum
//!   `FORM_FACTOR` do python-yubikit, e o nibble alto fica limpo (sem flags
//!   FIPS/SKY). Placeholder até wiring de identidade de produto.
//! - **Capacidades `0x062E`**: `OATH (0x20) | PIV (0x02) | OpenPGP (0x08) |
//!   FIDO2 (0x200) | Management sobre CCID (0x400) | CCID geral (0x04)` — os
//!   dois últimos bits não têm nome na enum `CAPABILITY`, mas entram no
//!   cálculo de `usb_interfaces` do yubikit (interface CCID anunciada
//!   corretamente). PIV (F2a) e OpenPGP SIG (F2b) têm chaves reais, por isso
//!   são anunciados; OTP e HSMAUTH seguem fora.
//! - **Página única**: `P1 != 0` responde `6B00`; o ykman só pagina quando
//!   encontra `TAG_MORE_DATA`, que nunca emitimos, logo o caminho é apenas
//!   defensivo.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;
use crypto::{constant_time_eq, CryptoEngine};
use log::warn;
use storage::StorageEngine;
use transport::iso7816::{Apdu, Applet, CardRouter, ResponseData};

extern crate alloc;

/// AID da aplicação YubiKey Management (`AID.MANAGEMENT` do python-yubikit).
pub const AID_YUBICO_MANAGEMENT: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

/// Chave reservada no [`StorageEngine`] para o estado cifrado do applet.
const STORAGE_KEY: &str = "sys:mgmt";

/// Versão do formato de serialização do estado (`v1` = só serial,
/// migrado para `v2` com `usb_enabled` + lock + timeouts/flags).
const STATE_FORMAT_VERSION: u8 = 2;
/// Versão legada aceita na leitura (migração sem perda do serial).
const STATE_FORMAT_VERSION_V1: u8 = 1;

/// Versão reportada no SELECT e no TLV `0x05` — ver decisão no topo.
const REPORTED_VERSION: [u8; 3] = [0x05, 0x04, 0x00];

/// Bits CAPABILITY anunciados em USB supported/enabled (big-endian, 2 bytes).
const SUPPORTED_CAPABILITIES: u16 = 0x062E;

/// Form factor reportado (`FORM_FACTOR.USB_A_KEYCHAIN`) — ver decisão no topo.
const FORM_FACTOR_CODE: u8 = 0x01;

// --- Tags TLV (python-yubikit, `yubikit.management`) ---------------------------

const TAG_USB_SUPPORTED: u8 = 0x01;
const TAG_SERIAL: u8 = 0x02;
const TAG_USB_ENABLED: u8 = 0x03;
const TAG_FORM_FACTOR: u8 = 0x04;
const TAG_VERSION: u8 = 0x05;
const TAG_AUTO_EJECT_TIMEOUT: u8 = 0x06;
const TAG_CHALRESP_TIMEOUT: u8 = 0x07;
const TAG_DEVICE_FLAGS: u8 = 0x08;
const TAG_CONFIG_LOCK: u8 = 0x0A;
const TAG_UNLOCK: u8 = 0x0B;
const TAG_REBOOT: u8 = 0x0C;
const TAG_NFC_ENABLED: u8 = 0x0E;

// --- Instruções (`_ManagementSmartCardBackend`) ---------------------------------

/// READ CONFIG: leitura do DeviceInfo paginado por P1.
const INS_READ_CONFIG: u8 = 0x1D;
/// SET MODE legado (YubiKey NEO/4; no 5.x o host traduz para WRITE CONFIG).
const INS_SET_MODE: u8 = 0x16;
/// WRITE CONFIG (`DeviceConfig::get_bytes` do yubikit, exige versão ≥ 5.0).
const INS_WRITE_CONFIG: u8 = 0x1C;
/// P1 do SET MODE sobre CCID (`P1_DEVICE_CONFIG` do yubikit).
const P1_DEVICE_CONFIG: u8 = 0x11;
/// Tamanho do código de bloqueio de configuração (16 bytes).
const LOCK_CODE_LEN: usize = 16;

// --- Status Words ----------------------------------------------------------------

/// CLA diferente de `0x00` (mesma política do applet OATH).
const SW_CLASS_NOT_SUPPORTED: u16 = 0x6E00;
/// Dado malformado ou fora do suportado (`6A80`, convenção dos applets PIV/OpenPGP/OATH).
const SW_WRONG_SYNTAX: u16 = 0x6A80;

// --- Estado ------------------------------------------------------------------------

/// Estado do applet: identidade estável + configuração gravável.
///
/// O serial é informação pública (o ykman imprime); o código de bloqueio,
/// quando definido, é sensível e por isso é redigido no `Debug` do applet
/// (que só mostra `loaded`/`serial`) e nunca entra em logs.
struct ManagementState {
    serial: u32,
    usb_enabled: u16,
    nfc_enabled: u16,
    auto_eject_timeout: u16,
    chalresp_timeout: u8,
    device_flags: u8,
    lock_code: Option<[u8; LOCK_CODE_LEN]>,
}

impl ManagementState {
    fn factory(serial: u32) -> Self {
        Self {
            serial,
            usb_enabled: SUPPORTED_CAPABILITIES,
            nfc_enabled: 0,
            auto_eject_timeout: 0,
            chalresp_timeout: 0,
            device_flags: 0,
            lock_code: None,
        }
    }
}

/// Layout `v2` (30 bytes): `[ver][serial 4][usb 2][nfc 2][eject 2]
/// [chalresp 1][flags 1][has_lock 1][lock 16]`.
fn serialize_state(state: &ManagementState) -> Vec<u8> {
    let mut out = Vec::with_capacity(30);
    out.push(STATE_FORMAT_VERSION);
    out.extend_from_slice(&state.serial.to_be_bytes());
    out.extend_from_slice(&state.usb_enabled.to_be_bytes());
    out.extend_from_slice(&state.nfc_enabled.to_be_bytes());
    out.extend_from_slice(&state.auto_eject_timeout.to_be_bytes());
    out.push(state.chalresp_timeout);
    out.push(state.device_flags);
    match &state.lock_code {
        None => {
            out.push(0);
            out.extend_from_slice(&[0u8; LOCK_CODE_LEN]);
        }
        Some(code) => {
            out.push(1);
            out.extend_from_slice(code);
        }
    }
    out
}

/// Aceita `v2` e migra `v1` (só serial, demais campos com defaults);
/// rejeita blobs com formato desconhecido ou serial nulo (inválido para o
/// parser do yubikit, que trata serial 0 como ausente).
fn parse_state(blob: &[u8]) -> Option<ManagementState> {
    if blob.is_empty() {
        return None;
    }
    match blob[0] {
        STATE_FORMAT_VERSION_V1 => {
            if blob.len() != 5 {
                return None;
            }
            let serial = u32::from_be_bytes([blob[1], blob[2], blob[3], blob[4]]);
            if serial == 0 {
                return None;
            }
            Some(ManagementState::factory(serial))
        }
        STATE_FORMAT_VERSION => {
            if blob.len() != 30 {
                return None;
            }
            let serial = u32::from_be_bytes([blob[1], blob[2], blob[3], blob[4]]);
            if serial == 0 {
                return None;
            }
            let lock_code = match blob[13] {
                0 => None,
                1 => {
                    let mut code = [0u8; LOCK_CODE_LEN];
                    code.copy_from_slice(&blob[14..30]);
                    Some(code)
                }
                _ => return None,
            };
            Some(ManagementState {
                serial,
                usb_enabled: u16::from_be_bytes([blob[5], blob[6]]),
                nfc_enabled: u16::from_be_bytes([blob[7], blob[8]]),
                auto_eject_timeout: u16::from_be_bytes([blob[9], blob[10]]),
                chalresp_timeout: blob[11],
                device_flags: blob[12],
                lock_code,
            })
        }
        _ => None,
    }
}

// --- Applet -------------------------------------------------------------------------

/// Applet ISO 7816-4 da aplicação YubiKey Management.
///
/// Construtor para a fase de integração:
/// [`ManagementApplet::new`] produz um valor pronto para ser registrado num
/// [`CardRouter`] via [`register_yubico_applets`].
pub struct ManagementApplet<'a> {
    /// Storage compartilhado com o applet OATH (mesma identidade/kv).
    storage: &'a core::cell::RefCell<StorageEngine>,
    crypto: CryptoEngine,
    state: Option<ManagementState>,
}

impl fmt::Debug for ManagementApplet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Serial é público (ykman imprime); nada sensível existe neste estado.
        f.debug_struct("ManagementApplet")
            .field("loaded", &self.state.is_some())
            .field("serial", &self.state.as_ref().map(|s| s.serial))
            .finish()
    }
}

impl<'a> ManagementApplet<'a> {
    /// Cria o applet sobre o storage e o motor criptográfico fornecidos.
    ///
    /// Carrega (ou inicializa) o estado persistido: um registro ausente é
    /// criado imediatamente com serial aleatório para que a identidade seja
    /// estável desde a primeira seleção. Registro ilegível (chave-mestra
    /// trocada ou dado corrompido) é substituído por estado de fábrica.
    pub fn new(
        storage: &'a core::cell::RefCell<StorageEngine>,
        crypto: CryptoEngine,
    ) -> Result<Self, Box<dyn core::error::Error>> {
        let mut applet = Self {
            storage,
            crypto,
            state: None,
        };
        applet
            .ensure_loaded()
            .map_err(|sw| format!("YK management init failed with SW {:#06X}", sw))?;
        Ok(applet)
    }

    /// Serial atual, quando o estado já foi carregado.
    #[must_use]
    pub fn serial(&self) -> Option<u32> {
        self.state.as_ref().map(|s| s.serial)
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
                // Chave presente porém ilegível: registra e gera identidade nova.
                if self.storage.borrow().retrieve(STORAGE_KEY).is_ok() {
                    warn!("YK management state unreadable; regenerating device identity");
                }
                let state = self.factory_state();
                self.state = Some(state);
                self.persist_state()
            }
        }
    }

    /// Estado de fábrica: serial aleatório não nulo (SystemRandom) com
    /// configuração default (tudo suportado habilitado, sem bloqueio).
    fn factory_state(&self) -> ManagementState {
        loop {
            let bytes = self.crypto.random_bytes(4);
            let serial = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            // Serial 0 significa "sem serial" para o yubikit; sorteia de novo.
            if serial != 0 {
                break ManagementState::factory(serial);
            }
        }
    }

    /// Serializa, cifra (nonce aleatório) e grava o estado atual.
    fn persist_state(&mut self) -> Result<(), u16> {
        let state = self
            .state
            .as_ref()
            .ok_or(transport::iso7816::SW_CONDITIONS_NOT_SATISFIED)?;
        let plaintext = serialize_state(state);
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
                warn!("YK management persistence failed: {}", e);
                transport::iso7816::SW_CONDITIONS_NOT_SATISFIED
            })
    }

    /// Monta a resposta de READ CONFIG: `[len][TLVs…]` na ordem do yubikit.
    ///
    /// Os 5 TLVs base são sempre emitidos (mesmo layout das chaves físicas);
    /// timeouts/flags só entram quando não-default para não quebrar o
    /// layout de 22 bytes do estado de fábrica; `TAG_NFC_ENABLED` é ecoado
    /// quando já foi gravado via WRITE CONFIG (sem `TAG_NFC_SUPPORTED`, o
    /// yubikit continua sem anunciar transporte NFC).
    fn read_config_payload(state: &ManagementState) -> Vec<u8> {
        let mut tlvs = Vec::new();
        push_tlv(
            &mut tlvs,
            TAG_USB_SUPPORTED,
            &SUPPORTED_CAPABILITIES.to_be_bytes(),
        );
        push_tlv(&mut tlvs, TAG_SERIAL, &state.serial.to_be_bytes());
        push_tlv(&mut tlvs, TAG_USB_ENABLED, &state.usb_enabled.to_be_bytes());
        push_tlv(&mut tlvs, TAG_FORM_FACTOR, &[FORM_FACTOR_CODE]);
        push_tlv(&mut tlvs, TAG_VERSION, &REPORTED_VERSION);
        if state.auto_eject_timeout != 0 {
            push_tlv(
                &mut tlvs,
                TAG_AUTO_EJECT_TIMEOUT,
                &state.auto_eject_timeout.to_be_bytes(),
            );
        }
        if state.chalresp_timeout != 0 {
            push_tlv(&mut tlvs, TAG_CHALRESP_TIMEOUT, &[state.chalresp_timeout]);
        }
        if state.device_flags != 0 {
            push_tlv(&mut tlvs, TAG_DEVICE_FLAGS, &[state.device_flags]);
        }
        if state.nfc_enabled != 0 {
            push_tlv(&mut tlvs, TAG_NFC_ENABLED, &state.nfc_enabled.to_be_bytes());
        }

        // Prefixo de comprimento exigido pelo parser (`len(encoded)-1 ==
        // encoded[0]`); payload cabe folgado em um byte.
        debug_assert!(tlvs.len() <= 255, "DeviceInfo TLVs exceed short length");
        let mut out = Vec::with_capacity(tlvs.len() + 1);
        out.push(tlvs.len() as u8);
        out.extend_from_slice(&tlvs);
        out
    }

    fn cmd_read_config(&mut self, page: u8) -> Result<ResponseData, u16> {
        if page != 0 {
            // Paginação nunca anunciada (sem TAG_MORE_DATA): caminho defensivo.
            return Err(transport::iso7816::SW_WRONG_P1_P2);
        }
        self.ensure_loaded()?;
        let state = self.state.as_ref().expect("loaded by ensure_loaded");
        Ok(ResponseData::ok(Self::read_config_payload(state)))
    }

    /// WRITE CONFIG (`0x1C`): aplica um `DeviceConfig::get_bytes` do yubikit.
    ///
    /// Formato: `[len][TLVs…]` com o comprimento cobrindo exatamente os TLVs
    /// (mesma regra do READ CONFIG). Tags honradas: `TAG_USB_ENABLED` (2B,
    /// deve ser subconjunto de `SUPPORTED_CAPABILITIES`, senão `6A80`),
    /// `TAG_NFC_ENABLED` (2B, persistido para eco), timeouts/flags,
    /// `TAG_REBOOT` (aceito como no-op — sem reboot físico no host),
    /// `TAG_UNLOCK`/`TAG_CONFIG_LOCK` (16B; sem bloqueio configurado,
    /// `TAG_UNLOCK` é ignorado; com bloqueio, divergência dá `6982`).
    /// Tags desconhecidas são ignoradas (compatibilidade futura).
    fn cmd_write_config(&mut self, data: &[u8]) -> Result<ResponseData, u16> {
        let tlvs = parse_config_payload(data)?;
        self.ensure_loaded()?;
        let state = self.state.as_mut().expect("loaded by ensure_loaded");

        // Bloqueio de configuração: valida antes de qualquer mutação.
        if let Some(cur) = tlv_get(&tlvs, TAG_UNLOCK) {
            if cur.len() != LOCK_CODE_LEN {
                return Err(SW_WRONG_SYNTAX);
            }
            // Sem bloqueio configurado, `TAG_UNLOCK` é ignorado (como na
            // chave física); com bloqueio, divergência dá `6982`.
            match &state.lock_code {
                Some(expected) if !constant_time_eq(cur, expected) => {
                    return Err(transport::iso7816::SW_SECURITY_STATUS);
                }
                _ => {}
            }
        }

        // Valida USB antes de mutar (tudo-ou-nada como na chave física).
        if let Some(value) = tlv_get(&tlvs, TAG_USB_ENABLED) {
            if value.len() != 2 {
                return Err(SW_WRONG_SYNTAX);
            }
            let caps = u16::from_be_bytes([value[0], value[1]]);
            if caps & !SUPPORTED_CAPABILITIES != 0 {
                return Err(SW_WRONG_SYNTAX);
            }
        }
        if let Some(value) = tlv_get(&tlvs, TAG_NFC_ENABLED) {
            if value.len() != 2 {
                return Err(SW_WRONG_SYNTAX);
            }
        }
        for (tag, value) in &tlvs {
            match *tag {
                TAG_AUTO_EJECT_TIMEOUT => {
                    if value.len() != 2 {
                        return Err(SW_WRONG_SYNTAX);
                    }
                }
                TAG_CHALRESP_TIMEOUT | TAG_DEVICE_FLAGS => {
                    if value.len() != 1 {
                        return Err(SW_WRONG_SYNTAX);
                    }
                }
                TAG_CONFIG_LOCK => {
                    if value.len() != LOCK_CODE_LEN {
                        return Err(SW_WRONG_SYNTAX);
                    }
                }
                TAG_REBOOT | TAG_UNLOCK | TAG_USB_ENABLED | TAG_NFC_ENABLED => {}
                _ => {} // tags futuras: ignoradas
            }
        }

        // Aplica na ordem do `DeviceConfig::get_bytes` (reboot/unlock sem efeito
        // persistente; capacidades, timeouts, flags e lock novo persistem).
        if let Some(value) = tlv_get(&tlvs, TAG_USB_ENABLED) {
            state.usb_enabled = u16::from_be_bytes([value[0], value[1]]);
        }
        if let Some(value) = tlv_get(&tlvs, TAG_NFC_ENABLED) {
            state.nfc_enabled = u16::from_be_bytes([value[0], value[1]]);
        }
        if let Some(value) = tlv_get(&tlvs, TAG_AUTO_EJECT_TIMEOUT) {
            state.auto_eject_timeout = u16::from_be_bytes([value[0], value[1]]);
        }
        if let Some(value) = tlv_get(&tlvs, TAG_CHALRESP_TIMEOUT) {
            state.chalresp_timeout = value[0];
        }
        if let Some(value) = tlv_get(&tlvs, TAG_DEVICE_FLAGS) {
            state.device_flags = value[0];
        }
        if let Some(value) = tlv_get(&tlvs, TAG_CONFIG_LOCK) {
            let mut code = [0u8; LOCK_CODE_LEN];
            code.copy_from_slice(value);
            if code == [0u8; LOCK_CODE_LEN] {
                state.lock_code = None; // all-zero remove o bloqueio
            } else {
                state.lock_code = Some(code);
            }
        }

        self.persist_state()?;
        Ok(ResponseData::ok(Vec::new()))
    }

    /// SET MODE legado (`0x16`, `P1 = 0x11`): traduz o código de modo
    /// (`_MODES` do yubikit, 3 bits baixos) em capacidades USB, com máscara
    /// em `SUPPORTED_CAPABILITIES`, e persiste timeouts. Na versão reportada
    /// (`5.4.0`) o host oficial prefere WRITE CONFIG; este caminho existe
    /// para compatibilidade com APDUs diretas e ferramentas antigas.
    fn cmd_set_mode(&mut self, p1: u8, data: &[u8]) -> Result<ResponseData, u16> {
        if p1 != P1_DEVICE_CONFIG {
            return Err(transport::iso7816::SW_WRONG_P1_P2);
        }
        if data.len() != 4 {
            return Err(transport::iso7816::SW_WRONG_LENGTH);
        }
        let code = data[0] & 0x07;
        let chalresp_timeout = data[1];
        let auto_eject_timeout = u16::from_le_bytes([data[2], data[3]]);

        // `_MODES = [OTP, CCID, OTP|CCID, FIDO, OTP|FIDO, FIDO|CCID, OTP|FIDO|CCID]`
        // com bits CAPABILITY do backend (OTP→0x01, CCID→OATH|PIV|OPENPGP|
        // HSMAUTH|0x400, FIDO→U2F|FIDO2). OTP/U2F/HSMAUTH caem na máscara de
        // suportados — o host oficial já faz esse overlay antes de enviar.
        const MODE_CAPS: [u16; 7] = [
            0x0001, // OTP
            0x0438, // CCID: OATH|PIV|OPENPGP|HSMAUTH|mgmt-CCID
            0x0439, // OTP|CCID
            0x0202, // FIDO: U2F|FIDO2
            0x0203, // OTP|FIDO
            0x063A, // FIDO|CCID
            0x063B, // OTP|FIDO|CCID
        ];
        let caps = MODE_CAPS[usize::from(code)] & SUPPORTED_CAPABILITIES;

        self.ensure_loaded()?;
        let state = self.state.as_mut().expect("loaded by ensure_loaded");
        state.usb_enabled = caps;
        state.chalresp_timeout = chalresp_timeout;
        state.auto_eject_timeout = auto_eject_timeout;
        self.persist_state()?;
        Ok(ResponseData::ok(Vec::new()))
    }
}

impl Applet for ManagementApplet<'_> {
    fn aid(&self) -> &[u8] {
        AID_YUBICO_MANAGEMENT
    }

    fn select(&mut self) -> Result<(), u16> {
        self.ensure_loaded()
    }

    /// String ASCII `"M.N.P"` — o backend smartcard do python-yubikit decodifica
    /// a resposta do SELECT com UTF-8 e extrai a versão por expressão regular
    /// (`Version.from_string`). Nenhum TLV aqui.
    fn select_response(&mut self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5);
        for (i, byte) in REPORTED_VERSION.iter().enumerate() {
            if i > 0 {
                out.push(b'.');
            }
            out.extend_from_slice(byte.to_string().as_bytes());
        }
        out
    }

    fn process(&mut self, apdu: &Apdu) -> Result<ResponseData, u16> {
        if apdu.cla != 0x00 {
            return Err(SW_CLASS_NOT_SUPPORTED);
        }
        match apdu.ins {
            INS_READ_CONFIG => self.cmd_read_config(apdu.p1),
            INS_WRITE_CONFIG => {
                if apdu.p1 != 0x00 || apdu.p2 != 0x00 {
                    return Err(transport::iso7816::SW_WRONG_P1_P2);
                }
                self.cmd_write_config(apdu.data)
            }
            INS_SET_MODE => self.cmd_set_mode(apdu.p1, apdu.data),
            // DEVICE RESET (0x1F, só YubiKey Bio) e qualquer outro INS:
            // não implementado.
            _ => Err(transport::iso7816::SW_INS_NOT_SUPPORTED),
        }
    }
}

/// Empacota um TLV de forma curta (valor <= 255 bytes) ao final de `out`.
fn push_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    assert!(value.len() <= 255, "TLV value exceeds short form");
    out.push(tag);
    out.push(value.len() as u8);
    out.extend_from_slice(value);
}

/// Busca o valor de uma tag no dicionário TLV (última ocorrência vence,
/// como no `Tlv.parse_dict` do yubikit).
fn tlv_get(tlvs: &[(u8, Vec<u8>)], tag: u8) -> Option<&Vec<u8>> {
    tlvs.iter().find(|(t, _)| *t == tag).map(|(_, v)| v)
}

/// Decodifica um payload de WRITE CONFIG (`DeviceConfig::get_bytes`):
/// `[len][TLVs…]` com o comprimento cobrindo exatamente os TLVs (mesma
/// regra que o parser do yubikit aplica no READ CONFIG). Comprimento
/// divergente dá `6700`; TLV truncado ou tag sem comprimento dá `6A80`.
/// Tags repetidas: vence a última (como no `Tlv.parse_dict` do yubikit).
fn parse_config_payload(data: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, u16> {
    use transport::iso7816::SW_WRONG_LENGTH;
    if data.is_empty() || data.len() - 1 != usize::from(data[0]) {
        return Err(SW_WRONG_LENGTH);
    }
    let mut out: Vec<(u8, Vec<u8>)> = Vec::new();
    let mut pos = 1usize;
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
        let value = data[pos + 2..end].to_vec();
        if let Some(slot) = out.iter_mut().find(|(t, _)| *t == tag) {
            slot.1 = value;
        } else {
            out.push((tag, value));
        }
        pos = end;
    }
    Ok(out)
}

// --- Integração ----------------------------------------------------------------------

/// Registra os applets Yubico ([`ManagementApplet`] + OATH) num roteador novo
/// ou existente, prontos para atender `ykman info` / Yubico Authenticator.
///
/// A ordem de registro define prioridade apenas entre prefixos ambíguos; os
/// AIDs completos são distintos, então a ordem é indiferente para hosts que
/// selecionam o AID completo (caso do python-yubikit).
pub fn register_yubico_applets<'a, 's>(
    router: &mut CardRouter<'a>,
    management: &'a mut ManagementApplet<'s>,
    oath: &'a mut crate::yubico_oath::OathApplet<'s>,
) {
    router.register(management);
    router.register(oath);
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::yubico_oath::OathApplet;
    use storage::FileStorageBackend;
    use transport::iso7816::{INS_GET_RESPONSE, INS_SELECT, SW_NO_ERROR};

    /// Chave-mestra fixa: permite recriar o applet sobre o mesmo arquivo,
    /// simulando um reinício do dispositivo com a mesma chave.
    const MASTER_KEY: [u8; 32] = [11u8; 32];

    fn make_applet(storage: &core::cell::RefCell<StorageEngine>) -> ManagementApplet<'_> {
        ManagementApplet::new(storage, CryptoEngine::from_key(MASTER_KEY)).unwrap()
    }

    fn open_persistent<'a>(
        storage: &'a core::cell::RefCell<StorageEngine>,
        path: &std::path::Path,
        master_key: [u8; 32],
    ) -> ManagementApplet<'a> {
        let backend = FileStorageBackend::new(path.to_path_buf()).unwrap();
        *storage.borrow_mut() = StorageEngine::with_backend(Box::new(backend));
        ManagementApplet::new(storage, CryptoEngine::from_key(master_key)).unwrap()
    }

    fn temp_root(tag: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("openkey-management-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    /// Processa um frame bruto com semântica de applet: `Err(sw)` vira
    /// resposta vazia com a Status Word correspondente.
    fn run(applet: &mut ManagementApplet, raw: &[u8]) -> ResponseData {
        let apdu = Apdu::parse(raw).unwrap();
        match applet.process(&apdu) {
            Ok(response) => response,
            Err(sw) => ResponseData::with_sw(Vec::new(), sw),
        }
    }

    /// READ CONFIG caso 2S com Le=0 (=256), formato do ShortApduFormatter do
    /// python-yubikit para comandos sem dados (`00 1D P1 00 00`).
    fn read_config_short(p1: u8) -> Vec<u8> {
        vec![0x00, INS_READ_CONFIG, p1, 0x00, 0x00]
    }

    /// READ CONFIG caso 1 (sem Lc/Le), exatamente o frame emitido pelo
    /// ExtendedApduFormatter do python-yubikit no USB para v >= 4.
    fn read_config_extended(p1: u8) -> Vec<u8> {
        vec![0x00, INS_READ_CONFIG, p1, 0x00]
    }

    /// Parser mínimo que replica a semântica do `DeviceInfo.parse_tlvs` do
    /// python-yubikit: prefixo de comprimento obrigatório, dicionário de
    /// TLVs de forma curta e TAG_USB_SUPPORTED obrigatório (indexação direta
    /// em `data[TAG_USB_SUPPORTED]` levantaria KeyError se ausente).
    fn parse_like_yubikit(encoded: &[u8]) -> Result<YubikitDeviceInfo, String> {
        if encoded.is_empty() || encoded.len() - 1 != usize::from(encoded[0]) {
            return Err("Invalid length".to_string());
        }
        let mut dict: Vec<(u8, Vec<u8>)> = Vec::new();
        let mut pos = 1usize;
        while pos < encoded.len() {
            if encoded.len() - pos < 2 {
                return Err("Invalid encoding of tag/length".to_string());
            }
            let tag = encoded[pos];
            let len = usize::from(encoded[pos + 1]);
            let end = pos + 2 + len;
            if end > encoded.len() {
                return Err("Truncated TLV".to_string());
            }
            dict.push((tag, encoded[pos + 2..end].to_vec()));
            pos = end;
        }
        let get = |tag: u8| dict.iter().find(|(t, _)| *t == tag).map(|(_, v)| v.clone());
        let usb_supported =
            get(TAG_USB_SUPPORTED).ok_or_else(|| "KeyError: TAG_USB_SUPPORTED".to_string())?;
        Ok(YubikitDeviceInfo {
            usb_supported: u16::from_be_bytes([usb_supported[0], usb_supported[1]]),
            serial: get(TAG_SERIAL).map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]])),
            usb_enabled: get(TAG_USB_ENABLED).map(|v| u16::from_be_bytes([v[0], v[1]])),
            form_factor: get(TAG_FORM_FACTOR).map(|v| v[0]).unwrap_or(0),
            version: get(TAG_VERSION).unwrap_or_else(|| REPORTED_VERSION.to_vec()),
            has_more_data: get(0x10).is_some(),
        })
    }

    /// Espelho dos campos relevantes do `DeviceInfo` do python-yubikit.
    struct YubikitDeviceInfo {
        usb_supported: u16,
        serial: Option<u32>,
        usb_enabled: Option<u16>,
        form_factor: u8,
        version: Vec<u8>,
        has_more_data: bool,
    }

    // --- SELECT ---------------------------------------------------------------------

    #[test]
    fn test_select_response_is_ascii_version_parsable_by_yubikit() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        applet.select().unwrap();
        let response = applet.select_response();

        // Regex `\b\d+.\d.\d\b`: três componentes numéricos separados por ponto.
        let text = core::str::from_utf8(&response).expect("SELECT deve ser ASCII");
        let parts: Vec<&str> = text.split('.').collect();
        assert_eq!(parts.len(), 3, "esperado M.N.P, obtido {text:?}");
        assert!(
            parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
            "componentes devem ser numéricos: {text:?}"
        );

        // Constraints reais do backend smartcard do python-yubikit:
        // major == 3 dispara workaround NEO e require_version((4,1,0)) falharia;
        // abaixo de (5,0,0) o TAG_USB_ENABLED passa a ser ignorado.
        let major: u32 = parts[0].parse().unwrap();
        let minor: u32 = parts[1].parse().unwrap();
        let patch: u32 = parts[2].parse().unwrap();
        assert!(
            (major, minor, patch) >= (4, 1, 0),
            "read_device_info exige >= 4.1.0"
        );
        assert!(
            (major, minor, patch) >= (5, 0, 0),
            "usb_enabled exige >= 5.0.0"
        );
        assert_eq!(response, b"5.4.0");
    }

    // --- READ CONFIG ----------------------------------------------------------------

    #[test]
    fn test_read_config_matches_yubikit_layout_byte_for_byte() {
        // Applet único: o serial vem do mesmo estado que responde ao comando.
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        let serial = applet.serial().expect("estado carregado no construtor");

        // Layout montado à mão a partir da semântica do python-yubikit:
        // [len][01 02 caps][02 04 serial][03 02 caps][04 01 ff][05 03 vvv].
        let mut expected = vec![22, TAG_USB_SUPPORTED, 0x02, 0x06, 0x2E, TAG_SERIAL, 0x04];
        expected.extend_from_slice(&serial.to_be_bytes());
        expected.extend_from_slice(&[
            TAG_USB_ENABLED,
            0x02,
            0x06,
            0x2E,
            TAG_FORM_FACTOR,
            0x01,
            FORM_FACTOR_CODE,
            TAG_VERSION,
            0x03,
            REPORTED_VERSION[0],
            REPORTED_VERSION[1],
            REPORTED_VERSION[2],
        ]);

        let response = run(&mut applet, &read_config_short(0));
        assert_eq!(response.sw, None);
        assert_eq!(response.data, expected, "resposta deve casar byte a byte");
    }

    #[test]
    fn test_device_info_fields_parse_like_python_yubikit() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        let response = run(&mut applet, &read_config_short(0));
        assert_eq!(response.sw, None);

        let info = parse_like_yubikit(&response.data).expect("parser do yubikit deve aceitar");
        // CAPABILITY: OATH | PIV | OpenPGP | FIDO2 | mgmt-CCID | CCID geral.
        assert_eq!(info.usb_supported, 0x062E);
        assert_eq!(info.usb_enabled, Some(0x062E));
        // USB interfaces computadas pelo yubikit devem incluir CCID.
        let ccid_mask = 0x0004u16 | 0x0400 | 0x0020;
        assert_ne!(
            info.usb_supported & ccid_mask,
            0,
            "interface CCID deve ser anunciada"
        );

        // Serial presente, estável e não nulo (0 viraria None no yubikit).
        let serial = info.serial.expect("serial deve estar presente");
        assert_ne!(serial, 0);

        // Form factor dentro da enum FORM_FACTOR (0x01 USB_A_KEYCHAIN),
        // sem flags FIPS (0x80) nem SKY (0x40) no nibble alto.
        assert_eq!(info.form_factor, 0x01);

        // Versão do TLV consistente com o SELECT.
        assert_eq!(info.version, REPORTED_VERSION.to_vec());

        // Sem TAG_MORE_DATA: paginação encerra após a página 0.
        assert!(!info.has_more_data);
    }

    #[test]
    fn test_serial_is_stable_across_restart() {
        let root = temp_root("stable-serial");
        let path = root.join("store.json");

        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let first = open_persistent(&storage, &path, MASTER_KEY);
        let serial = first.serial().expect("serial gerado no primeiro uso");

        drop(first);
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let second = open_persistent(&storage, &path, MASTER_KEY);
        assert_eq!(
            second.serial(),
            Some(serial),
            "serial deve sobreviver ao reinício"
        );
    }

    #[test]
    fn test_unreadable_state_regenerates_serial() {
        let root = temp_root("regenerated-serial");
        let path = root.join("store.json");

        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let first = open_persistent(&storage, &path, MASTER_KEY);
        let original = first.serial().expect("serial inicial");
        drop(first);

        // Chave-mestra trocada: blob cifrado torna-se ilegível.
        let other_key = [12u8; 32];
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let second = open_persistent(&storage, &path, other_key);
        let regenerated = second.serial().expect("identidade nova gerada");
        assert_ne!(
            regenerated, original,
            "blob ilegível deve regenerar o serial"
        );
    }

    // --- erros -----------------------------------------------------------------------

    #[test]
    fn test_unknown_ins_returns_ins_not_supported() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        // DEVICE RESET (0x1F, só YubiKey Bio) continua não implementado...
        assert_eq!(
            run(&mut applet, &[0x00, 0x1F, 0x00, 0x00]).sw,
            Some(transport::iso7816::SW_INS_NOT_SUPPORTED)
        );
        // ...e qualquer INS arbitrário.
        assert_eq!(
            run(&mut applet, &[0x00, 0x42, 0x00, 0x00]).sw,
            Some(transport::iso7816::SW_INS_NOT_SUPPORTED)
        );
    }

    #[test]
    fn test_nonzero_page_rejected_with_wrong_p1p2() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        let response = run(&mut applet, &read_config_short(1));
        assert_eq!(response.sw, Some(transport::iso7816::SW_WRONG_P1_P2));
    }

    #[test]
    fn test_wrong_cla_returns_class_not_supported() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        let raw = vec![0x80, INS_READ_CONFIG, 0x00, 0x00];
        assert_eq!(run(&mut applet, &raw).sw, Some(SW_CLASS_NOT_SUPPORTED));
    }

    // --- WRITE CONFIG / SET MODE --------------------------------------------------

    /// Monta um frame curto (`00 1C 00 00 Lc data`) como o `DeviceConfig`
    /// do yubikit: `data = [len][TLVs…]`.
    fn write_config_frame(entries: &[(u8, &[u8])]) -> Vec<u8> {
        let mut inner = Vec::new();
        for (tag, value) in entries {
            push_tlv(&mut inner, *tag, value);
        }
        let mut data = Vec::with_capacity(inner.len() + 1);
        data.push(inner.len() as u8);
        data.extend_from_slice(&inner);
        let mut frame = vec![0x00, INS_WRITE_CONFIG, 0x00, 0x00, data.len() as u8];
        frame.extend_from_slice(&data);
        frame
    }

    fn read_usb_enabled(applet: &mut ManagementApplet) -> u16 {
        let resp = run(applet, &read_config_short(0));
        assert_eq!(resp.sw, None);
        let info = parse_like_yubikit(&resp.data).expect("READ deve parsear");
        info.usb_enabled.expect("usb_enabled presente")
    }

    #[test]
    fn test_write_config_usb_subset_roundtrips_in_read_config() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        // Desliga o OpenPGP (0x08) mantendo o restante: subconjunto válido.
        let subset = SUPPORTED_CAPABILITIES & !0x08u16;
        let frame = write_config_frame(&[(TAG_USB_ENABLED, &subset.to_be_bytes())]);
        assert_eq!(run(&mut applet, &frame).sw, None);
        assert_eq!(read_usb_enabled(&mut applet), subset);
        // READ continua parseável pelo yubikit (layout + comprimento).
        let resp = run(&mut applet, &read_config_short(0));
        assert_eq!(usize::from(resp.data[0]), resp.data.len() - 1);
    }

    #[test]
    fn test_write_config_rejects_capabilities_outside_supported() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        // OTP (0x01) não está em SUPPORTED_CAPABILITIES.
        let bad = SUPPORTED_CAPABILITIES | 0x0001u16;
        let frame = write_config_frame(&[(TAG_USB_ENABLED, &bad.to_be_bytes())]);
        assert_eq!(run(&mut applet, &frame).sw, Some(SW_WRONG_SYNTAX));
        // Estado intocado.
        assert_eq!(read_usb_enabled(&mut applet), SUPPORTED_CAPABILITIES);
    }

    #[test]
    fn test_write_config_framing_errors() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        // Comprimento externo divergente → 6700.
        let mut inner = Vec::new();
        push_tlv(
            &mut inner,
            TAG_USB_ENABLED,
            &SUPPORTED_CAPABILITIES.to_be_bytes(),
        );
        let mut bad_len = vec![0x00, INS_WRITE_CONFIG, 0x00, 0x00, (inner.len() + 1) as u8];
        bad_len.push((inner.len() + 9) as u8);
        bad_len.extend_from_slice(&inner);
        assert_eq!(
            run(&mut applet, &bad_len).sw,
            Some(transport::iso7816::SW_WRONG_LENGTH)
        );
        // TLV truncado → 6A80.
        let truncated = vec![0x00, INS_WRITE_CONFIG, 0x00, 0x00, 0x03, 0x02, 0x03, 0x02];
        assert_eq!(run(&mut applet, &truncated).sw, Some(SW_WRONG_SYNTAX));
        // usb_enabled com 1 byte → 6A80.
        let frame = write_config_frame(&[(TAG_USB_ENABLED, &[0x06])]);
        assert_eq!(run(&mut applet, &frame).sw, Some(SW_WRONG_SYNTAX));
        // P1/P2 != 0 → 6B00.
        let mut frame =
            write_config_frame(&[(TAG_USB_ENABLED, &SUPPORTED_CAPABILITIES.to_be_bytes())]);
        frame[2] = 0x01;
        assert_eq!(
            run(&mut applet, &frame).sw,
            Some(transport::iso7816::SW_WRONG_P1_P2)
        );
    }

    #[test]
    fn test_set_mode_legacy_maps_code_and_persists_timeouts() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        // Código 6 = OTP+FIDO+CCID, com timeouts; P1_DEVICE_CONFIG exigido.
        let frame = vec![
            0x00,
            INS_SET_MODE,
            P1_DEVICE_CONFIG,
            0x00,
            0x04,
            0x06,
            0x05,
            0x10,
            0x00,
        ];
        assert_eq!(run(&mut applet, &frame).sw, None);
        assert_eq!(read_usb_enabled(&mut applet), 0x062Au16);
        let resp = run(&mut applet, &read_config_short(0));
        let info = parse_like_yubikit(&resp.data).expect("READ deve parsear");
        assert_eq!(info.usb_enabled, Some(0x062Au16));
        // P1 errado → 6B00; dados curtos → 6700 (roteador).
        assert_eq!(
            run(
                &mut applet,
                &[0x00, INS_SET_MODE, 0x00, 0x00, 0x04, 0x06, 0x00, 0x00, 0x00]
            )
            .sw,
            Some(transport::iso7816::SW_WRONG_P1_P2)
        );
    }

    #[test]
    fn test_config_lock_flow() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        let lock = [0xA5u8; LOCK_CODE_LEN];
        let wrong = [0x5Au8; LOCK_CODE_LEN];
        let subset = SUPPORTED_CAPABILITIES & !0x08u16;

        // Define o bloqueio.
        let frame = write_config_frame(&[(TAG_CONFIG_LOCK, &lock)]);
        assert_eq!(run(&mut applet, &frame).sw, None);

        // Unlock errado bloqueia a escrita (6982) sem mutar estado.
        let frame = write_config_frame(&[
            (TAG_UNLOCK, &wrong),
            (TAG_USB_ENABLED, &subset.to_be_bytes()),
        ]);
        assert_eq!(
            run(&mut applet, &frame).sw,
            Some(transport::iso7816::SW_SECURITY_STATUS)
        );
        assert_eq!(read_usb_enabled(&mut applet), SUPPORTED_CAPABILITIES);

        // Unlock correto aplica.
        let frame = write_config_frame(&[
            (TAG_UNLOCK, &lock),
            (TAG_USB_ENABLED, &subset.to_be_bytes()),
        ]);
        assert_eq!(run(&mut applet, &frame).sw, None);
        assert_eq!(read_usb_enabled(&mut applet), subset);

        // All-zero com unlock correto remove o bloqueio: escrita aberta volta.
        let frame = write_config_frame(&[
            (TAG_UNLOCK, &lock),
            (TAG_CONFIG_LOCK, &[0u8; LOCK_CODE_LEN]),
        ]);
        assert_eq!(run(&mut applet, &frame).sw, None);
        let frame = write_config_frame(&[(TAG_USB_ENABLED, &SUPPORTED_CAPABILITIES.to_be_bytes())]);
        assert_eq!(run(&mut applet, &frame).sw, None);
        assert_eq!(read_usb_enabled(&mut applet), SUPPORTED_CAPABILITIES);
    }

    #[test]
    fn test_write_config_persists_across_restart_with_stable_serial() {
        let root = temp_root("mgmt-write-persist");
        let path = root.join("store.json");
        let subset = SUPPORTED_CAPABILITIES & !0x08u16;

        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut first = open_persistent(&storage, &path, MASTER_KEY);
        let serial = first.serial().expect("serial gerado");
        let frame = write_config_frame(&[(TAG_USB_ENABLED, &subset.to_be_bytes())]);
        assert_eq!(run(&mut first, &frame).sw, None);
        drop(first);

        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut second = open_persistent(&storage, &path, MASTER_KEY);
        assert_eq!(second.serial(), Some(serial), "serial estável");
        let resp = run(&mut second, &read_config_short(0));
        let info = parse_like_yubikit(&resp.data).expect("READ deve parsear");
        assert_eq!(info.usb_enabled, Some(subset), "usb_enabled sobrevive");
    }

    #[test]
    fn test_v1_state_migrates_preserving_serial() {
        // Blob v1 = [0x01][serial 4]: migrate deve adotar defaults e aceitar
        // escrita em seguida.
        let serial = 0x12345678u32;
        let mut blob = vec![STATE_FORMAT_VERSION_V1];
        blob.extend_from_slice(&serial.to_be_bytes());
        assert!(parse_state(&blob).is_some());
        let migrated = parse_state(&blob).unwrap();
        assert_eq!(migrated.serial, serial);
        assert_eq!(migrated.usb_enabled, SUPPORTED_CAPABILITIES);
        assert!(migrated.lock_code.is_none());
    }

    #[test]
    fn test_read_config_echoes_timeouts_flags_and_nfc_when_set() {
        let storage = core::cell::RefCell::new(StorageEngine::new().unwrap());
        let mut applet = make_applet(&storage);
        let frame = write_config_frame(&[
            (TAG_AUTO_EJECT_TIMEOUT, &0x001Eu16.to_be_bytes()),
            (TAG_CHALRESP_TIMEOUT, &[0x0A]),
            (TAG_DEVICE_FLAGS, &[0x40]),
            (TAG_NFC_ENABLED, &0x0020u16.to_be_bytes()),
        ]);
        assert_eq!(run(&mut applet, &frame).sw, None);
        let resp = run(&mut applet, &read_config_short(0));
        let info = parse_like_yubikit(&resp.data).expect("READ deve parsear");
        // Layout continua válido e usb_enabled intocado.
        assert_eq!(info.usb_enabled, Some(SUPPORTED_CAPABILITIES));
        assert_eq!(usize::from(resp.data[0]), resp.data.len() - 1);
        // TLVs condicionais presentes no payload bruto.
        let has = |tag: u8| {
            let mut pos = 1usize;
            while pos + 1 < resp.data.len() {
                let t = resp.data[pos];
                let l = usize::from(resp.data[pos + 1]);
                if t == tag {
                    return true;
                }
                pos += 2 + l;
            }
            false
        };
        assert!(has(TAG_AUTO_EJECT_TIMEOUT));
        assert!(has(TAG_CHALRESP_TIMEOUT));
        assert!(has(TAG_DEVICE_FLAGS));
        assert!(has(TAG_NFC_ENABLED));
    }

    // --- integração com o roteador ----------------------------------------------------

    #[test]
    fn test_router_extended_style_read_config_drains_via_get_response() {
        // Storage e applets são vazados: o roteador exige 'static. Os dois
        // applets compartilham a MESMA instância de storage (mesma identidade).
        let storage: &'static core::cell::RefCell<StorageEngine> = Box::leak(Box::new(
            core::cell::RefCell::new(StorageEngine::new().unwrap()),
        ));
        let management = Box::leak(Box::new(
            ManagementApplet::new(storage, CryptoEngine::from_key(MASTER_KEY)).unwrap(),
        ));
        let oath = Box::leak(Box::new(
            OathApplet::new(storage, CryptoEngine::from_key(MASTER_KEY)).unwrap(),
        ));

        let mut router = CardRouter::new();
        register_yubico_applets(&mut router, management, oath);

        // SELECT AID Management: string ASCII da versão + 9000.
        let mut select_frame = vec![
            0x00,
            INS_SELECT,
            0x04,
            0x00,
            AID_YUBICO_MANAGEMENT.len() as u8,
        ];
        select_frame.extend_from_slice(AID_YUBICO_MANAGEMENT);
        let resp = router.process(&select_frame);
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        assert_eq!(resp.data, b"5.4.0");

        // Frame estilo ExtendedApduFormatter (caso 1, sem Lc/Le): nada sai
        // inline e a resposta completa (1 + 22 = 23 bytes) vai para o
        // encadeamento `61 XX`.
        let resp = router.process(&read_config_extended(0));
        assert!(resp.data.is_empty());
        assert_eq!(resp.sw, Some(transport::iso7816::sw_more_data(23)));

        // Host busca o restante com GET RESPONSE (também sem Le na forma
        // estendida): payload completo + 9000.
        let resp = router.process(&vec![0x00, INS_GET_RESPONSE, 0x00, 0x00][..]);
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        let parsed = parse_like_yubikit(&resp.data).expect("payload encadeado deve parsear");
        assert_eq!(parsed.usb_supported, 0x062E);
    }

    #[test]
    fn test_router_short_form_read_config_inline_and_oath_coexistence() {
        // Storage e applets são vazados: o roteador exige 'static. Os dois
        // applets compartilham a MESMA instância de storage (mesma identidade).
        let storage: &'static core::cell::RefCell<StorageEngine> = Box::leak(Box::new(
            core::cell::RefCell::new(StorageEngine::new().unwrap()),
        ));
        let management = Box::leak(Box::new(
            ManagementApplet::new(storage, CryptoEngine::from_key(MASTER_KEY)).unwrap(),
        ));
        let oath = Box::leak(Box::new(
            OathApplet::new(storage, CryptoEngine::from_key(MASTER_KEY)).unwrap(),
        ));

        let mut router = CardRouter::new();
        register_yubico_applets(&mut router, management, oath);

        // Caso 2S com Le=0 (=256): resposta completa inline.
        let _ = router.process(&{
            let mut f = vec![
                0x00,
                INS_SELECT,
                0x04,
                0x00,
                AID_YUBICO_MANAGEMENT.len() as u8,
            ];
            f.extend_from_slice(AID_YUBICO_MANAGEMENT);
            f
        });
        let resp = router.process(&read_config_short(0));
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        assert_eq!(usize::from(resp.data[0]), resp.data.len() - 1);

        // Reseleção do OATH continua funcionando no mesmo roteador.
        let mut oath_select = vec![
            0x00,
            INS_SELECT,
            0x04,
            0x00,
            crate::yubico_oath::AID_YUBICO_OATH.len() as u8,
        ];
        oath_select.extend_from_slice(crate::yubico_oath::AID_YUBICO_OATH);
        let resp = router.process(&oath_select);
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        // OATH abre o SELECT com a TLV de versão (tag 0x79 do YKOATH).
        assert_eq!(resp.data[0], 0x79);
    }
}
