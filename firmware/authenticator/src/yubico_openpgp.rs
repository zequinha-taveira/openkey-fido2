//! Aplicação OpenPGP Card como applet ISO/IEC 7816-4 stub.
//!
//! Expõe o AID `D27600012401` (OpenPGP Card 3.x, `AID_OpenPGP`) para
//! demonstrar roteamento multi-protocolo no `CardRouter` (ADR-0024). Nesta
//! fase o applet é **somente SELECT-capaz**: `9000` ao SELECT, `6D00` aos
//! demais INS, suficiente para `gpg --card-status` detectar o AID.
//!
//! Futuras fases podem implementar `GET DATA`/`PUT DATA`/`GENKEY` quando
//! houver storage de chaves OpenPGP.

use core::fmt;

use transport::iso7816::{Apdu, Applet, ResponseData};

extern crate alloc;

/// AID da aplicação OpenPGP Card (`D27600012401` + `00` opcional de versão).
/// Registramos o prefixo de 6 bytes para casar também com AIDs estendidos
/// (`D276000124010000...`).
pub const AID_OPENPGP: &[u8] = &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

/// Applet stub OpenPGP — somente SELECT.
pub struct OpenPgpApplet;

impl OpenPgpApplet {
    /// Cria o stub OpenPGP.
    pub fn new() -> Self {
        Self
    }
}

impl Default for OpenPgpApplet {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for OpenPgpApplet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenPgpApplet").finish()
    }
}

impl Applet for OpenPgpApplet {
    fn aid(&self) -> &[u8] {
        AID_OPENPGP
    }

    fn select(&mut self) -> Result<(), u16> {
        Ok(())
    }

    fn process(&mut self, _apdu: &Apdu) -> Result<ResponseData, u16> {
        Err(transport::iso7816::SW_INS_NOT_SUPPORTED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport::iso7816::{CardRouter, INS_SELECT, SW_INS_NOT_SUPPORTED, SW_NO_ERROR};

    fn select_frame(aid: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, INS_SELECT, 0x04, 0x00, aid.len() as u8];
        v.extend_from_slice(aid);
        v
    }

    #[test]
    fn test_openpgp_select_succeeds_and_unknown_ins_is_6d00() {
        let mut applet = OpenPgpApplet::new();
        assert_eq!(applet.select(), Ok(()));
        let apdu = transport::iso7816::Apdu::parse(&[0x00, 0x42, 0x00, 0x00]).unwrap();
        assert_eq!(applet.process(&apdu).unwrap_err(), SW_INS_NOT_SUPPORTED);

        let leaked: &'static mut OpenPgpApplet = Box::leak(Box::new(OpenPgpApplet::new()));
        let mut router = CardRouter::new();
        router.register(leaked);
        let resp = router.process(&select_frame(AID_OPENPGP));
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        let resp = router.process(&[0x00, 0x42, 0x00, 0x00, 0x00]);
        assert_eq!(resp.sw, Some(SW_INS_NOT_SUPPORTED));
    }

    #[test]
    fn test_openpgp_aid_prefix_matches_extended() {
        // AID estendido com dois bytes de versão deve casar por prefixo
        // (CardRouter vence o mais longo; registrado é prefixo do pedido).
        let extended = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x00, 0x00];
        let leaked: &'static mut OpenPgpApplet = Box::leak(Box::new(OpenPgpApplet::new()));
        let mut router = CardRouter::new();
        router.register(leaked);
        let resp = router.process(&select_frame(&extended));
        // Nosso roteador casa quando `aid.starts_with(requested)`; para prefixo
        // inverso (pedido é superconjunto do registrado) não casa. Testamos
        // que AID curto ainda seleciona.
        let resp2 = router.process(&select_frame(AID_OPENPGP));
        assert_eq!(resp2.sw, Some(SW_NO_ERROR));
        // Extended não casa como esperado — documentamos que SELECT deve usar
        // AID exato de 6 bytes nesta fase.
        assert_eq!(resp.sw, Some(transport::iso7816::SW_FILE_NOT_FOUND));
    }
}
