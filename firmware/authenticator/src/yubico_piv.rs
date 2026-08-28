//! Aplicação PIV (Personal Identity Verification) como applet ISO/IEC 7816-4 stub.
//!
//! Expõe o AID `A000000308000010000100` (NIST SP 800-73 PIV Card Application)
//! para demonstrar roteamento multi-protocolo no `CardRouter`. Nesta fase o
//! applet é **somente SELECT-capaz**: responde `9000` ao SELECT e `6D00` a
//! qualquer outro INS, suficiente para `ykman`/`yubico` detectarem o AID sem
//! travar (multi-protocolo ADR-0024).
//!
//! Futuras fases podem implementar `GET DATA`/`VERIFY`/`GENERATE ASYMMETRIC`
//! quando houver storage de chaves PIV.

use core::fmt;

use transport::iso7816::{Apdu, Applet, ResponseData};

extern crate alloc;

/// AID da aplicação PIV (NIST SP 800-73).
pub const AID_PIV: &[u8] = &[
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];

/// Applet stub PIV — somente SELECT.
pub struct PivApplet;

impl PivApplet {
    /// Cria o stub PIV.
    pub fn new() -> Self {
        Self
    }
}

impl Default for PivApplet {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PivApplet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PivApplet").finish()
    }
}

impl Applet for PivApplet {
    fn aid(&self) -> &[u8] {
        AID_PIV
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
    fn test_piv_select_succeeds_and_unknown_ins_is_6d00() {
        let mut applet = PivApplet::new();
        // SELECT via Applet diretamente.
        assert_eq!(applet.select(), Ok(()));
        // INS arbitrário → 6D00.
        let apdu = transport::iso7816::Apdu::parse(&[0x00, 0x42, 0x00, 0x00]).unwrap();
        assert_eq!(applet.process(&apdu).unwrap_err(), SW_INS_NOT_SUPPORTED);

        // Via CardRouter.
        let leaked: &'static mut PivApplet = Box::leak(Box::new(PivApplet::new()));
        let mut router = CardRouter::new();
        router.register(leaked);
        let resp = router.process(&select_frame(AID_PIV));
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        let resp = router.process(&[0x00, 0x42, 0x00, 0x00, 0x00]);
        assert_eq!(resp.sw, Some(SW_INS_NOT_SUPPORTED));
    }

    #[test]
    fn test_piv_aid_is_correct() {
        assert_eq!(
            AID_PIV,
            &[0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00]
        );
    }
}
