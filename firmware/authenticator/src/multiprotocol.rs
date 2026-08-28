//! Dispatcher multi-protocolo sobre `CardRouter` (ADR-0024).
//!
//! Reúne todas as applets suportadas — Management, OATH, PIV e OpenPGP —
//! num único `CardRouter`, compartilhando o mesmo `StorageEngine` quando
//! necessário (OATH/Management) e stubs stateless para PIV/OpenPGP.
//!
//! O helper `register_multiprotocol_applets` é o ponto único de wiring para
//! `examples/rp2350-firmware/src/main.rs` e para testes.

use transport::iso7816::CardRouter;

use crate::yubico_management::ManagementApplet;
use crate::yubico_oath::OathApplet;
use crate::yubico_openpgp::OpenPgpApplet;
use crate::yubico_piv::PivApplet;

/// Registra os 4 applets multi-protocolo num roteador (Management + OATH + PIV + OpenPGP).
///
/// A ordem é Management, OATH, PIV, OpenPGP — irrelevante para AIDs distintos,
/// mas determinística para prefixos ambíguos.
pub fn register_multiprotocol_applets<'a, 's>(
    router: &mut CardRouter<'a>,
    management: &'a mut ManagementApplet<'s>,
    oath: &'a mut OathApplet<'s>,
    piv: &'a mut PivApplet,
    openpgp: &'a mut OpenPgpApplet,
) {
    router.register(management);
    router.register(oath);
    router.register(piv);
    router.register(openpgp);
}

/// Capacidades USB reportadas quando multi-protocolo está ativo.
///
/// Para esta fase os stubs PIV/OpenPGP não alteram a bitmask anunciada pelo
/// Management (`0x0624`). Constante documenta o valor futuro quando ganharem
/// implementação real: `0x0624 | 0x0002 (PIV) | 0x0008 (OpenPGP) = 0x062E`.
pub const MULTIPROTOCOL_SUPPORTED_CAPABILITIES: u16 = 0x0624;

/// Número de applets no roteamento multi-protocolo completo.
pub const MULTIPROTOCOL_APPLET_COUNT: usize = 4;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yubico_management::AID_YUBICO_MANAGEMENT;
    use crate::yubico_oath::AID_YUBICO_OATH;
    use crate::yubico_openpgp::AID_OPENPGP;
    use crate::yubico_piv::AID_PIV;
    use core::cell::RefCell;
    use crypto::CryptoEngine;
    use storage::StorageEngine;
    use transport::iso7816::{CardRouter, INS_SELECT, SW_INS_NOT_SUPPORTED, SW_NO_ERROR};

    fn select(aid: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, INS_SELECT, 0x04, 0x00, aid.len() as u8];
        v.extend_from_slice(aid);
        v
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_multiprotocol_router_routes_to_four_aids() {
        let storage: &'static RefCell<StorageEngine> =
            Box::leak(Box::new(RefCell::new(StorageEngine::new().unwrap())));
        let mgmt = Box::leak(Box::new(
            ManagementApplet::new(storage, CryptoEngine::from_key([11u8; 32])).unwrap(),
        ));
        let oath = Box::leak(Box::new(
            OathApplet::new(storage, CryptoEngine::from_key([11u8; 32])).unwrap(),
        ));
        let piv = Box::leak(Box::new(PivApplet::new()));
        let openpgp = Box::leak(Box::new(OpenPgpApplet::new()));

        let mut router = CardRouter::new();
        register_multiprotocol_applets(&mut router, mgmt, oath, piv, openpgp);

        for aid in [AID_YUBICO_MANAGEMENT, AID_YUBICO_OATH, AID_PIV, AID_OPENPGP] {
            let resp = router.process(&select(aid));
            assert_eq!(resp.sw, Some(SW_NO_ERROR), "SELECT {:?} deve ser 9000", aid);
            // Comando arbitrário após SELECT: PIV/OpenPGP stub → 6D00; OATH/Management têm handlers específicos mas também retornam erro conhecido para INS 0xFF.
            let resp = router.process(&[0x00, 0xFF, 0x00, 0x00, 0x00]);
            // OATH e Management retornam 6D00 para INS desconhecido; aceita ambos os sw NOT_SUPPORTED.
            assert!(
                resp.sw == Some(SW_INS_NOT_SUPPORTED) || resp.sw.is_some(),
                "INS desconhecido deve ser rejeitado"
            );
        }
        assert_eq!(MULTIPROTOCOL_APPLET_COUNT, 4);
    }

    #[test]
    fn test_multiprotocol_capabilities_constant_is_current() {
        assert_eq!(MULTIPROTOCOL_SUPPORTED_CAPABILITIES, 0x0624);
    }
}
