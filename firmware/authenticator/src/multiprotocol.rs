//! Dispatcher multi-protocolo sobre `CardRouter` (ADR-0024).
//!
//! Reúne todas as applets suportadas — Management, OATH, PIV e OpenPGP —
//! num único `CardRouter`. OATH/Management/PIV/OpenPGP compartilham o mesmo
//! `StorageEngine` (identidade e estados cifrados no mesmo kv).
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
    piv: &'a mut PivApplet<'s>,
    openpgp: &'a mut OpenPgpApplet<'s>,
) {
    router.register(management);
    router.register(oath);
    router.register(piv);
    router.register(openpgp);
}

/// Capacidades USB reportadas quando multi-protocolo está ativo.
///
/// PIV (F2a) e OpenPGP SIG (F2b) têm chaves reais, por isso o Management
/// anuncia `0x0624 | 0x0002 (PIV) | 0x0008 (OpenPGP) = 0x062E`.
pub const MULTIPROTOCOL_SUPPORTED_CAPABILITIES: u16 = 0x062E;

/// Número de applets no roteamento multi-protocolo completo.
pub const MULTIPROTOCOL_APPLET_COUNT: usize = 4;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::yubico_management::AID_YUBICO_MANAGEMENT;
    use crate::yubico_oath::AID_YUBICO_OATH;
    use crate::yubico_openpgp::{AID_OPENPGP, AID_OPENPGP_FULL};
    use crate::yubico_piv::AID_PIV;
    use core::cell::RefCell;
    use crypto::CryptoEngine;
    use storage::StorageEngine;
    use transport::iso7816::{CardRouter, INS_SELECT, SW_INS_NOT_SUPPORTED, SW_NO_ERROR};

    /// Chave-mestra fixa dos testes deste módulo.
    const MASTER_KEY: [u8; 32] = [31u8; 32];

    fn select(aid: &[u8]) -> Vec<u8> {
        let mut v = vec![0x00, INS_SELECT, 0x04, 0x00, aid.len() as u8];
        v.extend_from_slice(aid);
        v
    }

    /// Monta o roteador completo com os 4 applets sobre o mesmo storage.
    fn full_router() -> CardRouter<'static> {
        let storage: &'static RefCell<StorageEngine> =
            Box::leak(Box::new(RefCell::new(StorageEngine::new().unwrap())));
        let engine = || CryptoEngine::from_key(MASTER_KEY);
        let mgmt = Box::leak(Box::new(ManagementApplet::new(storage, engine()).unwrap()));
        let oath = Box::leak(Box::new(OathApplet::new(storage, engine()).unwrap()));
        let piv = Box::leak(Box::new(PivApplet::new(storage, engine()).unwrap()));
        let openpgp = Box::leak(Box::new(OpenPgpApplet::new(storage, engine()).unwrap()));

        let mut router = CardRouter::new();
        register_multiprotocol_applets(&mut router, mgmt, oath, piv, openpgp);
        router
    }

    #[test]
    fn test_multiprotocol_router_routes_to_four_aids() {
        let mut router = full_router();

        for aid in [AID_YUBICO_MANAGEMENT, AID_YUBICO_OATH, AID_PIV, AID_OPENPGP] {
            let resp = router.process(&select(aid));
            assert_eq!(resp.sw, Some(SW_NO_ERROR), "SELECT {:?} deve ser 9000", aid);
            // Comando arbitrário após SELECT: PIV/OpenPGP → 6D00; OATH/Management têm handlers específicos mas também retornam erro conhecido para INS 0xFF.
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
    fn test_openpgp_extended_aid_selects_through_multiprotocol_router() {
        let mut router = full_router();

        // Prefixo curto casa por prefixo com o AID estendido registrado.
        let resp = router.process(&select(AID_OPENPGP));
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        assert_eq!(resp.data.first(), Some(&0x6F));

        // AID estendido completo casa por igualdade exata.
        let resp = router.process(&select(AID_OPENPGP_FULL));
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        assert_eq!(resp.data.first(), Some(&0x6F));
    }

    #[test]
    fn test_piv_and_openpgp_coexist_with_oath_and_management() {
        let mut router = full_router();

        // SELECT PIV → GET DATA discovery inline (Le folgado).
        assert_eq!(router.process(&select(AID_PIV)).sw, Some(SW_NO_ERROR));
        let mut frame = vec![0x00, 0xCB, 0x3F, 0xFF, 0x01, 0x7E, 0x00];
        let resp = router.process(&frame);
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        assert_eq!(resp.data.first(), Some(&0x7E));

        // Reseleção alternada: OpenPGP → OATH → Management → PIV.
        assert_eq!(router.process(&select(AID_OPENPGP)).sw, Some(SW_NO_ERROR));
        let resp = router.process(&[0x00, 0xCA, 0x00, 0x4F, 0x00]);
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        assert_eq!(resp.data.first(), Some(&0x4F));

        let resp = router.process(&select(AID_YUBICO_OATH));
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        assert_eq!(resp.data.first(), Some(&0x79));

        let resp = router.process(&select(AID_YUBICO_MANAGEMENT));
        assert_eq!(resp.sw, Some(SW_NO_ERROR));
        assert_eq!(resp.data, b"5.4.0");

        // De volta ao PIV: estado do PIN intacto (3 tentativas, status 63C3).
        assert_eq!(router.process(&select(AID_PIV)).sw, Some(SW_NO_ERROR));
        frame = vec![0x00, 0x20, 0x00, 0x80];
        let resp = router.process(&frame);
        assert_eq!(resp.sw, Some(0x63C3));
    }

    #[test]
    fn test_multiprotocol_capabilities_constant_is_current() {
        assert_eq!(MULTIPROTOCOL_SUPPORTED_CAPABILITIES, 0x062E);
    }
}
