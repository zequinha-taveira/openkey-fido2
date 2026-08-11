use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use ciborium::value::Integer;
use ciborium::Value;
use crypto::CryptoEngine;

extern crate alloc;

use crate::ctap2::Ctap2Error;

/// Attestation formats supported by CTAP2 (§6.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationFormat {
    /// Sem attestation — `attStmt` vazio.
    None,
    /// Formato `packed`, com ou sem cadeia x5c.
    Packed,
    /// Self-attestation com a chave da própria credencial.
    Self_,
    /// Formato legado U2F.
    U2F,
    /// Attestation do Android Keystore.
    AndroidKey,
    /// Attestation da Apple.
    Apple,
}

impl AttestationFormat {
    /// Wire identifier used in the `fmt` field of MakeCredential responses.
    pub fn as_str(&self) -> &str {
        match self {
            AttestationFormat::None => "none",
            AttestationFormat::Packed => "packed",
            AttestationFormat::Self_ => "self",
            AttestationFormat::U2F => "u2f",
            AttestationFormat::AndroidKey => "android-key",
            AttestationFormat::Apple => "apple",
        }
    }
}

/// X.509 attestation certificate and its private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationCertificate {
    /// Certificado X.509 em DER, publicado no campo `x5c`.
    pub cert: Vec<u8>,
    /// Chave privada correspondente, usada para assinar o `attStmt`.
    pub private_key: Vec<u8>,
}

/// Packed attestation statement (CTAP2 §6.3.3.1).
///
/// Produces `attStmt = { alg: int, sig: bytes, x5c: [bytes] }` when a certificate
/// is available, or `attStmt = { alg: int, sig: bytes, ecdaaKeyId: bytes }` for
/// ECDAA. Self-attested variant (no x5c) signs with the credential's own key.
pub struct PackedAttestation<'a> {
    /// Algoritmo COSE da assinatura (-7 ES256, -8 EdDSA).
    pub algorithm: i32,
    /// Certificado do lote; `None` produz a variante self-attested.
    pub certificate: Option<&'a AttestationCertificate>,
}

impl<'a> PackedAttestation<'a> {
    /// Configura o gerador de attestation `packed`.
    pub fn new(algorithm: i32, certificate: Option<&'a AttestationCertificate>) -> Self {
        Self {
            algorithm,
            certificate,
        }
    }

    /// Generate the Packed attestation statement.
    ///
    /// `data_to_sign` = `authData || clientDataHash` (CTAP2 §6.3.3.1, step 4).
    pub fn generate(
        &self,
        data_to_sign: &[u8],
        credential_key: Option<&[u8]>,
        crypto: &CryptoEngine,
    ) -> Result<BTreeMap<i64, Value>, Ctap2Error> {
        let signature = match self.certificate {
            Some(cert) => {
                if self.algorithm == -7 {
                    crypto.sign_p256(&cert.private_key, data_to_sign)
                } else {
                    crypto.sign(data_to_sign, &cert.private_key)
                }
            }
            None => {
                let cred_key = credential_key.ok_or(Ctap2Error::InvalidParameter)?;
                if self.algorithm == -7 {
                    crypto.sign_p256(cred_key, data_to_sign)
                } else {
                    crypto.sign(data_to_sign, cred_key)
                }
            }
        }
        .map_err(|_| Ctap2Error::InvalidData)?;

        let mut att_stmt: BTreeMap<i64, Value> = BTreeMap::new();
        att_stmt.insert(3, Value::Integer(Integer::from(self.algorithm)));
        att_stmt.insert(2, Value::Bytes(signature));

        if let Some(cert) = self.certificate {
            let x5c = vec![cert.cert.clone()];
            att_stmt.insert(1, Value::Array(x5c.into_iter().map(Value::Bytes).collect()));
        }

        Ok(att_stmt)
    }
}

/// Self attestation (CTAP2 §6.3.3.2).
///
/// Signs with the credential's own private key.
/// `attStmt = { alg: int, sig: bytes }`.
pub struct SelfAttestation;

impl SelfAttestation {
    /// Gera o `attStmt` assinando `data_to_sign` com a chave da credencial.
    ///
    /// `data_to_sign` = `authData || clientDataHash`.
    pub fn generate(
        data_to_sign: &[u8],
        credential_key: &[u8],
        algorithm: i32,
        crypto: &CryptoEngine,
    ) -> Result<BTreeMap<i64, Value>, Ctap2Error> {
        let signature = if algorithm == -7 {
            crypto.sign_p256(credential_key, data_to_sign)
        } else {
            crypto.sign(data_to_sign, credential_key)
        }
        .map_err(|_| Ctap2Error::InvalidData)?;

        let mut att_stmt: BTreeMap<i64, Value> = BTreeMap::new();
        att_stmt.insert(3, Value::Integer(Integer::from(algorithm)));
        att_stmt.insert(2, Value::Bytes(signature));

        Ok(att_stmt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_format_as_str() {
        assert_eq!(AttestationFormat::None.as_str(), "none");
        assert_eq!(AttestationFormat::Packed.as_str(), "packed");
        assert_eq!(AttestationFormat::Self_.as_str(), "self");
        assert_eq!(AttestationFormat::U2F.as_str(), "u2f");
        assert_eq!(AttestationFormat::AndroidKey.as_str(), "android-key");
        assert_eq!(AttestationFormat::Apple.as_str(), "apple");
    }

    #[test]
    fn test_self_attestation_generate() {
        let crypto = CryptoEngine::new().unwrap();
        let (private_key, _) = crypto.generate_key_pair().unwrap();
        let data = b"test data to sign";

        let att_stmt = SelfAttestation::generate(data, &private_key, -8, &crypto).unwrap();

        assert!(att_stmt.contains_key(&3));
        assert!(att_stmt.contains_key(&2));
        assert_eq!(att_stmt[&3], Value::Integer(Integer::from(-8)));
    }

    #[test]
    fn test_packed_attestation_self_attested() {
        let crypto = CryptoEngine::new().unwrap();
        let (private_key, _) = crypto.generate_key_pair().unwrap();
        let data = b"test data to sign";

        let packed = PackedAttestation::new(-8, None);
        let att_stmt = packed.generate(data, Some(&private_key), &crypto).unwrap();

        assert!(att_stmt.contains_key(&3));
        assert!(att_stmt.contains_key(&2));
        assert!(!att_stmt.contains_key(&1));
    }

    #[test]
    fn test_packed_attestation_with_cert() {
        let crypto = CryptoEngine::new().unwrap();
        let (cert_private_key, _) = crypto.generate_key_pair().unwrap();
        let cert = AttestationCertificate {
            cert: vec![0x30, 0x82, 0x01, 0x00],
            private_key: cert_private_key,
        };

        let data = b"test data to sign";
        let packed = PackedAttestation::new(-8, Some(&cert));
        let att_stmt = packed.generate(data, None, &crypto).unwrap();

        assert!(att_stmt.contains_key(&3));
        assert!(att_stmt.contains_key(&2));
        assert!(att_stmt.contains_key(&1));
    }
}
