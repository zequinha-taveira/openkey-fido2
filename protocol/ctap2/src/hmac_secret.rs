//! Extensão `hmac-secret` (CTAP 2.1 §12.5).
//!
//! Fluxo conforme a especificação:
//!
//! - **MakeCredential**: entrada booleana `true`. O autenticador gera
//!   `CredRandomWithUV` e `CredRandomWithoutUV` (32 bytes cada, via
//!   `SystemRandom`) e responde `"hmac-secret": true`.
//! - **GetAssertion**: mapa `{1: keyAgreement, 2: saltEnc, 3: saltAuth,
//!   4: pinUvAuthProtocol}`. O autenticador decapsula o acordo ECDH P-256,
//!   deriva o segredo compartilhado pelo protocolo PIN/UV indicado (1 ou 2),
//!   verifica `saltAuth = authenticate(sharedSecret, saltEnc)`, decifra os
//!   salts (32 ou 64 bytes de plaintext), calcula as saídas
//!   `HMAC-SHA-256(CredRandom, salt_i)` e devolve `salt1 || salt2` cifrado
//!   sob o mesmo segredo compartilhado.
//!
//! O segredo compartilhado é derivado *inline* do `keyAgreement` desta
//! requisição (CTAP 2.1 §12.5: a plataforma obtém o `sharedSecret` com um
//! getKeyAgreement imediatamente anterior). Para asserções encadeadas
//! (GetNextAssertion), o segredo e os salts decifrados são retidos em uma
//! sessão de transação ([`HmacSecretSession`], ADR-0022) — o acordo P-256 em
//! si permanece de uso único.

use alloc::vec::Vec;
use ciborium::Value;
use crypto::pin_protocol::{PinUvProtocol, Zeroizing};
use crypto::CryptoEngine;

use crate::client_pin::CoseEc2Key;
use crate::ctap2::{Ctap2Authenticator, Ctap2Error};

extern crate alloc;

/// Tamanho de cada salt (`salt1`/`salt2`, CTAP 2.1 §12.5).
const SALT_LEN: usize = 32;

/// Sessão de transação da extensão para asserções encadeadas (ADR-0022).
///
/// Estabelecida na asserção inicial com `hmac-secret`:
///
/// - `shared_secret`: necessário para **cifrar** a saída de cada asserção da
///   cadeia — a plataforma decifra todas com o mesmo segredo que ela própria
///   derivou do getKeyAgreement inicial;
/// - `salts`: os salts chegam cifrados uma única vez no GetAssertion; cada
///   saída é `HMAC-SHA-256(CredRandom_da_credencial, salt_i)`, logo os salts
///   decifrados precisam sobreviver às asserções seguintes.
///
/// Vive apenas em memória, pelo período de uma transação de user presence
/// (`GetAssertion` → cadeia de `GetNextAssertion`); nunca é persistido. É
/// descartada ao fim da cadeia, por qualquer outro comando CTAP2 ou no Reset,
/// com o material sensível apagado via [`Zeroizing`] no drop.
#[derive(Debug)]
pub(crate) struct HmacSecretSession {
    /// Segredo compartilhado da plataforma (`kdf(Z)` do protocolo PIN/UV):
    /// 32 bytes no protocolo 1, 64 bytes no protocolo 2.
    shared_secret: Zeroizing<Vec<u8>>,
    /// Protocolo PIN/UV usado na derivação (KDF/cifra dependem da versão).
    pin_protocol: u8,
    /// Salts decifrados da requisição inicial (32 ou 64 bytes).
    salts: Zeroizing<Vec<u8>>,
}

impl HmacSecretSession {
    fn protocol(&self) -> Result<PinUvProtocol, Ctap2Error> {
        PinUvProtocol::new(self.pin_protocol).map_err(|_| Ctap2Error::InvalidParameter)
    }
}

/// Interpreta a entrada booleana da extensão no MakeCredential.
///
/// Retorna `true` quando a plataforma pediu a geração de CredRandom.
/// `false` significa "não processar" (§12.5) e vira `Ok(false)`; qualquer
/// outro formato é rejeitado — o formato de mapa no MakeCredential pertence
/// à extensão separada `hmac-secret-mc`, não anunciada por este autenticador.
pub(crate) fn parse_make_credential(value: &Value) -> Result<bool, Ctap2Error> {
    match value {
        Value::Bool(true) => Ok(true),
        Value::Bool(false) => Ok(false),
        _ => Err(Ctap2Error::InvalidParameter),
    }
}

/// Forma de mapa da extensão no GetAssertion (CTAP 2.1 §12.5).
pub(crate) struct GetRequest {
    /// Chave pública efêmera da plataforma (`keyAgreement`, COSE_Key EC2).
    key_agreement: CoseEc2Key,
    /// Um ou dois salts cifrados sob o segredo compartilhado (`saltEnc`).
    salt_enc: Vec<u8>,
    /// MAC do protocolo sobre `saltEnc` (`saltAuth`).
    salt_auth: Vec<u8>,
    /// Versão do protocolo PIN/UV; padrão 1 quando ausente (§12.5).
    pin_protocol: u8,
}

/// Decodifica o mapa `{1: keyAgreement, 2: saltEnc, 3: saltAuth,
/// 4: pinUvAuthProtocol}`.
pub(crate) fn parse_get_assertion(value: &Value) -> Result<GetRequest, Ctap2Error> {
    let Value::Map(entries) = value else {
        return Err(Ctap2Error::InvalidParameter);
    };

    let mut key_agreement = None;
    let mut salt_enc = None;
    let mut salt_auth = None;
    // §12.5: "If pinUvAuthProtocol is absent ... let the value be 1".
    let mut pin_protocol = 1u8;

    for (key, val) in entries {
        let Value::Integer(number) = key else {
            continue;
        };
        let key_i64 = i64::try_from(*number).unwrap_or_default();
        match key_i64 {
            1 => key_agreement = Some(CoseEc2Key::from_cose_value(val)?),
            2 => salt_enc = Some(value_to_bytes(val)?),
            3 => salt_auth = Some(value_to_bytes(val)?),
            4 => pin_protocol = value_to_u8(val)?,
            _ => {}
        }
    }

    Ok(GetRequest {
        key_agreement: key_agreement.ok_or(Ctap2Error::MissingParameter)?,
        salt_enc: salt_enc.ok_or(Ctap2Error::MissingParameter)?,
        salt_auth: salt_auth.ok_or(Ctap2Error::MissingParameter)?,
        pin_protocol,
    })
}

/// Estabelece a sessão de transação da extensão na asserção inicial
/// (CTAP 2.1 §12.5, ADR-0022): decapsula o acordo ECDH P-256 (a chave
/// anunciada no getKeyAgreement mais recente é **consumida** — uso único,
/// §6.5.5.4), deriva o segredo compartilhado pelo protocolo PIN/UV indicado,
/// verifica `saltAuth = authenticate(sharedSecret, saltEnc)` e decifra os
/// salts (`32` ou `64` bytes de plaintext).
///
/// Falhas de derivação/verificação viram `PinAuthInvalid`; plaintext de salts
/// inválido vira `InvalidParameter` ("not 32 or 64 bytes long"), exatamente
/// como a especificação define.
pub(crate) fn begin_session(
    authenticator: &mut Ctap2Authenticator,
    request: &GetRequest,
) -> Result<HmacSecretSession, Ctap2Error> {
    let protocol =
        PinUvProtocol::new(request.pin_protocol).map_err(|_| Ctap2Error::InvalidParameter)?;

    // decapsulate(keyAgreement): consome a chave efêmera anunciada no
    // getKeyAgreement mais recente (CTAP 2.1 §6.5.5.4); sem ela não há
    // segredo compartilhado válido.
    let peer_point = request.key_agreement.to_uncompressed()?;
    let agreement_key = authenticator
        .take_pin_agreement_key()
        .ok_or(Ctap2Error::PinAuthInvalid)?;
    let z = agreement_key.agree(&peer_point).map_err(|_| {
        // Ponto inválido: a plataforma não possui o segredo desta transação.
        Ctap2Error::PinAuthInvalid
    })?;
    let secret = Zeroizing::new(protocol.kdf(&z).map_err(|_| Ctap2Error::PinAuthInvalid)?);

    // verify(shared secret, saltEnc, saltAuth): falha → PIN_AUTH_INVALID.
    if !protocol
        .verify(&secret, &request.salt_enc, &request.salt_auth)
        .unwrap_or(false)
    {
        return Err(Ctap2Error::PinAuthInvalid);
    }

    // decrypt(shared secret, saltEnc): "if the result is not 32 or 64 bytes
    // long, return CTAP1_ERR_INVALID_PARAMETER" (§12.5).
    let salts_plain = protocol
        .decrypt(&secret, &request.salt_enc)
        .map_err(|_| Ctap2Error::InvalidParameter)?;
    if salts_plain.len() != SALT_LEN && salts_plain.len() != SALT_LEN * 2 {
        return Err(Ctap2Error::InvalidParameter);
    }

    Ok(HmacSecretSession {
        shared_secret: secret,
        pin_protocol: request.pin_protocol,
        salts: Zeroizing::new(salts_plain),
    })
}

/// Saída cifrada da extensão para UMA credencial (assertion inicial ou
/// encadeada, CTAP 2.1 §12.5 + ADR-0022).
///
/// Calcula `output_i = HMAC-SHA-256(CredRandom, salt_i)` sobre os salts da
/// sessão e devolve `encrypt(sharedSecret, output1 [|| output2])`. O nonce é
/// aleatório via SystemRandom a cada chamada (protocolo 2 prefixa IV; o
/// protocolo 1 usa IV zero definido pela própria especificação §6.5.6) — cada
/// resposta da cadeia recebe cifra fresca.
pub(crate) fn session_output(
    crypto: &CryptoEngine,
    session: &HmacSecretSession,
    cred_random: &[u8],
) -> Result<Vec<u8>, Ctap2Error> {
    let protocol = session.protocol()?;

    // output_i = HMAC-SHA-256(CredRandom, salt_i), saídas completas de 32B.
    let mut outputs = Vec::with_capacity(session.salts.len() * 2);
    for salt in session.salts.chunks(SALT_LEN) {
        outputs.extend_from_slice(
            &crypto
                .compute_hmac(salt, cred_random)
                .map_err(|_| Ctap2Error::Unknown)?,
        );
    }

    protocol
        .encrypt(&session.shared_secret, &outputs)
        .map_err(|_| Ctap2Error::Unknown)
}

fn value_to_bytes(value: &Value) -> Result<Vec<u8>, Ctap2Error> {
    match value {
        Value::Bytes(bytes) => Ok(bytes.clone()),
        _ => Err(Ctap2Error::InvalidParameter),
    }
}

fn value_to_u8(value: &Value) -> Result<u8, Ctap2Error> {
    match value {
        Value::Integer(number) => {
            let raw = i64::try_from(*number).map_err(|_| Ctap2Error::InvalidParameter)?;
            u8::try_from(raw).map_err(|_| Ctap2Error::InvalidParameter)
        }
        _ => Err(Ctap2Error::InvalidParameter),
    }
}
