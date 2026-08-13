#![no_main]

use ciborium::value::Value;
use ctap2::{
    decode_cbor, encode_cbor, BioEnrollRequest, ClientPinRequest, GetAssertionRequest,
    MakeCredentialRequest,
};
use libfuzzer_sys::fuzz_target;

/// `ciborium::Value` normaliza o CBOR (indefinite→definite, tags 0..=3 →
/// tipos naturais, f16→f64), então `decode(encode(v))` pode diferir de `v` no
/// primeiro passo — ex.: tag 2 (bignum) sobre bstr indefinido vira `Integer`.
/// O invariante correto é que a re-encodação *estabiliza*: a segunda e a
/// terceira re-encodações são idênticas.
fn reencode_stable(value: &Value) -> bool {
    let Ok(e1) = encode_cbor(value) else {
        return true;
    };
    let Ok(v2) = decode_cbor::<Value>(&e1) else {
        return false;
    };
    let Ok(e2) = encode_cbor(&v2) else {
        return true;
    };
    let Ok(v3) = decode_cbor::<Value>(&e2) else {
        return false;
    };
    let Ok(e3) = encode_cbor(&v3) else {
        return true;
    };
    e2 == e3
}

fuzz_target!(|data: &[u8]| {
    let _ = decode_cbor::<MakeCredentialRequest>(data);
    let _ = decode_cbor::<GetAssertionRequest>(data);
    let _ = decode_cbor::<ClientPinRequest>(data);
    let _ = decode_cbor::<BioEnrollRequest>(data);

    if let Ok(value) = decode_cbor::<Value>(data) {
        assert!(reencode_stable(&value), "CBOR re-encoding must stabilize");
    }
});
