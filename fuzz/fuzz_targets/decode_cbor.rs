#![no_main]

use ciborium::value::Value;
use ctap2::{
    decode_cbor, encode_cbor, BioEnrollRequest, ClientPinRequest, GetAssertionRequest,
    MakeCredentialRequest,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_cbor::<MakeCredentialRequest>(data);
    let _ = decode_cbor::<GetAssertionRequest>(data);
    let _ = decode_cbor::<ClientPinRequest>(data);
    let _ = decode_cbor::<BioEnrollRequest>(data);

    if let Ok(value) = decode_cbor::<Value>(data) {
        if let Ok(reencoded) = encode_cbor(&value) {
            let roundtrip = decode_cbor::<Value>(&reencoded)
                .expect("reencoding a decoded CBOR value must stay decodable");
            fn values_equivalent(a: &Value, b: &Value) -> bool {
                match (a, b) {
                    (Value::Float(x), Value::Float(y)) => x == y || (x.is_nan() && y.is_nan()),
                    (Value::Tag(xt, xv), Value::Tag(yt, yv)) => {
                        xt == yt && values_equivalent(xv, yv)
                    }
                    (Value::Array(xs), Value::Array(ys)) => {
                        xs.len() == ys.len()
                            && xs.iter().zip(ys).all(|(x, y)| values_equivalent(x, y))
                    }
                    (Value::Map(xs), Value::Map(ys)) => {
                        xs.len() == ys.len()
                            && xs.iter().zip(ys).all(|((xk, xv), (yk, yv))| {
                                values_equivalent(xk, yk) && values_equivalent(xv, yv)
                            })
                    }
                    _ => a == b,
                }
            }
            assert!(
                values_equivalent(&value, &roundtrip),
                "CBOR roundtrip must be stable"
            );
        }
    }
});
