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
            assert_eq!(value, roundtrip, "CBOR roundtrip must be stable");
        }
    }
});
