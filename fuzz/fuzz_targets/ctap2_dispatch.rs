#![no_main]

use ctap2::{Ctap2Authenticator, AAGUID};
use crypto::CryptoEngine;
use libfuzzer_sys::fuzz_target;
use storage::StorageEngine;

fuzz_target!(|data: &[u8]| {
    let Some((&command, payload)) = data.split_first() else {
        return;
    };
    let Ok(crypto) = CryptoEngine::new() else {
        return;
    };
    let Ok(storage) = StorageEngine::new() else {
        return;
    };
    let Ok(mut authenticator) = Ctap2Authenticator::new(AAGUID, crypto, storage) else {
        return;
    };

    let _ = authenticator.process_command(command, payload.to_vec());
});
