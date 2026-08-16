#![no_main]

use libfuzzer_sys::fuzz_target;
use transport::ctaphid::CtaphidAssembler;

fuzz_target!(|data: &[u8]| {
    let mut assembler = CtaphidAssembler::new();
    for chunk in data.chunks(64) {
        if chunk.len() != 64 {
            break;
        }
        let mut packet = [0u8; 64];
        packet.copy_from_slice(chunk);
        let _ = assembler.process_packet(&packet);
    }
});
