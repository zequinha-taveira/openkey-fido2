//! Copia `memory.x` para o diretório de build para o linker encontrá-lo.
//!
//! O `link.x` do `cortex-m-rt` faz `INCLUDE memory.x`, então o arquivo
//! precisa estar em um caminho de busca do linker.

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    println!("cargo:rustc-link-search={}", out_dir.display());

    let memory_x = include_bytes!("memory.x");
    File::create(out_dir.join("memory.x"))
        .unwrap()
        .write_all(memory_x)
        .unwrap();

    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=build.rs");
}
