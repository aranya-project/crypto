//! Build script.

use std::{env, fs, path::Path};

use anyhow::Context;
use spideroak_libcrypto_codegen::{self as gen, Builder};

fn main() -> anyhow::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(cbindgen)");
    if env::var("_CBINDGEN_IS_RUNNING").is_ok() {
        println!("cargo::rustc-cfg=cbindgen");
    }

    let out_dir = env::var("OUT_DIR")?;

    let bindings = Builder::new()
        // RustCrypto `aes` <= v0.8.4 defaults to a large
        // bitslicing impl when it can't auto-detect AES
        // intrinsics.
        .with_max_aead_size(1024)
        .build();

    let tokens = bindings
        .generate_code()
        .inspect_err(|err| err.display(Path::new(""), ""))?;
    let code = gen::format(&tokens);
    let out_path = Path::new(&out_dir).join("generated.rs");
    fs::write(out_path, &code)?;

    bindings
        .generate_headers(out_dir)
        .with_context(|| "unable to write headers")?;
    Ok(())
}
