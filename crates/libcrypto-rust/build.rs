//! Build script.

use std::{env, fs, path::Path};

use anyhow::Context;
use spideroak_libcrypto_codegen::{
    gen::{self, Builder},
    Headers,
};

fn main() -> anyhow::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(cbindgen)");
    if env::var("_CBINDGEN_IS_RUNNING").is_ok() {
        println!("cargo::rustc-cfg=cbindgen");
    }

    let out_dir = env::var("OUT_DIR")?;

    let tokens = Builder::new()
        .generate()
        .inspect_err(|err| err.display(Path::new(""), ""))?;
    let code = gen::format(&tokens);
    let out_path = Path::new(&out_dir).join("generated.rs");
    fs::write(out_path, &code)?;

    Headers::new()
        .generate(out_dir)
        .with_context(|| "unable to write headers")?;
    Ok(())
}
