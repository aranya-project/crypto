//! Build script.

use std::env;

use anyhow::Context;
use spideroak_libcrypto_codegen::Builder;

fn main() -> anyhow::Result<()> {
    let out_dir = env::var("OUT_DIR")?;
    let headers = Builder::new()
        // RustCrypto `aes` <= v0.8.4 defaults to a large
        // bitslicing impl when it can't auto-detect AES
        // intrinsics.
        .with_max_aead_size(1024)
        .build()?;
    headers
        .generate(out_dir)
        .with_context(|| "unable to write headers")?;
    Ok(())
}
