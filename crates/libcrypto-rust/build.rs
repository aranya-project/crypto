//! Build script.

use std::env;

use anyhow::Context;
use spideroak_libcrypto_codegen::write_headers;

fn main() -> anyhow::Result<()> {
    let out_dir = env::var("OUT_DIR")?;
    write_headers(out_dir).with_context(|| "unable to write headers")?;
    Ok(())
}
