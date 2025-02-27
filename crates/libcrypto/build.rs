//! Build script.

use std::env;

fn main() -> anyhow::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(cbindgen)");
    if env::var("_CBINDGEN_IS_RUNNING").is_ok() {
        println!("cargo::rustc-cfg=cbindgen");
    }
    Ok(())
}
