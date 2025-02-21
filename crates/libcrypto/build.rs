//! Build script.

use std::env;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(cbindgen)");
    println!("cargo::rustc-check-cfg=cfg(cbindgenx)");
    if env::var("_CBINDGEN_IS_RUNNING").is_ok() {
        println!("cargo::rustc-cfg=cbindgen");
    }
}
