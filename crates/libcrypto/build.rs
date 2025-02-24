//! Build script.

use std::{
    env::{self, VarError},
    fmt::Write,
    fs,
    path::PathBuf,
};

const SPIDEROAK_LIBCRYPTO_MAX_AEAD_SIZE: &str = "SPIDEROAK_LIBCRYPTO_MAX_AEAD_SIZE";
const SPIDEROAK_LIBCRYPTO_MAX_AEAD_ALIGN: &str = "SPIDEROAK_LIBCRYPTO_MAX_AEAD_ALIGN";

fn main() -> anyhow::Result<()> {
    println!("cargo::rerun-if-env-changed={SPIDEROAK_LIBCRYPTO_MAX_AEAD_SIZE}");
    println!("cargo::rerun-if-env-changed={SPIDEROAK_LIBCRYPTO_MAX_AEAD_ALIGN}");

    println!("cargo::rustc-check-cfg=cfg(cbindgen)");
    if env::var("_CBINDGEN_IS_RUNNING").is_ok() {
        println!("cargo::rustc-cfg=cbindgen");
    }

    println!(
        "cargo::warning=zz {:?}",
        option_env!("SPIDEROAK_LIBCRYPTO_MAX_AEAD_SIZE")
    );

    let mut buf = String::new();

    let max_size: usize = match env::var(SPIDEROAK_LIBCRYPTO_MAX_AEAD_SIZE) {
        Ok(s) => s.parse()?,
        Err(VarError::NotPresent) => 512,
        Err(err) => Err(err)?,
    };
    writeln!(
        &mut buf,
        r#"
/// The maximum size in bytes of an AEAD implementation.
pub const MAX_AEAD_SIZE: usize = {max_size};
"#,
    )?;

    let max_align: usize = match env::var(SPIDEROAK_LIBCRYPTO_MAX_AEAD_ALIGN) {
        Ok(s) => s.parse()?,
        Err(VarError::NotPresent) => 16,
        Err(err) => Err(err)?,
    };
    writeln!(
        &mut buf,
        r#"
/// The maximum alignment in bytes of an AEAD implementation.
pub const MAX_AEAD_ALIGN: usize = {max_align};
"#,
    )?;

    let out_path = PathBuf::from(env::var("OUT_DIR")?).join("generated.rs");
    fs::write(out_path, &buf)?;

    Ok(())
}
