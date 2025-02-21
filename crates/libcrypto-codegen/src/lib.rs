//! Code generation for `spideroak-libcrypto`.

use std::{fs, path::Path};

/// Writes the headers to `dir`.
pub fn write_headers<P: AsRef<Path>>(dir: P) -> anyhow::Result<()> {
    let dir = dir.as_ref().join("openssl");
    fs::create_dir_all(&dir)?;

    fs::write(dir.join("base.h"), BASE_H)?;
    fs::write(dir.join("aead.h"), AEAD_H)?;

    Ok(())
}

static BASE_H: &str = include_str!("base.h");
static AEAD_H: &str = include_str!("aead.h");
