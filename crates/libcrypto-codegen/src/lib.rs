//! Code generation for `spideroak-libcrypto`.

mod error;
pub mod gen;

use std::{fs, path::Path};

/// Generated headers.
pub struct Headers {
    max_aead_size: usize,
    max_aead_align: usize,
}

impl Headers {
    /// TODO
    pub fn new() -> Self {
        Self {
            max_aead_size: 0,
            max_aead_align: 0,
        }
    }

    /// Writes the headers to `dir`.
    pub fn generate<P: AsRef<Path>>(self, dir: P) -> anyhow::Result<()> {
        let Self {
            max_aead_size,
            max_aead_align,
        } = self;

        let dir = dir.as_ref().join("openssl");
        fs::create_dir_all(&dir)?;

        fs::write(dir.join("base.h"), BASE_H)?;
        fs::write(dir.join("aead.h"), AEAD_H)?;
        self.write_cfg(&dir.join("__config.h"))?;

        println!("cargo::rustc-env=SPIDEROAK_LIBCRYPTO_MAX_AEAD_SIZE={max_aead_size}");
        println!("cargo::rustc-env=SPIDEROAK_LIBCRYPTO_MAX_AEAD_ALIGN={max_aead_align}");

        Ok(())
    }

    fn write_cfg(&self, path: &Path) -> anyhow::Result<()> {
        let Self {
            max_aead_size,
            max_aead_align,
        } = self;

        let buf = format!(
            r#"
#ifndef OPENSSL_HEADER_CONFIG_H
#define OPENSSL_HEADER_CONFIG_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {{
#endif

enum {{
    OPENSSL_EVP_AEAD_CTX_SIZE = {max_aead_size},
    OPENSSL_EVP_AEAD_CTX_ALIGN = {max_aead_align},
}}

#if defined(__cplusplus)
}} // extern "C"
#endif

#endif /* OPENSSL_HEADER_CONFIG_H */
"#
        );
        fs::write(path, buf)?;
        Ok(())
    }
}

static BASE_H: &str = include_str!("base.h");
static AEAD_H: &str = include_str!("aead.h");
