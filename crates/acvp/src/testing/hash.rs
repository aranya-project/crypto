//! Hash test utilities.

use core::fmt;

use anyhow::{ensure, Context};

use crate::{traits::Hash, util::dprintln};

// Testing with the default (Rust Crypto) SHA-2 and SHA-3 impls
// suggests that a large value here doesn't really matter. So,
// make it large enough to handle at least a couple blocks.
const LARGE_DATA_TEST_MSG_SIZE: usize = 256;

/// Backing memory for a large data test.
#[derive(Clone, Debug)]
pub struct LargeDataTest {
    /// Contains as many copies of the LDT's message as will fit
    /// for faster testing.
    msg: [u8; LARGE_DATA_TEST_MSG_SIZE],
}

impl LargeDataTest {
    /// Creates a `LargeDataTest`.
    pub fn new() -> Self {
        Self {
            msg: [0; LARGE_DATA_TEST_MSG_SIZE],
        }
    }

    /// Performs the LDT, returning the computed digest.
    ///
    /// The caller is responsible for comparing the computed
    /// digest with the expected digest.
    ///
    /// `total_bytes` is the total number of **bytes** that must
    /// be written to the hash. It must be divisible by
    /// `content.len()`.
    #[track_caller]
    #[allow(clippy::arithmetic_side_effects)]
    pub fn run<H: Hash>(
        &mut self,
        content: &[u8],
        total_bytes: usize,
    ) -> anyhow::Result<H::Digest> {
        ensure!(!content.is_empty(), "`content` cannot be empty");
        ensure!(
            total_bytes % content.len() == 0,
            "`total_bytes` is not divisible by `content.len()`"
        );

        let mut timer = Timer::start();
        let msg = self
            .fill(content)
            .with_context(|| "BUG: `content` is too large")?;
        dprintln!("`fill` took {:.2?}", timer.elapsed());
        timer.restart();

        let chunks = total_bytes / msg.len();
        let mut h = <H>::new();
        for _ in 0..chunks {
            h.update(msg);
        }
        let n = (total_bytes % msg.len()) / content.len();
        for _ in 0..n {
            h.update(content);
        }
        dprintln!(
            "`update` {chunks} chunks + {n} bytes took {:.2?}",
            timer.elapsed()
        );

        Ok(h.digest())
    }

    /// Fills `self.msg` with as many copies of `s` as possible
    /// and returns the portion of `self.msg` that was written
    /// to, or `None` if `s` is larger than `self.msg`.
    #[allow(clippy::arithmetic_side_effects)]
    fn fill(&mut self, s: &[u8]) -> Option<&[u8]> {
        if s.is_empty() {
            self.msg.fill(0);
            return Some(&self.msg);
        }

        if s.len() > self.msg.len() {
            return None;
        }
        let count = self.msg.len() / s.len();
        assert!(count >= 1);

        let n = count * s.len();
        assert!(n <= self.msg.len());

        const LIMIT: usize = 8 * 1024;
        let chunk_max = if n > LIMIT {
            let max = (LIMIT / s.len()) * s.len();
            if max > 0 {
                max
            } else {
                s.len()
            }
        } else {
            n
        };

        self.msg[..s.len()].copy_from_slice(s);
        let mut i = s.len();
        while i != n {
            let mut chunk = chunk_max;
            if chunk > i {
                // More than how much we've written.
                chunk = i;
            }
            if chunk > n - i {
                // More than the space we have left.
                chunk = n - i;
            }
            if chunk > self.msg.len() - i {
                // This just helps the compiler out since this
                // code might be running without full compiler
                // optimizations.
                chunk = self.msg.len() - i;
            }
            self.msg.copy_within(..chunk, i);
            i = i.wrapping_add(chunk);
        }

        Some(&self.msg[..n])
    }
}

impl Default for LargeDataTest {
    fn default() -> Self {
        Self::new()
    }
}

struct Timer {
    #[cfg(feature = "std")]
    start: std::time::Instant,
}

impl Timer {
    fn start() -> Self {
        Self {
            #[cfg(feature = "std")]
            start: std::time::Instant::now(),
        }
    }

    #[cfg(feature = "std")]
    fn elapsed(&self) -> std::time::Duration {
        self.start.elapsed()
    }

    fn restart(&mut self) {
        #[cfg(feature = "std")]
        {
            self.start = std::time::Instant::now();
        }
    }
}

#[derive(Clone)]
pub(crate) enum MctSeed<S, H: Hash> {
    /// The original seed value passed to the MCT.
    Seed(S),
    /// Subsequent digests.
    Digest(H::Digest),
}

impl<S, H> fmt::Debug for MctSeed<S, H>
where
    H: Hash,
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Digest(d) => f.debug_tuple("MctSeed::Digest").field(d).finish(),
            Self::Seed(v) => f.debug_tuple("MctSeed::Other").field(v).finish(),
        }
    }
}

impl<S, H> MctSeed<S, H>
where
    H: Hash,
{
    pub(crate) fn as_bytes(&self) -> &[u8]
    where
        S: AsRef<[u8]>,
    {
        match self {
            Self::Digest(d) => d.as_ref(),
            Self::Seed(v) => v.as_ref(),
        }
    }
}
