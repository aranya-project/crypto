//! SHA-3 testing utilities.

#![cfg(feature = "sha3")]
#![cfg_attr(docsrs, doc(cfg(feature = "sha3")))]

use alloc::boxed::Box;
use core::{
    cmp, fmt,
    iter::{ExactSizeIterator, FusedIterator},
};

pub use crate::testing::hash::LargeDataTest;
use crate::{testing::hash::MctSeed, traits::Hash};

/// SHA-3 standard MCT.
#[derive(Clone)]
pub struct StdMctIter<'a, H: Hash> {
    inner: StdMctInner<'a, H>,
    j: usize,
}

impl<'a, H: Hash> StdMctIter<'a, H> {
    /// Creates a new SHA-3 alternate MCT iterator.
    pub fn new(seed: &'a [u8]) -> Self {
        Self {
            inner: StdMctInner::new(seed),
            j: 0,
        }
    }
}

impl<H: Hash> fmt::Debug for StdMctIter<'_, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StdMct")
            .field("inner", &self.inner)
            .field("j", &self.j)
            .finish()
    }
}

impl<H: Hash> Iterator for StdMctIter<'_, H> {
    type Item = H::Digest;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.j < 100 {
            self.j = self.j.wrapping_add(1);
            self.inner.next()
        } else {
            None
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.len();
        (n, Some(n))
    }
}

impl<H: Hash> ExactSizeIterator for StdMctIter<'_, H> {
    #[inline]
    fn len(&self) -> usize {
        // NB: `j` is in [0, 100]
        100usize.wrapping_sub(self.j)
    }
}

impl<H: Hash> FusedIterator for StdMctIter<'_, H> {}

/// SHA-3 standard MCT.
#[derive(Clone)]
struct StdMctInner<'a, H: Hash> {
    seed: MctSeed<&'a [u8], H>,
}

impl<'a, H: Hash> StdMctInner<'a, H> {
    fn new(seed: &'a [u8]) -> Self {
        Self {
            seed: MctSeed::Seed(seed),
        }
    }
}

impl<H: Hash> fmt::Debug for StdMctInner<'_, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StdMctInner")
            .field("seed", &self.seed)
            .finish()
    }
}

impl<H: Hash> Iterator for StdMctInner<'_, H> {
    type Item = H::Digest;

    fn next(&mut self) -> Option<Self::Item> {
        // NB: The caller handles all of the 100 `j` iterations.
        //
        // For j = 0 to 99
        // MD[0] = SEED;
        //     For i = 1 to 1000
        //         MSG = MD[i-1]
        //         MD[i] = SHA3(MSG)
        //     Output MD[1000]
        //     SEED = MD[1000]

        // Instead of keeping 1000 digests in memory, do the
        // obvious thing and just keep the previous digest.
        let mut md = H::hash(self.seed.as_bytes());

        // This loop condition is the same thing as
        //    for _ in 2..=1000 { ... }
        // but generates a little better code.
        for _ in 1..1000 {
            md = H::hash(md.as_ref());
        }

        self.seed = MctSeed::Digest(md.clone());
        Some(md)
    }
}

/// SHA-3 alternate MCT.
#[derive(Clone)]
pub struct AltMctIter<H: Hash> {
    inner: AltMctInner<H>,
    j: usize,
}

impl<H: Hash> AltMctIter<H> {
    /// Creates a new SHA-3 alternate MCT iterator.
    pub fn new(seed: &[u8]) -> Self {
        Self {
            inner: AltMctInner::new(seed),
            j: 0,
        }
    }
}

impl<H: Hash> fmt::Debug for AltMctIter<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AltMct")
            .field("inner", &self.inner)
            .field("j", &self.j)
            .finish()
    }
}

impl<H: Hash> Iterator for AltMctIter<H> {
    type Item = H::Digest;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.j < 100 {
            self.j = self.j.wrapping_add(1);
            self.inner.next()
        } else {
            None
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.len();
        (n, Some(n))
    }
}

impl<H: Hash> ExactSizeIterator for AltMctIter<H> {
    #[inline]
    fn len(&self) -> usize {
        // NB: `j` is in [0, 100]
        100usize.wrapping_sub(self.j)
    }
}

impl<H: Hash> FusedIterator for AltMctIter<H> {}

/// SHA-3 alternate MCT inner loop.
#[derive(Clone)]
struct AltMctInner<H: Hash> {
    /// If `j0`, this contains the original seed. Otherwise, it
    /// is scratch space for padding each message.
    msg: Box<[u8]>,
    /// MD[0] saved across iters.
    ///
    /// If `j0` then this is unset.
    md: H::Digest,
    j0: bool,
}

impl<'a, H: Hash> AltMctInner<H> {
    fn new(seed: &'a [u8]) -> Self {
        Self {
            msg: seed.to_vec().into_boxed_slice(),
            md: H::Digest::default(),
            j0: true,
        }
    }
}

impl<H: Hash> fmt::Debug for AltMctInner<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AltMct")
            .field("seed", &self.md)
            .field("msg", &self.msg)
            .finish_non_exhaustive()
    }
}

impl<H: Hash> Iterator for AltMctInner<H> {
    type Item = H::Digest;

    fn next(&mut self) -> Option<Self::Item> {
        // NB: The caller handles all of the 100 `j` iterations.
        //
        // MD[0] = SEED
        // INITIAL_SEED_LENGTH = LEN(SEED)
        // For 100 iterations
        //     For i = 1 to 1000
        //         MSG = MD[i-1];
        //         if LEN(MSG) >= INITIAL_SEED_LENGTH:
        //             MSG = leftmost INITIAL_SEED_LENGTH bits of MSG
        //         else:
        //             MSG = MSG || INITIAL_SEED_LENGTH - LEN(MSG) 0 bits
        //         MD[i] = SHA3(MSG)
        //     MD[0] = MD[1000]
        //     Output MD[0]

        let mut start = 1;
        if self.j0 {
            // This is j = 0 where
            //    MD[0] = SEED
            self.md = H::hash(&self.msg);
            start = 2;
            self.j0 = false;
        };

        for _ in start..=1000 {
            let md = &self.md.as_ref();
            // We assume that the seed is larger than the
            // metadata.
            self.msg[..md.len()].copy_from_slice(md);
            let n = cmp::min(self.msg.len(), md.len());
            let (lhs, rhs) = self.msg.split_at_mut(n);
            lhs.copy_from_slice(&md[..n]);
            rhs.fill(0);
            self.md = H::hash(&self.msg);
        }

        Some(self.md.clone())
    }
}
