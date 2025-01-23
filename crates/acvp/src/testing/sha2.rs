//! SHA-2 testing utilities.

#![cfg(feature = "sha2")]
#![cfg_attr(docsrs, doc(cfg(feature = "sha2")))]

use alloc::vec::Vec;
use core::{
    fmt,
    iter::{ExactSizeIterator, FusedIterator},
    marker::PhantomData,
};

pub use crate::testing::hash::LargeDataTest;
use crate::{testing::hash::MctSeed, traits::Hash};

/// SHA-2 MCT.
#[derive(Clone)]
pub struct MctIter<'a, H: Hash> {
    inner: MctInner<'a, H>,
    i: usize,
}

impl<'a, H: Hash> MctIter<'a, H> {
    /// Creates a new SHA-2 MCT iterator.
    ///
    /// If `alt` is true, it implements the alternate MCT.
    /// Otherwise, it implements the standard MCT.
    pub fn new(seed: &'a [u8], alt: bool) -> Self {
        Self {
            inner: MctInner::new(seed, alt),
            i: 0,
        }
    }
}

impl<H: Hash> fmt::Debug for MctIter<'_, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mct")
            .field("inner", &self.inner)
            .field("j", &self.i)
            .finish()
    }
}

impl<H: Hash> Iterator for MctIter<'_, H> {
    type Item = H::Digest;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.i < 100 {
            self.i = self.i.wrapping_add(1);
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

impl<H: Hash> ExactSizeIterator for MctIter<'_, H> {
    #[inline]
    fn len(&self) -> usize {
        // NB: `i` is in [0, 100]
        100usize.wrapping_sub(self.i)
    }
}

impl<H: Hash> FusedIterator for MctIter<'_, H> {}

/// An [`Iterator`] over each `i` step in a SHA-2 monte carlo
/// test.
#[derive(Clone)]
struct MctInner<'a, H: Hash> {
    seed_len: Option<usize>,
    seed: MctSeed<&'a [u8], H>,
    msg: Vec<u8>,
    _h: PhantomData<H>,
}

impl<'a, H: Hash> MctInner<'a, H> {
    fn new(seed: &'a [u8], alt: bool) -> Self {
        Self {
            seed_len: if alt { Some(seed.len()) } else { None },
            seed: MctSeed::Seed(seed),
            msg: Vec::new(),
            _h: PhantomData,
        }
    }
}

impl<H: Hash> fmt::Debug for MctInner<'_, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MctInner")
            .field("seed", &self.seed)
            .finish_non_exhaustive()
    }
}

impl<H: Hash> Iterator for MctInner<'_, H> {
    type Item = H::Digest;

    fn next(&mut self) -> Option<Self::Item> {
        let mut a = self.seed.clone();
        let mut b = self.seed.clone();
        let mut c = self.seed.clone();
        for _ in 0..=999 {
            self.msg.truncate(0);
            self.msg.extend_from_slice(a.as_bytes());
            self.msg.extend_from_slice(b.as_bytes());
            self.msg.extend_from_slice(c.as_bytes());
            if let Some(initial_seed_len) = self.seed_len {
                if self.msg.len() > initial_seed_len {
                    self.msg.truncate(initial_seed_len);
                } else {
                    self.msg.resize(initial_seed_len, 0);
                }
            }
            let md = H::hash(&self.msg);
            a = b;
            b = c;
            c = MctSeed::Digest(md);
        }
        self.seed = c;
        match &self.seed {
            MctSeed::Seed(_) => unreachable!(),
            MctSeed::Digest(d) => Some(d.clone()),
        }
    }
}
