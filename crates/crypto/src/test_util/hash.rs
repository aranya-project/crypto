//! [`Hash`] tests.

use crate::{hash::Hash, oid::Identified};

/// Invokes `callback` for each hash test.
///
/// # Example
///
/// ```
/// use spideroak_crypto::rust::Sha256;
///
/// macro_rules! run_test {
///     ($test:ident) => {
///         spideroak_crypto::test_util::hash::$test::<Sha256>();
///     };
/// }
/// spideroak_crypto::for_each_hash_test!(run_test);
/// ```
#[macro_export]
macro_rules! for_each_hash_test {
    ($callback:ident) => {
        $crate::__apply! {
            $callback,
            test_vectors,
            test_basic,
        }
    };
}
pub use for_each_hash_test;

/// Performs cryptographic hash tests.
///
/// This macro expands into a bunch of individual `#[test]`
/// functions.
///
/// # Example
///
/// ```
/// use spideroak_crypto::{test_hash, rust::Sha256};
///
/// test_hash!(mod sha256, Sha256);
/// ```
#[macro_export]
macro_rules! test_hash {
    (mod $name:ident, $hash:ty) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            $crate::test_hash!($hash);
        }
    };
    ($hash:ty) => {
        macro_rules! __hash_test {
            ($test:ident) => {
                #[test]
                fn $test() {
                    use $crate::test_util::{hash::$test, HashWithDefaults};

                    $test::<$hash>();
                    $test::<HashWithDefaults<$hash>>();
                }
            };
        }
        $crate::for_each_hash_test!(__hash_test);
    };
}
pub use test_hash;

/// Tests against hash-specific vectors.
///
/// Unknown hash algorithms are ignored.
pub fn test_vectors<T: Hash + Identified>() {
    use acvp::vectors::{sha2, sha3};

    use crate::{
        oid::consts::{SHA2_256, SHA2_512, SHA2_512_256, SHA3_256},
        test_util::acvp::{test_sha2, test_sha3},
    };

    fn load_and_test_sha2<T: Hash>(alg: sha2::Algorithm) {
        let vectors = sha2::load(alg).expect("should be able to load SHA-2 test vectors");
        test_sha2::<T>(&vectors);
    }

    fn load_and_test_sha3<T: Hash>(alg: sha3::Algorithm) {
        let vectors = sha3::load(alg).expect("should be able to load SHA-3 test vectors");
        test_sha3::<T>(&vectors);
    }

    match T::OID {
        SHA2_256 => load_and_test_sha2::<T>(sha2::Algorithm::Sha2_256),
        SHA2_512 => load_and_test_sha2::<T>(sha2::Algorithm::Sha2_512),
        SHA2_512_256 => load_and_test_sha2::<T>(sha2::Algorithm::Sha2_512_256),
        SHA3_256 => load_and_test_sha3::<T>(sha3::Algorithm::Sha3_256),
        _ => {}
    }
}

/// A basic test for a `Hash`.
pub fn test_basic<T: Hash>() {
    const INPUT: &[u8] = r#"
Sir, in my heart there was a kind of fighting
That would not let me sleep. Methought I lay
Worse than the mutines in the bilboes. Rashly—
And prais'd be rashness for it—let us know
Our indiscretion sometimes serves us well ...
"#
    .as_bytes();

    let want = T::hash(INPUT);

    let got = {
        // Repeated calls to `update` should be the same as
        // calling `hash` directly.
        let mut h = T::new();
        for c in INPUT {
            h.update(&[*c]);
        }
        h.digest()
    };
    assert_eq!(want, got);

    // Hashing the same input should result in the same
    // output.
    assert_eq!(want, T::hash(INPUT));

    // A modified input should have a different hash, though.
    let mut modified = INPUT.to_vec();
    modified[0] += 1;
    assert_ne!(want, T::hash(&modified[..]));
}
