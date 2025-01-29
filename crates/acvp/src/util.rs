#[allow(unused_macros, reason = "Depends which features are enabled")]
macro_rules! dprintln {
    () => {
        #[cfg(feature = "std")] {
            eprintln!();
        }
    };
    ($($tt:tt)*) => {
        #[cfg(feature = "std")] {
            eprintln!($($tt)*);
        }
    };
}
#[allow(unused_imports, reason = "Depends which features are enabled")]
pub(crate) use dprintln;

#[allow(unused_macros, reason = "Depends which features are enabled")]
macro_rules! ensure_eq {
    ($left:expr, $right:expr $(,)?) => {
        match (&$left, &$right) {
            (left_val, right_val) => {
                if (*left_val != *right_val) {
                    ::anyhow::bail!(r#"
left: {:?}
right: {:?}"#,
                        &*left_val,
                        &*right_val,
                    );
                }
            }
        }
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
        match (&$left, &$right) {
            (left_val, right_val) => {
                if (*left_val != *right_val) {
                    let args = ::alloc::format!($($arg)+);
                    ::anyhow::bail!(r#"{args}
left: {:?}
right: {:?}"#,
                        &*left_val,
                        &*right_val,
                    );
                }
            }
        }
    };
}
#[allow(unused_imports, reason = "Depends which features are enabled")]
pub(crate) use ensure_eq;
