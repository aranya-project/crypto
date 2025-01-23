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
pub(crate) use dprintln;
