#![allow(clippy::module_inception, reason = "This is intentional")]

cfg_if::cfg_if! {
    if #[cfg(all(feature = "linkage", unix, not(target_vendor = "apple")))] {
        macro_rules! new_sym {
            ($sym:ident, $ty:ty) => {
                extern "C" {
                    #[linkage = "extern_weak"]
                    #[allow(non_upper_case_globals)]
                    static $sym: ::core::option::Option<unsafe extern "C" fn() -> $ty?>;
                }
            };
        }
        pub(crate) use new_sym;

        macro_rules! get_sym {
            ($sym:ident, $ty:ty) => {
                match unsafe { $sym } {
                    ::core::option::Option::Some(f) => unsafe { f() },
                    ::core::option::Option::None => ::core::ptr::null(),
                }
            };
        }
        pub(crate) use get_sym;

        #[doc(hidden)]
        #[macro_export]
        macro_rules! set_sym {
            ($name:ident, || -> $ty:ty $block:block) => {
                #[no_mangle]
                unsafe extern "C" fn $name() -> $ty {
                    $block
                }
            };
        }
    } else if #[cfg(feature = "ctor")] {
        macro_rules! new_sym {
            ($sym:ident, $ty:ty) => {
                #[doc(hidden)]
                pub static $sym: ::core::sync::atomic::AtomicPtr<$ty> =
                    ::core::sync::atomic::AtomicPtr::new(::core::ptr::null_mut());
            };
        }
        pub(crate) use new_sym;

        macro_rules! get_sym {
            ($sym:ident) => {
                $sym.load(::core::sync::atomic::Ordering::Relaxed).cast_const()
            };
        }
        pub(crate) use get_sym;

        #[doc(hidden)]
        #[macro_export]
        macro_rules! set_sym {
            ($name:ident, || -> $ty:ty $block:block) => {
                $crate::ctor!(|| {
                    #[used]
                    static __TMP: $ty = { $block };
                    let result = $name.compare_exchange(
                        ::core::ptr::null_mut(),
                        ::core::ptr::from_ref(&__TMP).cast_mut(),
                        ::core::sync::atomic::Ordering::SeqCst,
                        ::core::sync::atomic::Ordering::SeqCst,
                    );
                    debug_assert!(result.is_ok());
                });
            };
        }

        #[doc(hidden)]
        #[macro_export]
        macro_rules! ctor {
            ($name:expr) => {
                const _: () = {
                    #[cfg_attr(
                        any(target_os = "linux", target_os = "android"),
                        link_section = ".text.startup"
                    )]
                    extern "C" fn __init() {
                        $name()
                    }

                    #[used]
                    // mach-o uses __mod_init_func
                    // - https://stackoverflow.com/a/30703178
                    // - https://opensource.apple.com/source/dyld/dyld-239.3/src/dyldInitialization.cpp
                    #[cfg_attr(
                        all(unix, target_vendor = "apple"),
                        link_section = "__DATA,__mod_init_func"
                    )]
                    // ELF uses .init_array
                    // - https://refspecs.linuxfoundation.org/LSB_1.1.0/gLSB/specialsections.html
                    #[cfg_attr(all(unix, not(target_vendor = "apple")), link_section = ".init_array")]
                    // The only LLVM toolchain that uses .ctors is
                    // mingw.
                    #[cfg_attr(
                        all(target_os = "windows", target_env = "gnu"),
                        link_section = ".ctors"
                    )]
                    // Windows (outside of mingw) uses .CRT$XCU.
                    #[cfg_attr(all(windows, not(target_env = "gnu")), link_section = ".CRT$XCU")]
                    static __CTOR: extern "C" fn() = __init;

                    // AIX uses -wl,-binitfini:$name
                    // I don't think VxWorks has any support for
                    // this, even though it uses ELF.
                    #[cfg(any(target_os = "aix", target_os = "vxworks"))]
                    compile_error("VxWorks and AIX are currently unsupported");
                };
            };
        }
    } else {
        macro_rules! new_sym {
            ($sym:ident, $ty:ty) => {
                #[doc(hidden)]
                #[linkme::distributed_slice]
                #[used]
                pub static $sym: [Option<&$ty>] = [..];

                // Make sure that we always have one element
                // because of <https://github.com/dtolnay/linkme/issues/98#issuecomment-2296078911>
                const _: () = {
                    #[linkme::distributed_slice($sym)]
                    #[allow(unused_attributes)]
                    #[used]
                    static __TMP: Option<&$ty> = None;
                };
            };
        }
        pub(crate) use new_sym;

        macro_rules! get_sym {
            ($sym:ident) => {{
                debug_assert!(!$sym.is_empty());
                debug_assert!($sym.len() <= 2);

                match $sym.get(0) {
                    Some(None) => match $sym.get(1) {
                        Some(Some(v)) => ::core::ptr::from_ref(v),
                        _ => ::core::ptr::null(),
                    },
                    Some(Some(v)) => ::core::ptr::from_ref(v),
                    None => ::core::ptr::null(),
                }
            }};
        }
        pub(crate) use get_sym;

        #[doc(hidden)]
        #[macro_export]
        macro_rules! set_sym {
            ($name:ident, || -> $ty:ty $block:block) => {
                const _: () = {
                    #[$crate::linkme::distributed_slice($name)]
                    #[linkme(crate = $crate::linkme)]
                    #[allow(unused_attributes)]
                    #[used]
                    static __TMP: ::core::option::Option<&$ty> =
                        ::core::option::Option::Some(&{ $block });
                };
            };
        }
    }
}
