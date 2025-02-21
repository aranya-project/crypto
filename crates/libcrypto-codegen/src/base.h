#ifndef OPENSSL_HEADER_BASE_H
#define OPENSSL_HEADER_BASE_H

#if defined(__cplusplus)
extern "C" {
#endif

#ifndef __has_attribute
    #define __has_attribute(x) 0
#endif /* __has_attribute */

#if !defined(OPENSSL_ALIGNED)
    #if __has_attribute(aligned)
        #define OPENSSL_ALIGNED(n) __attribute__((aligned(n)))
    #else
        #error "the compiler must support the `aligned` attribute"
    #endif
#endif /* OPENSSL_ALIGNED */

#if !defined(OPENSSL_DESIGNATED_INIT)
    #if __has_attribute(designated_init)
        #define OPENSSL_DESIGNATED_INIT __attribute__((designated_init))
    #else
        #define OPENSSL_DESIGNATED_INIT
    #endif
#endif /* OPENSSL_DESIGNATED_INIT */

#if !defined(OPENSSL_MUST_USE)
    #if __has_attribute(warn_unused_result)
        #define OPENSSL_MUST_USE __attribute__((warn_unused_result))
    #else
        #define OPENSSL_MUST_USE
    #endif
#endif /* OPENSSL_MUST_USE */

#if !defined(OPENSSL_NO_RETURN)
    #if __has_attribute(noreturn)
        #define OPENSSL_NO_RETURN __attribute__((noreturn))
    #else
        #define OPENSSL_NO_RETURN
    #endif
#endif /* OPENSSL_NO_RETURN */

#if !defined(OPENSSL_NON_NULL)
    #if defined(__gnu__)
        #if __has_attribute(nonnull)
            #define OPENSSL_NON_NULL __attribute__((nonnull))
        #endif
    #elif defined(__clang__)
        #define OPENSSL_NON_NULL _Nonnull
    #else
        #define OPENSSL_NON_NULL
    #endif
#endif /* OPENSSL_NON_NULL */

#if !defined(OPENSSL_PACKED)
    #if __has_attribute(packed)
        #define OPENSSL_PACKED __attribute__((packed))
    #else
        #define OPENSSL_PACKED
    #endif
#endif /* OPENSSL_PACKED */

#if defined(__cplusplus)
} // extern "C"
#endif

#endif // OPENSSL_HEADER_BASE_H
