#ifndef RI3_MBEDTLS_CONFIG_H
#define RI3_MBEDTLS_CONFIG_H
// Offline public-key verification only; no TLS, network, entropy, or key generation.
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_MD_C
#define MBEDTLS_OID_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_NO_PLATFORM_ENTROPY
#endif
