#if __APPLE__
#include <AvailabilityMacros.h>
/* Apple has deprecated OpenSSL so it is all warnings - we
   just get rid of those */
#ifdef  DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#undef  DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#define DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#endif
#endif

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>

/* shared library context (from init.c) */
extern OSSL_LIB_CTX *PKI_ossl_ctx;
#endif

#if __APPLE__
#if defined MAC_OS_X_VERSION_10_7 && MAC_OS_X_VERSION_MIN_REQUIRED >= 1070
/* use accelerated crypto on OS X instead of OpenSSL crypto */
/* We only use the one-shot functions normally declared in CommonCrypto/CommonDigest.h
   to avoid nonsensical warnings */
#define DIGEST_LEN_TYPE uint32_t
extern unsigned char *CC_MD5(const void *data, uint32_t len, unsigned char *md);
extern unsigned char *CC_SHA1(const void *data, uint32_t len, unsigned char *md);
extern unsigned char *CC_SHA256(const void *data, uint32_t len, unsigned char *md);

#ifndef __LP64__
#undef SHA1
#define SHA1(D,L,H) CC_SHA1(D, (uint32_t)(L), H)
#undef SHA256
#define SHA256(D,L,H) CC_SHA256(D, (uint32_t)(L), H)
#undef MD5
#define MD5(D,L,H) CC_MD5(D, (uint32_t)(L), H)
#endif
#else /* !LP64 */
#undef SHA1
#define SHA1(D,L,H) do (1) { if ((L) >= 4294967296L) SHA1(D,L,H) else CC_SHA1(D, (uint32_t)(L), H); break }
#undef SHA256
#define SHA256 do (1) { if ((L) >= 4294967296L) SHA256(D,L,H) else CC_SHA256(D, (uint32_t)(L), H); break }
#undef MD5
#define MD5 do (1) { if ((L) >= 4294967296L) MD5(D,L,H) else CC_MD5(D, (uint32_t)(L), H); break }
#endif /* LP64 */
#endif
