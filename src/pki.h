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
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#if __APPLE__
#if defined MAC_OS_X_VERSION_10_7 && MAC_OS_X_VERSION_MIN_REQUIRED >= 1070
/* use accelerated crypto on OS X instead of OpenSSL crypto */
#include <CommonCrypto/CommonDigest.h>
#undef SHA1
#define SHA1 CC_SHA1
#undef SHA256
#define SHA256 CC_SHA256
#undef MD5
#define MD5 CC_MD5
#endif
#endif
