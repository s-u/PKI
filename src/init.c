#include "pki.h"

static int ssl_needs_init = 1;

/* in OpenSSL 3.x we may need to load the legacy provider
   for ciphers like Blowfish */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
OSSL_LIB_CTX *PKI_ossl_ctx = NULL;
static OSSL_PROVIDER *legacy_provider = NULL;
static OSSL_PROVIDER *default_provider = NULL;
#endif

void PKI_init(void) {
    if (ssl_needs_init) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
#else
	OPENSSL_init_ssl(0, 0); /* defaults correspond to the above */
#endif
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (!PKI_ossl_ctx)
	    PKI_ossl_ctx = OSSL_LIB_CTX_new();
	if (PKI_ossl_ctx) {
	    if (!legacy_provider)
		legacy_provider = OSSL_PROVIDER_load(PKI_ossl_ctx, "legacy");
	    if (!default_provider)
		default_provider = OSSL_PROVIDER_load(PKI_ossl_ctx, "default");
	}
#endif

	ssl_needs_init = 0;
    }
}
