#include "pki.h"

static int ssl_needs_init = 1;

void PKI_init() {
    if (ssl_needs_init) {
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	ssl_needs_init = 0;
    }
}
