#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#define USE_RINTERNALS 1
#include <Rinternals.h>

/* from init.c */
void PKI_init();

static void PKI_free_X509(SEXP ref) {
    X509 *x509 = (X509*) R_ExternalPtrAddr(ref);
    if (x509)
	X509_free(x509);
}

static void PKI_free_EVP_PKEY(SEXP ref) {
    EVP_PKEY *key = (EVP_PKEY*) R_ExternalPtrAddr(ref);
    if (key)
	EVP_PKEY_free(key);
}

SEXP PKI_load_DER_X509(SEXP what) {
    SEXP res, ia;
    const unsigned char *ptr;
    X509 *x509 = 0;
    if (TYPEOF(what) != RAWSXP)
	Rf_error("what must be a raw vector containing the DER-encoded certificate");
    ptr = (const unsigned char*) RAW(what);
    PKI_init();
    x509 = d2i_X509(&x509, &ptr, LENGTH(what));
    if (!x509)
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    res = PROTECT(R_MakeExternalPtr(x509, R_NilValue, R_NilValue));
    R_RegisterCFinalizerEx(res, PKI_free_X509, TRUE);
    setAttrib(res, install("class"), mkString("X509cert"));
    /* we add the content to the cert in case someone tries to serialize it */
    ia = install("crt.DER");
    setAttrib(res, ia, what);
    UNPROTECT(1);
    return res;
}

/* c_name is solely for error messages */
static X509 *retrieve_cert(SEXP obj, const char *c_name) {
    X509 *cacrt;
    if (!inherits(obj, "X509cert"))
	Rf_error("invalid %scertificate object", c_name);
    cacrt = (X509*) R_ExternalPtrAddr(obj);
    if (!cacrt) { /* check if this is NULL because it has been restored from serialization */
	SEXP der = getAttrib(obj, install("crt.DER"));
	if (TYPEOF(der) == RAWSXP) {
	    const unsigned char *ptr = (const unsigned char*) RAW(der);
	    cacrt = d2i_X509(&cacrt, &ptr, LENGTH(der));
	    if (!cacrt)
		Rf_warning("Attempt to load NULL %scertificate with invalid crt.DER content", c_name);
	    else {
		/* there is no SETPTR so have have to use SETCAR */
		SETCAR(obj, (SEXP) cacrt);
		R_RegisterCFinalizerEx(obj, PKI_free_X509, TRUE);
	    }
	}
    }
    if (!cacrt)
	Rf_error("invalid %scertificate (NULL)", c_name);
    return cacrt;
}

SEXP PKI_verify_cert(SEXP sCA, SEXP sCert) {
    X509 *cert;
    X509_STORE *store;
    X509_STORE_CTX *ctx;
    int rv;
    PKI_init();
    cert = retrieve_cert(sCert, "");
    store = X509_STORE_new();
    if (TYPEOF(sCA) == VECSXP) {
	int i;
	for (i = 0; i < LENGTH(sCA); i++)
	    X509_STORE_add_cert(store, retrieve_cert(VECTOR_ELT(sCA, i),"CA "));
    } else
	X509_STORE_add_cert(store, retrieve_cert(sCA, "CA "));
    ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, NULL);
    rv = X509_verify_cert(ctx);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return ScalarLogical((rv == 1) ? TRUE : FALSE);
}

static SEXP wrap_EVP_PKEY(EVP_PKEY *key) {
    SEXP res = PROTECT(R_MakeExternalPtr(key, R_NilValue, R_NilValue));
    R_RegisterCFinalizerEx(res, PKI_free_EVP_PKEY, TRUE);
    setAttrib(res, install("class"), mkString("public.key"));
    /* FIXME: we don't have non-external payload for serialization */
    UNPROTECT(1);
    return res;
}

SEXP PKI_cert_public_key(SEXP sCert) {
    X509 *cert;
    EVP_PKEY *key;
    PKI_init();
    cert = retrieve_cert(sCert, "");
    key = X509_get_pubkey(cert);
    if (!key)
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    return wrap_EVP_PKEY(key);
}
