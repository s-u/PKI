#include "pki.h"
#include <string.h>

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

#define PKI_KT_PUBLIC  1
#define PKI_KT_PRIVATE 2

static SEXP wrap_EVP_PKEY(EVP_PKEY *key, int kt) {
    SEXP res = PROTECT(R_MakeExternalPtr(key, R_NilValue, R_NilValue));
    R_RegisterCFinalizerEx(res, PKI_free_EVP_PKEY, TRUE);
    if (kt == PKI_KT_PRIVATE || kt == PKI_KT_PUBLIC)
	setAttrib(res, R_ClassSymbol,
		  mkString((kt == PKI_KT_PUBLIC) ? "public.key" : "private.key"));
    else {
	SEXP cl = PROTECT(allocVector(STRSXP, 2));
	SET_STRING_ELT(cl, 0, mkChar("public.key"));
	SET_STRING_ELT(cl, 1, mkChar("private.key"));
	setAttrib(res, R_ClassSymbol, cl);
	UNPROTECT(1);
    }
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
    return wrap_EVP_PKEY(key, PKI_KT_PUBLIC);
}

static char buf[8192];

SEXP PKI_encrypt(SEXP what, SEXP sKey) {
    SEXP res;
    EVP_PKEY *key;
    RSA *rsa;
    int len;
    if (TYPEOF(what) != RAWSXP)
	Rf_error("invalid payload to sign - must be a raw vector");
    if (!inherits(sKey, "public.key"))
	Rf_error("invalid key object");
    key = (EVP_PKEY*) R_ExternalPtrAddr(sKey);
    if (!key)
	Rf_error("NULL key");
    if (EVP_PKEY_type(key->type) != EVP_PKEY_RSA)
	Rf_error("Sorry only RSA keys are supported at this point");
    rsa = EVP_PKEY_get1_RSA(key);
    if (!rsa)
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    len = RSA_public_encrypt(LENGTH(what), RAW(what), (unsigned char*) buf, rsa, RSA_PKCS1_PADDING);
    if (len < 0)
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    res = allocVector(RAWSXP, len);
    memcpy(RAW(res), buf, len);
    return res;
}

SEXP PKI_decrypt(SEXP what, SEXP sKey) {
    SEXP res;
    EVP_PKEY *key;
    RSA *rsa;
    int len;
    if (TYPEOF(what) != RAWSXP)
	Rf_error("invalid payload to sign - must be a raw vector");
    if (!inherits(sKey, "private.key"))
	Rf_error("invalid key object");
    key = (EVP_PKEY*) R_ExternalPtrAddr(sKey);
    if (!key)
	Rf_error("NULL key");
    if (EVP_PKEY_type(key->type) != EVP_PKEY_RSA)
	Rf_error("Sorry only RSA keys are supported at this point");
    rsa = EVP_PKEY_get1_RSA(key);
    if (!rsa)
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    len = RSA_private_decrypt(LENGTH(what), RAW(what), (unsigned char*) buf, rsa, RSA_PKCS1_PADDING);
    if (len < 0)
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    res = allocVector(RAWSXP, len);
    memcpy(RAW(res), buf, len);
    return res;
}

#define PKI_SHA1 1
#define PKI_MD5  2

SEXP PKI_digest(SEXP what, SEXP sMD) {
    SEXP res;
    unsigned char hash[32]; /* really, at most 20 bytes are needed */
    int len, md = asInteger(sMD);
    if (TYPEOF(what) != RAWSXP)
	Rf_error("what must be a raw vector");
    switch (md) {
    case PKI_SHA1:
	SHA1((const unsigned char*) RAW(what), LENGTH(what), hash);
	len = SHA_DIGEST_LENGTH;
	break;
    case PKI_MD5:
	MD5((const unsigned char*) RAW(what), LENGTH(what), hash);
	len = MD5_DIGEST_LENGTH;
	break;
    default:
	Rf_error("unsupported hash function");
	len = 0; /* dead code but needed to appease compilers */
    }
    res = allocVector(RAWSXP, len);
    memcpy(RAW(res), hash, len);
    return res;
}

SEXP PKI_sign_RSA(SEXP what, SEXP sMD, SEXP sKey) {
    SEXP res;
    int md = asInteger(sMD);
    EVP_PKEY *key;
    RSA *rsa;
    unsigned int siglen = sizeof(buf);
    if (md != PKI_MD5 && md != PKI_SHA1)
	Rf_error("unsupported hash type");
    if (TYPEOF(what) != RAWSXP ||
	(md == PKI_MD5 && LENGTH(what) != MD5_DIGEST_LENGTH) ||
	(md == PKI_SHA1 && LENGTH(what) != SHA_DIGEST_LENGTH))
	Rf_error("invalid hash");
    if (!inherits(sKey, "private.key"))
	Rf_error("key must be RSA private key");
    key = (EVP_PKEY*) R_ExternalPtrAddr(sKey);
    if (!key)
	Rf_error("NULL key");
    if (EVP_PKEY_type(key->type) != EVP_PKEY_RSA)
	Rf_error("key must be RSA private key");
    rsa = EVP_PKEY_get1_RSA(key);
    if (!rsa)
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    if (RSA_sign((md == PKI_MD5) ? NID_md5 : NID_sha1,
		 (const unsigned char*) RAW(what), LENGTH(what),
		 (unsigned char *) buf, &siglen, rsa) != 1)
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    res = allocVector(RAWSXP, siglen);
    memcpy(RAW(res), buf, siglen);
    return res;
}

SEXP PKI_verify_RSA(SEXP what, SEXP sMD, SEXP sKey, SEXP sig) {
    int md = asInteger(sMD);
    EVP_PKEY *key;
    RSA *rsa;
    if (md != PKI_MD5 && md != PKI_SHA1)
	Rf_error("unsupported hash type");
    if (TYPEOF(what) != RAWSXP ||
	(md == PKI_MD5 && LENGTH(what) != MD5_DIGEST_LENGTH) ||
	(md == PKI_SHA1 && LENGTH(what) != SHA_DIGEST_LENGTH))
	Rf_error("invalid hash");
    if (!inherits(sKey, "public.key"))
	Rf_error("key must be RSA public key");
    key = (EVP_PKEY*) R_ExternalPtrAddr(sKey);
    if (!key)
	Rf_error("NULL key");
    if (EVP_PKEY_type(key->type) != EVP_PKEY_RSA)
	Rf_error("key must be RSA public key");
    rsa = EVP_PKEY_get1_RSA(key);
    if (!rsa)
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    return
	ScalarLogical( /* FIXME: sig is not const in RSA_verify - that is odd so in theory in may modify sig ... */
		      (RSA_verify((md == PKI_MD5) ? NID_md5 : NID_sha1,
				  (const unsigned char*) RAW(what), LENGTH(what),
				  (unsigned char *) RAW(sig), LENGTH(sig), rsa) == 1)
		      ? TRUE : FALSE);
}

SEXP PKI_load_private_RSA(SEXP what) {
    EVP_PKEY *key;
    RSA *rsa = 0;
    const unsigned char *ptr;
    if (TYPEOF(what) != RAWSXP)
	Rf_error("key must be a raw vector");
    ptr = (const unsigned char *) RAW(what);
    rsa = d2i_RSAPrivateKey(&rsa, &ptr, LENGTH(what));
    if (!rsa)
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(key, rsa);
    return wrap_EVP_PKEY(key, PKI_KT_PRIVATE);
}

SEXP PKI_RSAkeygen(SEXP sBits) {
    EVP_PKEY *key;
    RSA *rsa;
    int bits = asInteger(sBits);
    if (bits < 512)
	Rf_error("invalid key size");
    rsa = RSA_generate_key(bits, 65537, 0, 0);
    if (!rsa)
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(key, rsa);
    return wrap_EVP_PKEY(key, PKI_KT_PRIVATE | PKI_KT_PUBLIC);
}

#if 0 /* FIXME: this requires openssl 1.0 or higher - not acceptable at this point */

#define PKI_MD5    1
#define PKI_SHA1   2
#define PKI_SHA256 3

#define PKI_PKCS1  1
/*#define PKI_ */

SEXP PKI_sign(SEXP what, SEXP sKey, SEXP sMD, SEXP sPad) {
    SEXP res;
    EVP_PKEY *key;
    EVP_PKEY_CTX *ctx;
    int mdt, padt, r;
    size_t sl;
    if (TYPEOF(what) != RAWSXP)
	Rf_error("invalid payload to sign - must be a raw vector");
    if (!inherits(sKey, "public.key"))
	Rf_error("invalid key object");
    mdt = asInteger(sMD);
    padt = asInteger(sPad);
    key = (EVP_PKEY*) R_ExternalPtrAddr(sKey);
    if (!key)
	Rf_error("NULL key");
    ctx = EVP_PKEY_CTX_new(key);
    if (!ctx || EVP_PKEY_sign_init(ctx) <= 0)
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    switch (padt) {
    case PKI_PKCS1:
    default:
	r = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    }
    if (r <= 0)
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    switch (mdt) {
    case PKI_MD5:
	r = EVP_PKEY_CTX_set_signature_md(ctx, EVP_md5()); break;
    case PKI_SHA1:
	r = EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha1()); break;
    default:
    case PKI_SHA256:
	r = EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()); break;
    }	
    if (r <= 0)
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    sl = sizeof(buf);
    if (EVP_PKEY_sign(ctx, buf, &sl, (const unsigned char*) RAW(what), LENGTH(what)) <= 0)
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    res = allocVector(RAWSXP, sl);
    memcpy(RAW(res), buf, sl);
    EVP_PKEY_CTX_free(ctx);
    return res;
}

#endif
