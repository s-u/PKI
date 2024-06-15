#include "pki.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define USE_RINTERNALS 1
#include <Rinternals.h>

/* NOTE: we use d2i_RSAPrivateKey but s2i_RSA_PUBKEY (instead of
         s2i_RSAPublicKey) because that is what OpenSSL uses as
	 well. PUBKEY is on X509 SubjectPublicKeyInfo format
	 while RSAPublicKey is in PKCS#1 format. The difference
	 in PEM files is "PUBLIC KEY" for X509 and
	 "RSA PUBLIC KEY" for the other. Note that OpenSSL on
	 the command line doesn't even support loading PEM
	 with RSA PUBLIC KEY, that's why we don't even offer it
	 as an option. */

/* from init.c */
void PKI_init(void);

/* OpenSSL 1.1 has changed APIs - adapt accordingly */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EVP_PKEY_get_key_type_(X) EVP_PKEY_type((X)->type)
#else
#define EVP_PKEY_get_key_type_(X) EVP_PKEY_base_id(X)
#endif

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
    setAttrib(res, R_ClassSymbol, PROTECT(mkString("X509cert")));
    /* we add the content to the cert in case someone tries to serialize it */
    ia = PROTECT(install("crt.DER"));
    setAttrib(res, ia, what);
    UNPROTECT(3);
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

SEXP PKI_verify_cert(SEXP sCA, SEXP sCert, SEXP sDefault, SEXP sPart) {
    X509 *cert;
    X509_STORE *store;
    X509_STORE_CTX *ctx;
    int rv;
    PKI_init();
    cert = retrieve_cert(sCert, "");
    store = X509_STORE_new();

    if (Rf_asInteger(sDefault) > 0)
	X509_STORE_set_default_paths(store);

    /* highly recommended (and default since OpenSSL 1.1.0) to avoid
       breakage of chains like the famous Let's Encrypt 2021 sanfu
       or Sectigo */
#ifdef X509_V_FLAG_TRUSTED_FIRST
    X509_STORE_set_flags(store, X509_V_FLAG_TRUSTED_FIRST);
#endif

#ifdef X509_V_FLAG_PARTIAL_CHAIN
    if (Rf_asInteger(sPart) > 0)
	X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN);
#endif

    if (TYPEOF(sCA) == VECSXP) {
	int i;
	for (i = 0; i < LENGTH(sCA); i++)
	    X509_STORE_add_cert(store, retrieve_cert(VECTOR_ELT(sCA, i),"CA "));
    } else if (sCA != R_NilValue)
	X509_STORE_add_cert(store, retrieve_cert(sCA, "CA "));

    ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, NULL);
    rv = X509_verify_cert(ctx);

#if 0 /* we could print of even return the chain, this is how ... */
    {
	int j;

	STACK_OF(X509) *chain = X509_STORE_CTX_get1_chain(ctx);
	int num_untrusted = X509_STORE_CTX_get_num_untrusted(ctx);
	Rprintf("Chain:\n");
	for (j = 0; j < sk_X509_num(chain); j++) {
	    X509 *cert = sk_X509_value(chain, j);
	    X509_NAME *sname = X509_get_subject_name(cert);
	    char buf[256];
	    Rprintf("depth=%d: %s", j, X509_NAME_oneline(sname, buf, sizeof(buf) - 1));
	    if (j < num_untrusted)
		Rprintf(" (untrusted)");
	    Rprintf("\n");
	}
	sk_X509_pop_free(chain, X509_free);
    }
#endif

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

SEXP PKI_extract_key(SEXP sKey, SEXP sPriv) {
    SEXP res;
    EVP_PKEY *key;
    RSA *rsa;
    int get_priv = asInteger(sPriv), len;
    if (!inherits(sKey, "public.key") && !inherits(sKey, "private.key"))
	Rf_error("invalid key object");
    if (get_priv == NA_INTEGER)
	get_priv = inherits(sKey, "private.key");
    if (get_priv && !inherits(sKey, "private.key"))
	return R_NilValue;
    key = (EVP_PKEY*) R_ExternalPtrAddr(sKey);
    if (!key)
	Rf_error("NULL key");
    PKI_init();
    if (EVP_PKEY_get_key_type_(key) != EVP_PKEY_RSA)
	Rf_error("Sorry only RSA keys are supported at this point");
    rsa = EVP_PKEY_get1_RSA(key);
    if (get_priv) {
	unsigned char *ptr;
	len = i2d_RSAPrivateKey(rsa, 0);
	if (len < 1)
	    Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
	res = allocVector(RAWSXP, len);
	ptr = (unsigned char*) RAW(res);
	len = i2d_RSAPrivateKey(rsa, &ptr);
	if (len < 1)
	    Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
	PROTECT(res);
	setAttrib(res, R_ClassSymbol, mkString("private.key.DER"));
	UNPROTECT(1);
    } else {
	unsigned char *ptr;
	len = i2d_RSA_PUBKEY(rsa, 0);
	if (len < 1)
	    Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
	res = allocVector(RAWSXP, len);
	ptr = (unsigned char*) RAW(res);
	len = i2d_RSA_PUBKEY(rsa, &ptr);
	if (len < 1)
	    Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
	PROTECT(res);
	setAttrib(res, R_ClassSymbol, mkString("public.key.DER"));
	UNPROTECT(1);
    }
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

static char cipher_name[32];

static EVP_CIPHER_CTX *get_cipher(SEXP sKey, SEXP sCipher, int enc, int *transient, SEXP sIV) {
    EVP_CIPHER_CTX *ctx;
    PKI_init();

    if (inherits(sKey, "symmeric.cipher")) {
	if (transient) transient[0] = 0;
	return (EVP_CIPHER_CTX*) R_ExternalPtrAddr(sCipher);
    }	
    if (TYPEOF(sKey) != RAWSXP && (TYPEOF(sKey) != STRSXP || LENGTH(sKey) < 1))
	Rf_error("invalid key object");
    else {
	const char *cipher, *c_key, *c_iv = 0;
	size_t key_len;
	const EVP_CIPHER *type;
	if (TYPEOF(sCipher) != STRSXP || LENGTH(sCipher) != 1)
	    Rf_error("non-RSA key and no cipher is specified");
	cipher = CHAR(STRING_ELT(sCipher, 0));
	if (strlen(cipher) > sizeof(cipher_name) - 1)
	    Rf_error("invalid cipher name");
	{
	    char *c = cipher_name;
	    while (*cipher) {
		if ((*cipher >= 'a' && *cipher <= 'z') || (*cipher >= '0' && *cipher <= '9'))
		    *(c++) = *cipher;
		else if (*cipher >= 'A' && *cipher <= 'Z')
		    *(c++) = *cipher + 32;
		cipher++;
	    }
	    *c = 0;
	    cipher = (const char*) cipher_name;
	}
	if (!strcmp(cipher, "aes128") || !strcmp(cipher, "aes128cbc"))
	    type = EVP_aes_128_cbc();
	else if (!strcmp(cipher, "aes128ecb"))
	    type = EVP_aes_128_ecb();
	else if (!strcmp(cipher, "aes128ofb"))
	    type = EVP_aes_128_ofb();
	else if (!strcmp(cipher, "aes256") || !strcmp(cipher, "aes256cbc"))
	    type = EVP_aes_256_cbc();
	else if (!strcmp(cipher, "aes256ecb"))
	    type = EVP_aes_256_ecb();
	else if (!strcmp(cipher, "aes256ofb"))
	    type = EVP_aes_256_ofb();
	else if (!strcmp(cipher, "blowfish") || !strcmp(cipher, "bfcbc"))
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	    type = EVP_CIPHER_fetch(PKI_ossl_ctx, "BF-CBC", NULL);
#else
	    type = EVP_bf_cbc();
#endif
	else if (!strcmp(cipher, "bfecb"))
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	    type = EVP_CIPHER_fetch(PKI_ossl_ctx, "BF-ECB", NULL);
#else
	    type = EVP_bf_ecb();
#endif
	else if (!strcmp(cipher, "bfofb"))
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	    type = EVP_CIPHER_fetch(PKI_ossl_ctx, "BF-OFB", NULL);
#else
	    type = EVP_bf_ofb();
#endif
	else if (!strcmp(cipher, "bfcfb"))
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	    type = EVP_CIPHER_fetch(PKI_ossl_ctx, "BF-CFB", NULL);
#else
	    type = EVP_bf_cfb();
#endif
	else Rf_error("unknown cipher `%s'", CHAR(STRING_ELT(sCipher, 0)));

	if (TYPEOF(sIV) == STRSXP) {
	    if (LENGTH(sIV) != 1)
		Rf_error("invalid IV - if used must be a string (or raw), but is string vector of length %d", (int) LENGTH(sIV));
	    c_iv = CHAR(STRING_ELT(sIV, 0));
	    size_t req_len = (size_t) EVP_CIPHER_iv_length(type);
	    size_t iv_len = strlen(c_iv);
	    if (iv_len < req_len)
		Rf_error("insufficient IV - must be %u bytes long", (unsigned int) req_len);
	} else if (TYPEOF(sIV) == RAWSXP) {
	    c_iv = (const char *) RAW(sIV);
	    size_t req_len = (size_t) EVP_CIPHER_iv_length(type);
	    if (((size_t) LENGTH(sIV)) < req_len)
		Rf_error("insufficient IV - must be %u bytes long", (unsigned int) req_len);
	} else if (sIV != R_NilValue)
	    Rf_error("invalid IV - must be NULL (no/empty IV), a string or a raw vector of sufficient length for the cipher");

	if (TYPEOF(sKey) == STRSXP) {
	    c_key = CHAR(STRING_ELT(sKey, 0));
	    key_len = strlen(c_key);
	} else {
	    c_key = (const char*) RAW(sKey);
	    key_len = (size_t) LENGTH(sKey);
	}
	if (key_len < (size_t) EVP_CIPHER_key_length(type))
	    Rf_error("key is too short (%u bytes) for the cipher - need %d bytes",
		     (unsigned int) key_len, (int) EVP_CIPHER_key_length(type));
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
	    Rf_error("cannot allocate memory for cipher");
	if (!EVP_CipherInit(ctx, type, (unsigned char*) c_key, (unsigned char *) c_iv, enc)) {
	    EVP_CIPHER_CTX_free(ctx);
	    Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
	}
	if (transient) transient[0] = 1;
	return ctx;
    }
}

#if 0
static void PKI_free_cipher(SEXP sCipher) {
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*) R_ExternalPtrAddr(sCipher);
    if (ctx)
	EVP_CIPHER_CTX_free(ctx);
}

/* FIXME: this is exposed as C symbol but not actually used anywhere ... ?!? */
/* it is not longer registered anyway ... */
SEXP PKI_sym_cipher(SEXP sKey, SEXP sCipher, SEXP sEncrypt, SEXP sIV) {
    SEXP res;
    int transient_cipher = 0;
    int do_enc = (asInteger(sEncrypt) != 0) ? 1 : 0;
    EVP_CIPHER_CTX *ctx = get_cipher(sKey, sCipher, do_enc, &transient_cipher, sIV);
    if (!transient_cipher)
	return sCipher;
    res = PROTECT(R_MakeExternalPtr(ctx, R_NilValue, R_NilValue));
    R_RegisterCFinalizerEx(res, PKI_free_cipher, TRUE);
    setAttrib(res, R_ClassSymbol, PROTECT(mkString("symmetric.cipher")));
    UNPROTECT(2);
    return res;
}
#endif

SEXP PKI_encrypt(SEXP what, SEXP sKey, SEXP sCipher, SEXP sIV) {
    SEXP res;
    EVP_PKEY *key;
    RSA *rsa;
    int len;
    if (TYPEOF(what) != RAWSXP)
	Rf_error("invalid payload to sign - must be a raw vector");
    if (!inherits(sKey, "public.key") && !inherits(sKey, "private.key")) {
	int transient_cipher = 0;
	EVP_CIPHER_CTX *ctx = get_cipher(sKey, sCipher, 1, &transient_cipher, sIV);
	int block_len = EVP_CIPHER_CTX_block_size(ctx);
	int padding = LENGTH(what) % block_len;
	/* Note: padding is always required, so if the last block is full, there
	   must be an extra block added at the end */
	padding = block_len - padding;
	/* FIXME: ctx will leak on alloc errors for transient ciphers - wrap them first */
	res = allocVector(RAWSXP, len = (LENGTH(what) + padding));
	if (!EVP_CipherUpdate(ctx, RAW(res), &len, RAW(what), LENGTH(what))) {
	    if (transient_cipher) {
		EVP_CIPHER_CTX_cleanup(ctx);
		free(ctx);
	    }
	    Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
	}
	if (len < LENGTH(res))
	    EVP_CipherFinal(ctx, RAW(res) + len, &len);
	if (transient_cipher) {
	    EVP_CIPHER_CTX_cleanup(ctx);
	    free(ctx);
	}
	return res;
    }

    key = (EVP_PKEY*) R_ExternalPtrAddr(sKey);
    if (!key)
	Rf_error("NULL key");
    if (EVP_PKEY_get_key_type_(key) != EVP_PKEY_RSA)
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

SEXP PKI_decrypt(SEXP what, SEXP sKey, SEXP sCipher, SEXP sIV) {
    SEXP res;
    EVP_PKEY *key;
    RSA *rsa;
    int len;
    if (TYPEOF(what) != RAWSXP)
	Rf_error("invalid payload to sign - must be a raw vector");
    PKI_init();
    if (!inherits(sKey, "private.key")) {
	int transient_cipher = 0, fin = 0;
	EVP_CIPHER_CTX *ctx = get_cipher(sKey, sCipher, 0, &transient_cipher, sIV);
	/* FIXME: ctx will leak on alloc errors for transient ciphers - wrap them first */
	res = allocVector(RAWSXP, len = LENGTH(what));
	if (!EVP_CipherUpdate(ctx, RAW(res), &len, RAW(what), LENGTH(what))) {
	    if (transient_cipher) {
		EVP_CIPHER_CTX_cleanup(ctx);
		free(ctx);
	    }
	    Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
	}
	if (EVP_CipherFinal(ctx, RAW(res) + len, &fin))
	    len += fin;
	if (len < LENGTH(res)) {
	    SEXP res2;
	    PROTECT(res);
	    res2 = allocVector(RAWSXP, len);
	    memcpy(RAW(res2), RAW(res), len);
	    res = res2;
	    UNPROTECT(1);
	}
	if (transient_cipher) {
	    EVP_CIPHER_CTX_cleanup(ctx);
	    free(ctx);
	}
	return res;
    }
    key = (EVP_PKEY*) R_ExternalPtrAddr(sKey);
    if (!key)
	Rf_error("NULL key");
    if (EVP_PKEY_get_key_type_(key) != EVP_PKEY_RSA)
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
#define PKI_SHA256 2
#define PKI_MD5  3

SEXP PKI_digest(SEXP sWhat, SEXP sMD) {
    SEXP res;
    unsigned char hash[32]; /* really, at most 20 bytes are needed */
    size_t len, what_len;
    int md = asInteger(sMD);
    const unsigned char *what;

    PKI_init();
    if (TYPEOF(sWhat) == RAWSXP) {
	what = (const unsigned char*) RAW(sWhat);
	what_len = (size_t) XLENGTH(sWhat);
    } else if (TYPEOF(sWhat) == STRSXP) {
	if (LENGTH(sWhat) < 1) return allocVector(RAWSXP, 0); /* good? */
	what = (const unsigned char*) CHAR(STRING_ELT(sWhat, 0));
	what_len = strlen((const char*) what);
    } else
	Rf_error("what must be a string or a raw vector");
    switch (md) {
    case PKI_SHA1:
	SHA1(what, what_len, hash);
	len = SHA_DIGEST_LENGTH;
	break;
    case PKI_SHA256:
	SHA256(what, what_len, hash);
	len = SHA256_DIGEST_LENGTH;
	break;
    case PKI_MD5:
	MD5(what, what_len, hash);
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
    int md = asInteger(sMD), type;
    EVP_PKEY *key;
    RSA *rsa;
    unsigned int siglen = sizeof(buf);
  switch (md) {
    case PKI_MD5:
      type = NID_md5;
      break;
    case PKI_SHA1:
      type = NID_sha1;
      break;
    case PKI_SHA256:
      type = NID_sha256;
      break;
    default:
      Rf_error("unsupported hash type");
  }
    if (TYPEOF(what) != RAWSXP ||
	(md == PKI_MD5 && LENGTH(what) != MD5_DIGEST_LENGTH) ||
	(md == PKI_SHA1 && LENGTH(what) != SHA_DIGEST_LENGTH) ||
  (md == PKI_SHA256 && LENGTH(what) != SHA256_DIGEST_LENGTH))
	Rf_error("invalid hash");
    if (!inherits(sKey, "private.key"))
	Rf_error("key must be RSA private key");
    key = (EVP_PKEY*) R_ExternalPtrAddr(sKey);
    if (!key)
	Rf_error("NULL key");
    PKI_init();
    if (EVP_PKEY_get_key_type_(key) != EVP_PKEY_RSA)
	Rf_error("key must be RSA private key");
    rsa = EVP_PKEY_get1_RSA(key);
    if (!rsa)
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    if (RSA_sign(type,
		 (const unsigned char*) RAW(what), LENGTH(what),
		 (unsigned char *) buf, &siglen, rsa) != 1)
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    res = allocVector(RAWSXP, siglen);
    memcpy(RAW(res), buf, siglen);
    return res;
}

SEXP PKI_verify_RSA(SEXP what, SEXP sMD, SEXP sKey, SEXP sig) {
    int md = asInteger(sMD), type;
    EVP_PKEY *key;
    RSA *rsa;
    switch (md) {
    case PKI_MD5:
  type = NID_md5;
  break;
    case PKI_SHA1:
  type = NID_sha1;
  break;
    case PKI_SHA256:
  type = NID_sha256;
  break;
    default:
  Rf_error("unsupported hash type");
  }
    if (TYPEOF(what) != RAWSXP ||
  (md == PKI_MD5 && LENGTH(what) != MD5_DIGEST_LENGTH) ||
  (md == PKI_SHA1 && LENGTH(what) != SHA_DIGEST_LENGTH) ||
  (md == PKI_SHA256 && LENGTH(what) != SHA256_DIGEST_LENGTH))
	Rf_error("invalid hash");
    if (!inherits(sKey, "public.key") && !inherits(sKey, "private.key"))
	Rf_error("key must be RSA public or private key");
    key = (EVP_PKEY*) R_ExternalPtrAddr(sKey);
    if (!key)
	Rf_error("NULL key");
    if (EVP_PKEY_get_key_type_(key) != EVP_PKEY_RSA)
	Rf_error("key must be RSA public or private key");
    rsa = EVP_PKEY_get1_RSA(key);
    if (!rsa)
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    return
	ScalarLogical( /* FIXME: sig is not const in RSA_verify - that is odd so in theory in may modify sig ... */
		      (RSA_verify(type,
				  (const unsigned char*) RAW(what), LENGTH(what),
				  (unsigned char *) RAW(sig), LENGTH(sig), rsa) == 1)
		      ? TRUE : FALSE);
}

SEXP PKI_load_private_RSA(SEXP what, SEXP sPassword) {
    EVP_PKEY *key = 0;
    BIO *bio_mem;
    if (TYPEOF(sPassword) != STRSXP || LENGTH(sPassword) != 1)
	Rf_error("Password must be a string");
    PKI_init();
    if (TYPEOF(what) == RAWSXP) { /* assuming binary DER format */
	RSA *rsa = 0;
	const unsigned char *ptr;
	ptr = (const unsigned char *) RAW(what);
	rsa = d2i_RSAPrivateKey(&rsa, &ptr, LENGTH(what));
	if (!rsa)
	    Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
	key = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(key, rsa);
    } else if (TYPEOF(what) == STRSXP && LENGTH(what)) {
	SEXP b64Key = STRING_ELT(what, 0);
	bio_mem = BIO_new_mem_buf((void *) CHAR(b64Key), -1);
	key = PEM_read_bio_PrivateKey(bio_mem, 0, 0, (void*) CHAR(STRING_ELT(sPassword, 0)));
	BIO_free(bio_mem);
	if (!key)
	    Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    } else
	Rf_error("Private key must be a character or raw vector");

    return wrap_EVP_PKEY(key, PKI_KT_PRIVATE);
}

SEXP PKI_load_public_RSA(SEXP what) {
    EVP_PKEY *key;
    RSA *rsa = 0;
    const unsigned char *ptr;
    if (TYPEOF(what) != RAWSXP)
	Rf_error("key must be a raw vector");
    PKI_init();
    ptr = (const unsigned char *) RAW(what);
    rsa = d2i_RSA_PUBKEY(&rsa, &ptr, LENGTH(what));
    if (!rsa)
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(key, rsa);
    return wrap_EVP_PKEY(key, PKI_KT_PUBLIC);
}

SEXP PKI_RSAkeygen(SEXP sBits) {
    EVP_PKEY *key;
    RSA *rsa;
    int bits = asInteger(sBits);
    if (bits < 512)
	Rf_error("invalid key size");
    PKI_init();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    rsa = RSA_generate_key(bits, 65537, 0, 0);
    if (!rsa)
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
#else  /* How to make simple things really complicated ... */
    rsa = RSA_new();
    if (!rsa)
	Rf_error("cannot allocate RSA key: %s", ERR_error_string(ERR_get_error(), NULL));
    {
        BIGNUM *e = BN_new();
	if (!e) {
            RSA_free(rsa);
	    Rf_error("cannot allocate exponent: %s", ERR_error_string(ERR_get_error(), NULL));
        }
	BN_set_word(e, 65537);
	if (RSA_generate_key_ex(rsa, bits, e, NULL) <= 0) {
            BN_free(e);
	    RSA_free(rsa);
	    Rf_error("cannot generate key: %s", ERR_error_string(ERR_get_error(), NULL));
        }
	BN_free(e);
    }
#endif

    key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(key, rsa);
    return wrap_EVP_PKEY(key, PKI_KT_PRIVATE | PKI_KT_PUBLIC);
}

SEXP PKI_random(SEXP sBytes) {
    int len = asInteger(sBytes);
    SEXP res;
    if (len < 0)
	Rf_error("invalid number of bytes requested - must be 0 .. 2^32-1");
    res = allocVector(RAWSXP, len);
    PKI_init();
    if (!RAND_bytes((unsigned char*) RAW(res), len))
	Rf_error("%s", ERR_error_string(ERR_get_error(), NULL));
    return res;
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
    if (!inherits(sKey, "private.key"))
	Rf_error("key must be RSA private key");
    PKI_init();
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

/* Return the Subject of an X509 Certificate by wrapping the OpenSSL X509_get_subject_name() function. */
SEXP PKI_get_subject(SEXP sCert) {
    SEXP res;
    X509 *cert;
    BIO  *mem = BIO_new(BIO_s_mem());
    long len;
    char *txt = 0;
    PKI_init();
    cert = retrieve_cert(sCert, "");
    if (X509_NAME_print_ex(mem, X509_get_subject_name(cert), 0, (XN_FLAG_ONELINE | ASN1_STRFLGS_UTF8_CONVERT) & ~ASN1_STRFLGS_ESC_MSB) < 0) {
	BIO_free(mem);
	Rf_error("X509_NAME_print_ex failed with %s", ERR_error_string(ERR_get_error(), NULL));
    }
    len = BIO_get_mem_data(mem, &txt);
    if (len < 0 || len > 2147483646) {
	BIO_free(mem);
	Rf_error("cannot get memory buffer, %s", ERR_error_string(ERR_get_error(), NULL));
    }
    res = PROTECT(allocVector(STRSXP, 1));
    SET_STRING_ELT(res, 0, mkCharLenCE(txt, (int) len, CE_UTF8));
    UNPROTECT(1);
    BIO_free(mem);
    return res;
}

#include <time.h>

static char cibuf[512];

static double ASN1_TIME2d(const ASN1_TIME* time) {
    int pday, psec;
    ASN1_TIME *epoch;
    double d;

#if OPENSSL_VERSION_NUMBER < 0x10002000L
    Rf_warning("OpenSSL is too old and does not support ASN1 time differences");
    return NA_REAL;
#else
    epoch = ASN1_TIME_set(0, 0);
    ASN1_TIME_diff(&pday, &psec, epoch, time);
    ASN1_STRING_free(epoch);

    d = (double) pday;
    d *= 86400.0;
    d += (double) psec;
    return d;
#endif
}

SEXP PKI_get_cert_info(SEXP sCert) {
#define FPLEN 20 /* size of the fingerprint - here SHA1 */
    const EVP_MD *digest = EVP_sha1();
    SEXP res = PROTECT(Rf_allocVector(VECSXP, 5));
    int rc;
    unsigned len;
    X509 *cert;
    double *ts;
    PKI_init();
    cert = retrieve_cert(sCert, "");
    cibuf[sizeof(cibuf) - 1] = 0;
    *cibuf = 0;
    X509_NAME_oneline(X509_get_subject_name(cert), cibuf, sizeof(cibuf) - 1);
    SET_VECTOR_ELT(res, 0, Rf_mkString(cibuf));
    X509_NAME_oneline(X509_get_issuer_name(cert), cibuf, sizeof(cibuf) - 1);
    SET_VECTOR_ELT(res, 1, Rf_mkString(cibuf));

    len = FPLEN;
    rc = X509_digest(cert, digest, (unsigned char*) cibuf, &len);
    if (rc && len == FPLEN) {
	SEXP sFP;
	SET_VECTOR_ELT(res, 2, (sFP = allocVector(RAWSXP, len)));
	memcpy(RAW(sFP), cibuf, len);
    }

    ts = REAL(SET_VECTOR_ELT(res, 3, Rf_allocVector(REALSXP, 2)));
    ts[0] = ASN1_TIME2d(X509_get_notBefore(cert));
    ts[1] = ASN1_TIME2d(X509_get_notAfter(cert));

    SET_VECTOR_ELT(res, 4, Rf_ScalarLogical(X509_check_ca(cert)));
    UNPROTECT(1);
    return res;
}

/* NOTE: we are intentionally not using macros since thay may not match the
         actual run-time version. The only exception is OPENSSL_VERSION_TEXT
	 where we have no other choice */
SEXP PKI_engine_info(void) {
    char sver[48];
    const char *names[] = { "engine", "version", "description", "" };
    SEXP res = PROTECT(mkNamed(VECSXP, names));
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    unsigned long ver = OpenSSL_version_num();
#else
    unsigned long ver = OPENSSL_VERSION_NUMBER;
#endif
#ifdef LIBRESSL_VERSION_NUMBER
    SET_VECTOR_ELT(res, 0, mkString("libressl"));
#else
    SET_VECTOR_ELT(res, 0, mkString("openssl"));
#endif
    sver[sizeof(sver) - 1] = 0;
    snprintf(sver, sizeof(sver) - 1, "%u.%u", (unsigned int) (ver >> 28), (unsigned int) ((ver >> 20) & 255));
    SET_VECTOR_ELT(res, 1, ScalarReal(atof(sver)));
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    SET_VECTOR_ELT(res, 2, mkString(OpenSSL_version(OPENSSL_FULL_VERSION_STRING)));
#else
#   ifdef OPENSSL_VERSION_TEXT
    SET_VECTOR_ELT(res, 2, mkString(OPENSSL_VERSION_TEXT));
#   else
    snprintf(sver, sizeof(sver) - 1, "%s %d.%d.%d%c",
#      ifdef LIBRESSL_VERSION_NUMBER
	     "LibreSSL",
#      else
	     "OpenSSL",
#      endif
	     (unsigned int) (ver >> 28), (unsigned int) ((ver >> 20) & 255),
	     (unsigned int) ((ver >> 12) & 255), (char) (((ver >> 8) & 31) + 0x60));
    SET_VECTOR_ELT(res, 2, mkString(sver));
#   endif
#endif
    UNPROTECT(1);
    return res;
}
