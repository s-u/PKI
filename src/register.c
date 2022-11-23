#include <R.h>
#include <Rinternals.h>
#include <stdlib.h> // for NULL
#include <R_ext/Rdynload.h>

/* .Call calls */
extern SEXP decode_ASN1(SEXP sWhat);
extern SEXP encode_ASN1(SEXP sWhat);
extern SEXP PKI_asBIGNUMint(SEXP sWhat, SEXP sScalar);
extern SEXP PKI_load_DER_X509(SEXP what);
extern SEXP PKI_verify_cert(SEXP sCA, SEXP sCert, SEXP sDefault, SEXP sPart);
extern SEXP PKI_extract_key(SEXP sKey, SEXP sPriv);
extern SEXP PKI_cert_public_key(SEXP sCert);
extern SEXP PKI_encrypt(SEXP what, SEXP sKey, SEXP sCipher, SEXP sIV);
extern SEXP PKI_decrypt(SEXP what, SEXP sKey, SEXP sCipher, SEXP sIV);
extern SEXP PKI_digest(SEXP sWhat, SEXP sMD);
extern SEXP PKI_sign_RSA(SEXP what, SEXP sMD, SEXP sKey);
extern SEXP PKI_verify_RSA(SEXP what, SEXP sMD, SEXP sKey, SEXP sig);
extern SEXP PKI_load_private_RSA(SEXP what, SEXP sPassword);
extern SEXP PKI_load_public_RSA(SEXP what);
extern SEXP PKI_int2oid(SEXP sVal);
extern SEXP PKI_oid2int(SEXP sVal);
extern SEXP PKI_RSAkeygen(SEXP sBits);
extern SEXP PKI_random(SEXP sBytes);
extern SEXP PKI_sign(SEXP what, SEXP sKey, SEXP sMD, SEXP sPad);
extern SEXP PKI_get_subject(SEXP sCert);
extern SEXP PKI_get_cert_info(SEXP sCert);
extern SEXP PKI_raw2hex(SEXP sRaw, SEXP sSep, SEXP sUpp);
extern SEXP PKI_parse_pgp_key(SEXP sWhat, SEXP sRaw);
extern SEXP PKI_PEM_split(SEXP sWhat);
extern SEXP PKI_PEM_part(SEXP sWhat, SEXP sBody, SEXP sDecode);
extern SEXP PKI_engine_info(void);

static const R_CallMethodDef CallEntries[] = {
    {"PKI_RSAkeygen",        (DL_FUNC) &PKI_RSAkeygen,        1},
    {"PKI_asBIGNUMint",      (DL_FUNC) &PKI_asBIGNUMint,      2},
    {"PKI_cert_public_key",  (DL_FUNC) &PKI_cert_public_key,  1},
    {"PKI_decrypt",          (DL_FUNC) &PKI_decrypt,          4},
    {"PKI_digest",           (DL_FUNC) &PKI_digest,           2},
    {"PKI_encrypt",          (DL_FUNC) &PKI_encrypt,          4},
    {"PKI_engine_info",      (DL_FUNC) &PKI_engine_info,      0},
    {"PKI_extract_key",      (DL_FUNC) &PKI_extract_key,      2},
    {"PKI_get_subject",      (DL_FUNC) &PKI_get_subject,      1},
    {"PKI_get_cert_info",    (DL_FUNC) &PKI_get_cert_info,    1},
    {"PKI_int2oid",          (DL_FUNC) &PKI_int2oid,          1},
    {"PKI_oid2int",          (DL_FUNC) &PKI_oid2int,          1},
    {"PKI_load_DER_X509",    (DL_FUNC) &PKI_load_DER_X509,    1},
    {"PKI_load_private_RSA", (DL_FUNC) &PKI_load_private_RSA, 2},
    {"PKI_load_public_RSA",  (DL_FUNC) &PKI_load_public_RSA,  1},
    {"PKI_parse_pgp_key",    (DL_FUNC) &PKI_parse_pgp_key,    2},
    {"PKI_PEM_split",        (DL_FUNC) &PKI_PEM_split,        1},
    {"PKI_PEM_part",         (DL_FUNC) &PKI_PEM_part,         3},
    {"PKI_random",           (DL_FUNC) &PKI_random,           1},
    {"PKI_raw2hex",          (DL_FUNC) &PKI_raw2hex,          3},
    {"PKI_sign_RSA",         (DL_FUNC) &PKI_sign_RSA,         3},
    {"PKI_verify_RSA",       (DL_FUNC) &PKI_verify_RSA,       4},
    {"PKI_verify_cert",      (DL_FUNC) &PKI_verify_cert,      4},
    {"decode_ASN1",          (DL_FUNC) &decode_ASN1,          1},
    {"encode_ASN1",          (DL_FUNC) &encode_ASN1,          1},
    {NULL, NULL, 0}
};

void R_init_PKI(DllInfo *dll)
{
    R_registerRoutines(dll, NULL, CallEntries, NULL, NULL);
    R_useDynamicSymbols(dll, FALSE);
}
