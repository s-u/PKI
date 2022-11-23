#include <Rinternals.h>
#include <string.h>

static char stbuf[1024];

static const char hex1[] = "0123456789abcdef";
static const char hex2[] = "0123456789ABCDEF";

SEXP PKI_raw2hex(SEXP sRaw, SEXP sSep, SEXP sUpp) {
    int upp = asInteger(sUpp) == 1;
    size_t n, i, sl;
    const char *sep = 0;
    char *buf, *bp;
    unsigned char *data;
    const char *hex = upp ? hex2 : hex1;
    SEXP tmp = R_NilValue, res;
    
    if (TYPEOF(sRaw) != RAWSXP)
	Rf_error("input must be a raw vector");
    if (TYPEOF(sSep) == STRSXP) {
	if (LENGTH(sSep) != 1)
	    Rf_error("sep must be a single string");
	sep = CHAR(STRING_ELT(sSep, 0));
    } else if (sSep != R_NilValue)
	Rf_error("sep must be a single string");
    n = (size_t) XLENGTH(sRaw);
    data = (unsigned char *) RAW(sRaw);
    if (!sep) {
	res = allocVector(STRSXP, n);
	PROTECT(res);
	for (i = 0; i < n; i++) {
	    char hv[3];
	    hv[0] = hex[data[i] >> 4];
	    hv[1] = hex[data[i] & 15];
	    hv[2] = 0;
	    SET_STRING_ELT(res, i, mkChar(hv));
	}
	UNPROTECT(1);
	return res;
    }
    sl = (size_t) strlen(sep);
    if (n * (2 + sl)  + 1 > sizeof(buf)) {
	tmp = PROTECT(allocVector(RAWSXP, n * (2 + sl) + 2));
	buf = (char*) RAW(tmp);
    } else buf = stbuf;
    bp = buf;
    for (i = 0; i < n; i++) {
	const char *sp = sep;
	*(buf++) = hex[data[i] >> 4];
	*(buf++) = hex[data[i] & 15];
	if (i + 1 < n) while (*sp) *(buf++) = *(sp++);
    }
    *buf = 0;
    res = mkString(bp);
    if (tmp != R_NilValue) UNPROTECT(1);
    return res;
}
