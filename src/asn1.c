#include <Rinternals.h>

#include <string.h>

static SEXP decode_ASN1_bytes(unsigned char *d, unsigned int l, unsigned int *ptr) {
    unsigned int i = 0;
    int cl = d[i++];
    if (i < l) {
	unsigned int len = d[i++];
	if (len > 127) {
	    unsigned int nb = len - 128;
	    if (i + nb > l)
		Rf_error("truncated ASN.1 object");
	    if (nb > 4) 
		Rf_error("too large ASN.1 object");
	    len = 0;
	    while (nb) {
		len <<= 8;
		len |= d[i++];
		nb--;
	    }
	}
	if (i + len > l)
	    Rf_error("truncated ASN.1 object");
	/* Rprintf(" %p: type 0x%02x len %d\n", d, cl, len); */
	if (cl == 0x30) { /* sequence */
	    SEXP rl = R_NilValue, tl = R_NilValue, res;
	    unsigned int si = i, n = 0;
	    while (i - si < len) {
		unsigned int i_off = 0;
		SEXP v = decode_ASN1_bytes(d + i, si + len - i, &i_off);
		i += i_off;
		if (rl == R_NilValue)
		    tl = rl = PROTECT(CONS(v, R_NilValue));
		else
		    tl = SETCDR(tl, CONS(v, R_NilValue));
		n++;
	    }
	    res = PROTECT(allocVector(VECSXP, n));
	    if (rl != R_NilValue) {
		unsigned int j = 0;
		while (rl != R_NilValue) {
		    SET_VECTOR_ELT(res, j++, CAR(rl));
		    rl = CDR(rl);
		}
		UNPROTECT(1);
	    }
	    UNPROTECT(1);
	    if (ptr) *ptr = i;
	    return res;
	} else { /* everything else we just return as raw with "type" attribute */
	    int unused = -1;
	    if (cl == 3) {/* bit string - take out the unused bits number */
		unused = d[i++];
		len--;
	    }
	    {
		SEXP res = PROTECT(allocVector(RAWSXP, len));
		SEXP clo = PROTECT(ScalarInteger(cl));
		memcpy(RAW(res), d + i, len);
		setAttrib(res, install("type"), clo);
		if (unused != -1) {
		    SEXP ub = PROTECT(ScalarInteger(unused));
		    setAttrib(res, install("padded.bits"), ub);
		    UNPROTECT(1);
		}
		UNPROTECT(2);
		if (ptr) *ptr = i + len;
		return res;
	    }
	}
    }
    Rf_error("truncated ASN.1 object");
    /* unreachable */
    return R_NilValue;
}

SEXP decode_ASN1(SEXP sWhat) {
    if (TYPEOF(sWhat) != RAWSXP)
	Rf_error("ASN.1 object must be a raw vector");
    
    return decode_ASN1_bytes((unsigned char*) RAW(sWhat), (unsigned int) LENGTH(sWhat), 0);
}

static unsigned char *encode_ASN1_bytes(unsigned char *d, unsigned int max_len, SEXP sWhat) {
    unsigned int i = 0;
    if (max_len < 16)
	Rf_error("too large object");
    if (TYPEOF(sWhat) == RAWSXP) {
	SEXP ty = getAttrib(sWhat, install("type"));
	unsigned int len = LENGTH(sWhat);
	unsigned char unused = 0;
	int cl;
	if (ty == R_NilValue)
	    Rf_error("raw object without type - cannot encode");
	cl = d[i++] = (unsigned char) asInteger(ty);
	if (cl == 3) {
	    SEXP ub = getAttrib(sWhat, install("unused.bits"));
	    if (ub != R_NilValue)
		unused = (unsigned char) asInteger(ub);
	    len++;
	}
	if (len < 128)
	    d[i++] = (unsigned char) len;
	else {
	    unsigned int nb = 0, l0 = len, nb0;
	    while (l0) {
		l0 >>= 8;
		nb++;
	    }
	    d[i++] = (unsigned char) (nb + 128);
	    nb0 = nb;
	    l0 = len;
	    while (nb) {
		d[i + --nb] = (unsigned char) l0;
		l0 >>= 8;
	    }
	    i += nb0;
	}
	if (i + len + 2 > max_len)
	    Rf_error("too large object");
	if (cl == 3) {
	    d[i++] = unused;
	    len--;
	}
	memcpy(d + i, RAW(sWhat), len);
	return d + i + len;
    } else if (TYPEOF(sWhat) == VECSXP) {
	unsigned int i0 = i, len = 0, n = LENGTH(sWhat), j, shift_by;
	unsigned char *e;
	d[i++] = 0x30;
	/* reserve some space for the length - we use at most 32-bits */
	i += 5;
	e = d + i;
	for (j = 0; j < n; j++) {
	    unsigned char *en = encode_ASN1_bytes(e, max_len - i, VECTOR_ELT(sWhat, j));
	    i += en - e;
	    e = en;
	}
	len = (unsigned int) (e - (d + i0 + 6));
	shift_by = 4;
	if (len < 128)
	    d[i0 + 1] = (unsigned char) len;
	else {
	    unsigned int l0 = len, nb = 0;
	    while (l0) {
		l0 >>= 8;
		nb++;
	    }
	    e = d + i0 + 1;
	    *(e++) = (unsigned char) (nb + 128);
	    l0 = len;
	    while (l0) {
		e[--nb] = (unsigned char) l0;
		l0 >>= 8;
		shift_by--;
	    }		
	}
	if (shift_by)
	    memmove(d + i0 + 6 - shift_by, d + i0 + 6, len);
	return d + i0 + 6 - shift_by + len;
    } else
	Rf_error("ASN.1 objects to be wrapped must be either lists or raw vectors");
    /* unreachable */
    return 0;
}

SEXP encode_ASN1(SEXP sWhat) {
    unsigned int max_len = 1024*1024;
    SEXP tmp = PROTECT(allocVector(RAWSXP, max_len)), res;
    unsigned char *e = encode_ASN1_bytes((unsigned char*) RAW(tmp), LENGTH(tmp), sWhat);
    res = allocVector(RAWSXP, e - (unsigned char*) RAW(tmp));
    memcpy(RAW(res), RAW(tmp), LENGTH(res));
    UNPROTECT(1);
    return res;
}

static SEXP bigz2bignum(const unsigned int *bz) {
    SEXP res = allocVector(RAWSXP, 1 + bz[0] * 4);
    unsigned char *c = (unsigned char *) RAW(res);
    unsigned int i;
    *(c++) = 0; /* we may need a leading zero */
    /* FIXME: we handle only positive numbers */
    for (i = 2; i < bz[0] + 2; i++) {
	*(c++) = bz[i] >> 24;
	*(c++) = (bz[i] >> 16) & 255;
	*(c++) = (bz[i] >> 8) & 255;
	*(c++) = bz[i] & 255;
    }
    c = (unsigned char*) RAW(res);
    for (i = 0; i < LENGTH(res); i++)
	if (c[i]) break;
    if (c[i] > 127) i--;
    if (i > 0) {
	SEXP res2;
	PROTECT(res);
	res2 = allocVector(RAWSXP, LENGTH(res) - i);
	memcpy(RAW(res2), c + i, LENGTH(res) - i);
	res = res2;
	UNPROTECT(1);
    }
    return res;
}

SEXP PKI_int2oid(SEXP sVal) {
    int np = 0;
    unsigned char buf[128], *dst = buf, *e = buf + sizeof(buf) - 6;
    const unsigned int *v;
    SEXP res;
    int i = 2, n;
    if (TYPEOF(sVal) == REALSXP) {
	sVal = PROTECT(coerceVector(sVal, INTSXP));
	np++;
    }
    if (TYPEOF(sVal) != INTSXP)
	Rf_error("OID specification must be a vector of integers");
    v = (const unsigned int*) INTEGER(sVal);
    n = LENGTH(sVal);
    if (n < 3) Rf_error("Invalid OID");
    *(dst++) = (unsigned char)(v[0] * 40 + v[1]);
    while (i < n && dst < e) {
	unsigned int x = v[i++];
	if (x > 127) { /* since we have only 32-bits that measn at most 5 encoded bytes */
	    char rev[8], *r = rev;
	    while (x > 0) {
		*(r++) = (x & 0x7f) | 0x80;
		x >>= 7;
	    }
	    while (r > rev)
		*(dst++) = *(--r);
	    dst[-1] &= 0x7f; /* clear the last MSB */
	} else *(dst++) = (unsigned char) x;
    }
    res = Rf_allocVector(RAWSXP, dst - buf);
    memcpy(RAW(res), buf, LENGTH(res));
    if (np) UNPROTECT(np);
    return res;
}

SEXP PKI_oid2int(SEXP sVal) {
    SEXP res;
    int len = 2;
    int i = 1, n;
    const unsigned char *r, *re;
    unsigned int *iv;
    if (TYPEOF(sVal) != RAWSXP)
	Rf_error("Input must be a raw vector");
    r = (const unsigned char*) RAW(sVal);
    n = LENGTH(sVal);
    re = r + n;
    /* count the total number of entries (w/o the leading two) */
    while (i < n)
	if ((r[i++] & 0x80) == 0) len++;
    res = Rf_allocVector(INTSXP, len);
    iv = (unsigned int*) INTEGER(res);
    iv[0] = r[0] / 40;
    iv[1] = r[0] - (40 * iv[0]);
    r++;
    i = 2;
    while (i < len) {
	unsigned int v = 0;
	while(r < re) {
	    unsigned int nx = *(r++);
	    v |= (nx & 0x7f);
	    if ((nx & 0x80) == 0)
		break;
	    v <<= 7;
	}
	iv[i++] = v;
    }
    return res;
}

/* BIGNUM is a big-endian integer with the additional
   rule that the first MSB is the sign, so for positive
   integers (like here) the first byte must be <128
   hence a leading 00 is needed if the first byte
   was to start with the MSB set */
static SEXP long2bignum(unsigned long v) {
    unsigned char buf[9], *c = buf + 8;
    SEXP res;
    if (v < 128) {
	SEXP res = allocVector(RAWSXP, 1);
	RAW(res)[0] = (unsigned char) v;
	return res;
    }
    while (v) {
	*(c--) = (unsigned char) v;
	v >>= 8;
    }
    if (c[1] < 128) c++; /* move back if leading zero is not needed */
    res = allocVector(RAWSXP, buf + 9 - c);
    memcpy(RAW(res), c, LENGTH(res));
    return res;
}

SEXP PKI_asBIGNUMint(SEXP sWhat, SEXP sScalar) {
    int scalar = asInteger(sScalar) == TRUE;
    if (inherits(sWhat, "bigz")) {
	const unsigned int *bz;
	if (TYPEOF(sWhat) != RAWSXP || LENGTH(sWhat) < 4)
	    Rf_error("invalid bigz format");
	bz = (const unsigned int*) RAW(sWhat);
	if (scalar) {
	    if (bz == 0) Rf_error("attempt to use zero-length vector as scalar");
	    return bigz2bignum(bz + 1);
	} else {
	    SEXP res = PROTECT(allocVector(VECSXP, bz[0]));
	    unsigned int i, j = 1;
	    for (i = 0; i < bz[0]; i++) {
		SET_VECTOR_ELT(res, i, bigz2bignum(bz + j));
		j += bz[j] + 1;
	    }
	    UNPROTECT(1);
	    return res;
	}
    }
    if (TYPEOF(sWhat) == REALSXP) {	
	if (scalar) {
	    if (!LENGTH(sWhat)) Rf_error("attempt to use zero-length vector as scalar");
	    return long2bignum((unsigned long) asReal(sWhat));
	} else {
	    unsigned int i, n = LENGTH(sWhat);
	    SEXP res = PROTECT(allocVector(VECSXP, n));
	    const double *d = REAL(sWhat);
	    for (i = 0; i < n; i++)
		SET_VECTOR_ELT(res, i, long2bignum((unsigned long) d[i]));
	    UNPROTECT(1);
	    return res;
	}
    }
    if (TYPEOF(sWhat) == INTSXP) {
	if (scalar) {
	    if (!LENGTH(sWhat)) Rf_error("attempt to use zero-length vector as scalar");
	    return long2bignum((unsigned long) asInteger(sWhat));
	} else {
	    unsigned int i, n = LENGTH(sWhat);
	    SEXP res = PROTECT(allocVector(VECSXP, n));
	    const int *d = INTEGER(sWhat);
	    for (i = 0; i < n; i++)
		SET_VECTOR_ELT(res, i, long2bignum((unsigned long) d[i]));
	    UNPROTECT(1);
	    return res;
	}
    }
    Rf_error("unsupported type to convert");
    /* unreachable */
    return R_NilValue;
}
