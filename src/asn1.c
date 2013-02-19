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
	/* printf(" %p: type 0x%02x len %d\n", d, cl, len); */
	if (cl == 0x30) { /* sequence */
	    SEXP rl = R_NilValue, tl = R_NilValue, res;
	    unsigned int si = i, n = 0;
	    while (i < len) {
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
	    d[i++] = len;
	else {
	    int nb = 0, l0 = len, nb0;
	    while (l0) {
		l0 >>= 8;
		nb++;
	    }
	    d[i++] = nb + 128;
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
	len = e - (d + i0 + 6);
	shift_by = 4;
	if (len < 128)
	    d[i0 + 1] = len;
	else {
	    unsigned int l0 = len, nb = 0;
	    while (l0) {
		l0 >>= 8;
		nb++;
	    }
	    e = d + i0 + 1;
	    *(e++) = nb + 128;
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
