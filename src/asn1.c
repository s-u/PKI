#include <Rinternals.h>

#include <string.h>
#include "asn1.h"

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
	memmove(c, c + i, LENGTH(res) - i);
	SETLENGTH(res, LENGTH(res) - i);
    }
    return res;
}

static SEXP long2bignum(unsigned long v) {
    unsigned char buf[9], *c = buf + 8;
    SEXP res;
    if (v < 128) {
	SEXP res = allocVector(RAWSXP, 1);
	RAW(res)[0] = v;
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

/*
* Parse an ASN1_TIME value and return a time_t structure. According to RFC 5280 (http://www.rfc-editor.org/rfc/rfc5280.txt)
* conforming implementations "MUST always encode certificate validity dates through the year 2049 as UTCTime; 
* certificate validity dates in 2050 or later MUST be encoded as GeneralizedTime." See section 4.1 of RFC 5280 for the
* definition of UTCTime and Generalized time, but the crux is that UTCTime uses a two digit year, whereas GeneralizedTime
* uses a 4 digit year.
* 
* This algorithm is based on parsing the character
* string in ASN1_TIME and extracting the date and time components based on length and results in the string.  It
* is derived from the publicly posted algorithm here: http://marc.info/?l=openssl-users&m=106781789300592&w=2
* I use timegm() rather than mktime() to do the conversion to time_t in order to not assume a local time zone during
* the conversion, but its not clear if timegm() is portable to Windows.  Need to look into that, 
* possibly proving an implementation for Windows as outlined here: 
* http://trac.rtmpd.com/browser/trunk/sources/common/src/platform/windows/timegm.cpp
*/
time_t getTimeFromASN1(const ASN1_TIME * aTime) {
    
    time_t lResult = 0;

	char lBuffer[24];
	char * pBuffer = lBuffer;

	size_t lTimeLength = aTime->length;
    
	char * pString = (char *)aTime->data;

	if (aTime->type == V_ASN1_UTCTIME) {
		if ((lTimeLength < 11) || (lTimeLength > 17)) {
			return 0;
		}

		memcpy(pBuffer, pString, 10);
		pBuffer += 10;
		pString += 10;
	} else {
		if (lTimeLength < 13) {
			return 0;
		}

		memcpy(pBuffer, pString, 12);
		pBuffer += 12;
		pString += 12;
	}

	if ((*pString == 'Z') || (*pString == '-') || (*pString == '+')) {
		*(pBuffer++) = '0';
		*(pBuffer++) = '0';
	} else {
		*(pBuffer++) = *(pString++);
		*(pBuffer++) = *(pString++);
		// Skip any fractional seconds...
		if (*pString == '.') {
			pString++;
			while ((*pString >= '0') && (*pString <= '9')) {
				pString++;
			}
		}
	}

	*(pBuffer++) = 'Z';
	*(pBuffer++) = '\0';

	time_t lSecondsFromUCT;
	if (*pString == 'Z') {
		lSecondsFromUCT = 0;
	} else {
		if ((*pString != '+') && (pString[5] != '-')) {
			return 0;
		}

		lSecondsFromUCT = ((pString[1]-'0') * 10 + (pString[2]-'0')) * 60;
		lSecondsFromUCT += (pString[3]-'0') * 10 + (pString[4]-'0');
		if (*pString == '-') {
			lSecondsFromUCT = -lSecondsFromUCT;
		}
	}

	struct tm lTime;
	lTime.tm_sec = ((lBuffer[10] - '0') * 10) + (lBuffer[11] - '0');
	lTime.tm_min = ((lBuffer[8] - '0') * 10) + (lBuffer[9] - '0');
	lTime.tm_hour = ((lBuffer[6] - '0') * 10) + (lBuffer[7] - '0');
	lTime.tm_mday = ((lBuffer[4] - '0') * 10) + (lBuffer[5] - '0');
	lTime.tm_mon = (((lBuffer[2] - '0') * 10) + (lBuffer[3] - '0')) - 1;
	lTime.tm_year = ((lBuffer[0] - '0') * 10) + (lBuffer[1] - '0');
	if (lTime.tm_year < 50) {
		lTime.tm_year += 100;
		// RFC 2459
	}
	lTime.tm_wday = 0;
	lTime.tm_yday = 0;
	lTime.tm_isdst = 0;

	// No DST adjustment requested
	lResult = timegm(&lTime);
	if ((time_t)-1 != lResult) {
		if (0 != lTime.tm_isdst) {
			lResult -= 3600;
			// mktime may adjust for DST (OS dependent)
		}
		lResult += lSecondsFromUCT;
	} else {
		lResult = 0;
	}

	return lResult;
}
