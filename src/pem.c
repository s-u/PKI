#include <Rinternals.h>
#include <string.h>

/* sadly memmem is not POSIX and our payload is not guatanteed to the 0-terminated
   (and we can't terminate it since it is const char*) so we have to use a silly stopgap */
static const char *mm(const char *haystack, size_t hlen, const char *needle, size_t nlen) {
    const char *c = haystack;
    size_t left;
    if (!nlen) return 0;
    while (((left = (hlen - (c - haystack))) >= nlen) /* needle must fit */ &&
	   (c = memchr(c, needle[0], left))) {
	if (!memcmp(c, needle, nlen))
	    return c;
	c++;
    }
    return 0;
}

/* returns 0-63 for valid input or 127 on EOF */
static unsigned char val(const char **src, const char *se) {
    while (*src < se) {
	char c = **src;
        src[0]++;
        if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
        if (c == '/') return 63;
        if (c == '=')
            break;
        /* we loop as to skip any blanks, newlines etc. */
    }
    return 127; /* EOF */
}

/* src = dst is permissible since decoded is always shorter (4 -> 3)
   if t = NULL then the required size is returned instead */
static R_xlen_t base64decode(const char *src, R_xlen_t len, void *dst, R_xlen_t max_len) {
    unsigned char *t = (unsigned char*) dst, *end = t ? (t + max_len) : 0;
    const char *se = src + len;
    R_xlen_t est = 0;
    while ((src < se) && (!t || t < end)) {
        unsigned char v = val(&src, se);
        if (v > 63) break;
        if (t)
	    *t = (unsigned char) (v << 2);
        v = val(&src, se);
        if (v < 64) {
	    if (t) {
		*t |= (unsigned char) (v >> 4);
		if (++t == end) {
		    if (src < se && *src == '=')
			break; /* correct end at padding */
		    return -1;
		}
		*t = (unsigned char) (v << 4);
	    } else est++; /* 1 complete, 1 pending */
            v = val(&src, se);
            if (v < 64) {
		if (t) {
		    *t |= (unsigned char) (v >> 2);
		    if (++t == end) {
			if (src < se && *src == '=')
			    break;
			return -1;
		    }
			   *t = (unsigned char) (v << 6);
		} else est++; /* 2 complete, 1 pending */
                v = val(&src, se);
		if (v < 64) {
		    if (t) {
			*t |= (unsigned char) (v & 0x3f);
			t++;
		    } else est++; /* 3 complete */
		}
            }
        }
    }
    return t ? ((R_xlen_t) (t - (unsigned char*) dst)) : est;
}

static char buf[512];

/* PEM specifies "-----BEGIN (.*)-----" and so does OpenPGP,
   but SSH2 uses "---- BEGIN (.*) ----" so we allow "----[- ]BEGIN" */
SEXP PKI_PEM_split(SEXP sWhat) {
    SEXP res = PROTECT(CONS(R_NilValue, R_NilValue)), tail = 0;

    if (TYPEOF(sWhat) == STRSXP) { /* line-by-line */
	R_xlen_t n = XLENGTH(sWhat), i = 0;
	while (i < n - 1) {
	    const char *c = CHAR(STRING_ELT(sWhat, i));
	    if (!strncmp(c, "-----BEGIN ", 11) ||
		!strncmp(c, "---- BEGIN ", 11)) {
		const char *tag = c + 11;
		const char *e = strstr(c + 11, "----");
		if (e) {
		    const char *te = e;
		    R_xlen_t i0 = i + 1;
		    size_t cmplen;
		    SEXP sTag;
		    while (te > tag && te[-1] == ' ') te--;
		    if (te - tag > 256)
			Rf_error("Armor tag too long on line %ld: %s", (long) (i + 1), tag);
		    sTag = PROTECT(Rf_ScalarString(mkCharLenCE(tag, (int) (te - tag), CE_UTF8)));
		    cmplen = te - tag + 9;
		    /* construct the tail tag by s/BEGIN/END/ */
		    memcpy(buf, tag - 11, 5);
		    memcpy(buf + 5, "END ", 4);
		    memcpy(buf + 9, tag, te - tag);
		    buf[te - tag + 9] = 0;
		    while (i < n) {
			c = CHAR(STRING_ELT(sWhat, i));
			if (!strncmp(c, buf, cmplen))
			    break;
			i++;
		    }
		    if (i < n) {
			R_xlen_t j = i0;
			R_xlen_t psize = 0;
			/* compute total size */
			while (j < i) {
			    psize += strlen(CHAR(STRING_ELT(sWhat, j))) + 1;
			    j++;
			}
			if (psize) {
			    SEXP chunk = PROTECT(Rf_allocVector(RAWSXP, psize));
			    unsigned char *d = (unsigned char *)RAW(chunk);
			    j = i0;
			    while (j < i) {
				const char *cc = CHAR(STRING_ELT(sWhat, j));
				size_t clen = strlen(cc);
				memcpy(d, cc, clen);
				d += clen;
				*(d++) = '\n';
				j++;
			    }
			    if (tail) {
				SEXP nt = PROTECT(CONS(chunk, R_NilValue));
				SETCDR(tail, nt);
				UNPROTECT(1);
				tail = nt;
			    } else {
				SETCAR(res, chunk);
				tail = res;
			    }
			    Rf_setAttrib(chunk, Rf_install("tag"), sTag);
			    UNPROTECT(1);
			}
		    } /* i < n (= end found) */
		    UNPROTECT(1); /* sTag */
		} /* if end ---- found */
	    } /* if ----[- ]BEGIN found */
	    i++;
	} /* while i < n */
    } else if (TYPEOF(sWhat) == RAWSXP) {
	const char *src = (const char *) RAW(sWhat);
	const char *se  = src + XLENGTH(sWhat), *c = src;
	while (c + 30 < se) { /* it has to fit both armor guards */
	    c = memchr(c, '-', se - c);
	    if (!c) break;
	    if (!strncmp(c, "-----BEGIN ", 11) ||
		!strncmp(c, "---- BEGIN ", 11)) {
		const char *tag = c + 11;
		const char *e = mm(c + 11, se - c - 11, "----", 4);
		c += 11;
		if (e) {
		    const char *te = e;
		    SEXP sTag;
		    size_t cmplen;
		    while (te > tag && te[-1] == ' ') te--;
		    if (te - tag > 256)
			Rf_error("Armor tag too long @%ld", (long) (tag - src));
		    sTag = PROTECT(Rf_ScalarString(mkCharLenCE(tag, (int) (te - tag), CE_UTF8)));
		    cmplen = te - tag + 9;
		    /* construct the tail tag by s/BEGIN/END/ */
		    memcpy(buf, tag - 11, 5);
		    memcpy(buf + 5, "END ", 4);
		    memcpy(buf + 9, tag, te - tag);
		    /* find EOL */
		    while (e < se && (*e != '\r' && *e != '\n')) e++;
		    if (e < se - 1 && *e == '\r' && e[1] == '\n') e++; /* handle \r\n as one */
		    if (e < se - 12) { /* need a lot more ... (payload, END etc.) */
			/* look for end of armor */
			const char *epos = mm(e + 1, (se - e) - 1, buf, cmplen);
			if (epos) {
			    R_xlen_t psize = (R_xlen_t) ((epos - e) - 1);
			    SEXP chunk = PROTECT(Rf_allocVector(RAWSXP, psize));
			    unsigned char *d = (unsigned char *) RAW(chunk);
			    memcpy(d, e + 1, psize);
			    if (tail) {
				SEXP nt = PROTECT(CONS(chunk, R_NilValue));
				SETCDR(tail, nt);
				UNPROTECT(1);
				tail = nt;
			    } else {
				SETCAR(res, chunk);
				tail = res;
			    }
			    Rf_setAttrib(chunk, Rf_install("tag"), sTag);
			    UNPROTECT(1);
			    
			    c = epos + (te - tag + 9); /* but c behind the armor */			    
			} /* if (epos) */
		    }
		    UNPROTECT(1); /* sTag */
		}
	    }
	    while (c < se && *c == '-') c++;	    
	}
    } else
	Rf_error("Invalid input type, must be either character of raw vector");

    UNPROTECT(1);
    return (CAR(res) == R_NilValue) ? R_NilValue : res;
}

SEXP PKI_PEM_part(SEXP sWhat, SEXP sBody, SEXP sDecode) {
    int body = (Rf_asInteger(sBody) == 0) ? 0 : 1;
    int decode = (Rf_asInteger(sDecode) == 0) ? 0 : 1;
    SEXP res;
    const char *src, *se, *c, *he;
    if (TYPEOF(sWhat) != RAWSXP)
	Rf_error("Input must be a raw vector");
    src = (const char *) RAW(sWhat);
    se = src + XLENGTH(sWhat);
    /* Note that this is merely a heuristic, each format has slightly
       different definitions, but mostly base64 doesn't include :
       and headers must either have : or a leading whitespace */
    he = c = src;
    while (c < se) {
	const char *le = c;
	int has_col = 0;
	he = c;
	while (le < se && (*le != '\r' && *le != '\n')) {
	    if (*le == ':') has_col = 1;
	    le++;
	}
	/* it is has no :, doesn't start with WS and has some content
	   then it must be body */
	if (!has_col && *c != ' ' && *c != '\t' && le > c)
	    break;
	if (le == c) { /* end of headers, empty line, skip to next */
	    while (le < se && (*le == '\n' || *le == '\r')) le++;
	    c = le;
	    break;
	}
	if (le + 1 < se && *le == '\r' && le[1] == '\n')
	    le++;
	/* move past EOL */
	c = le + 1;
    }
    /* he = first byte that is not a header
       c  = first byte that is body */
    if (body) {
	if (c < se) {
	    if (decode) {
		R_xlen_t dsize = base64decode(c, se - c, 0, 0);
		if (dsize < 0) {
		    Rf_warning("Invalid base64 content, returning empty vector");
		    dsize = 0;
		}
		res = Rf_allocVector(RAWSXP, dsize);
		if (dsize > 0) {
		    /* this should never fail since we determined the size ahead of time ... */
		    if (base64decode(c, se - c, RAW(res), XLENGTH(res)) != XLENGTH(res)) {
			PROTECT(res);
			Rf_warning("Decoding base64 error, result may be incomplete");
			UNPROTECT(1);
		    }
		}
	    } else {
		res = Rf_allocVector(RAWSXP, se - c);
		memcpy(RAW(res), c, XLENGTH(res));
	    }
	    return res;
	} else {
	    return Rf_allocVector(RAWSXP, 0);
	}
    }
    res = Rf_allocVector(RAWSXP, he - src);
    if (XLENGTH(res))
	memcpy(RAW(res), src, XLENGTH(res));
    return res;
}
