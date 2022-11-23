#include <Rinternals.h>
#include <string.h>

typedef unsigned int plen_t;
typedef unsigned int u32_t;

typedef struct ppacket {
    int type;
    plen_t len;
    const unsigned char *data;
} ppacket_t;

static int parse1(ppacket_t *p, const unsigned char *r, const unsigned char *e) {
    plen_t len = 0;
    int   type = 0;
    unsigned char h = r[0];
    const unsigned char *b = r;
    int trunp = 0;

    if (!(h & 0x80)) { /* headers must have MSB set */
	Rf_warning("Invalid trailing content at %lu",
		   (unsigned long) (r - b));
	return -1;
    }

    while (1) {
	if (h & 0x40) { /* new format */
	    type = h & 0x3f;
	    if (r[0] < 192) { /* one - byte length */
		len = *(r++);
	    } else if (r[0] >= 192 && r[0] < 224) {
		if (r + 2 <= e) {
		    trunp = 1;
		    break;
		}
		len = *(r++) - 192;
		len <<= 8;
		len |= *(r++);
		len += 192;
	    } else if (r[0] == 255) {
		int i = 0;
		if (r + 4 <= e) {
		    trunp = 1;
		    break;
		}
		r++;
		while (i < 4) {
		    len <<= 8;
		    len |= *(r++);
		    i++;
		}
	    } else
		Rf_error("Packets with partial body lengths are not supported");
	} else { /* old format */
	    int ld = h & 3;
	    type = (h >> 2) & 0xf;
	    r++;
	    if (r + ld + 2 >= e) {
		trunp = 1;
		break;
	    }
	    switch (ld) {
	    case 0:
		len = *(r++); break;
	    case 1:
		len = *(r++);
		len <<= 8;
		len |= *(r++); break;
	    case 2:
		len = *(r++);
		len <<= 8;
		len |= *(r++); 
		len <<= 8;
		len |= *(r++); 
		len <<= 8;
		len |= *(r++); break;
	    case 3:
		if (e - r > 2147483640)
		    Rf_error("Packet in old format is too big");
		len = (plen_t) (e - r); break;
	    }
	}
	break;
    }
    if (trunp)
	Rf_error("Truncated packet at %lu (incomplete header)",
		 (unsigned long) (r - b));
    if ((unsigned long) (e - r) < (unsigned long) len)
	Rf_error("Truncated packet at %lu (expected %u body, got only %lu)",
		 (unsigned long) (r - b), len, (unsigned long) (e - r));
    
    p->type = type;
    p->len  = len;
    p->data = r;
    return 1;
}

/* parse a single MPI (multiprecision integer)
   Note that the packet is modified to eat the parsed
   content.
   FWIW: The MPI representation in PGP uses length in bits 
   (leading 16-bit integer) while ASN.1 uses bytes only and
   bigz uses 32-bit segments. This is not a problem here, but
   if one of those formats were to be converted back then
   we would have to extract teh exact precision 
   FIXME: in theory the MSB may contain garbage, but
   we require it to be 0-padded. To fix we'd have to zero-out
   the unused bits.
*/
static SEXP parse_mpi(ppacket_t *p, int vlf) {
    SEXP res;
    unsigned char *dst;
    if (vlf) { /* EC formats use (non-MPI) var-len entries so we cover them here, too */
	unsigned int len;
	if (p->len < 1 || p->len < (len = ((unsigned int) p->data[0])) + 1)
	    Rf_error("Invalid or truncated variable-length field");
	dst = (unsigned char*) RAW(res = allocVector(RAWSXP, len));
	memcpy(dst, p->data + 1, len);
	p->data += len + 1;
	p->len  -= len + 1;
	return res;
    }
    if (p->len < 2)
	Rf_error("Invalid or truncated multiprecision integer header (need 2 bytes, got %d)", (int) p->len);
    unsigned int mplen = (((unsigned int) p->data[0]) << 8) | ((unsigned int) p->data[1]);
    unsigned int mpby  = (mplen + 7) / 8;
    dst = (unsigned char*) RAW(res = allocVector(RAWSXP, mpby));
    if (mpby) {
	if (p->len < mpby + 2)
	    Rf_error("Invalid or truncated multiprecision integer entry (need %d, got %d)", (int) mpby +2, (int) p->len);
	memcpy(dst, p->data + 2, mpby);
    }
    p->data += 2 + mpby;
    p->len  -= 2 + mpby;
    return res;
}

/* parses OpenPGP binary payload. Note, however, that currently
   we only extract the Key/Sub-Key Packets and User ID Packet,
   all other packets are recognised, but ignored.

   If sRaw != FALSE then the result is simply a list of raw
   vectors with "type" attributes, each containing one packet.
*/
SEXP PKI_parse_pgp_key(SEXP sWhat, SEXP sRaw) {
    const unsigned char *r, *e;
    int raw = Rf_asInteger(sRaw) ? 1 : 0;
    SEXP res = PROTECT(raw ? CONS(R_NilValue, R_NilValue) : allocVector(VECSXP, 5)), rt = 0, tys = 0;
    SEXP lastKey = R_NilValue;

    if (TYPEOF(sWhat) != RAWSXP)
	Rf_error("Invalid input, must be a raw vector");
    r = (const unsigned char *) RAW(sWhat);
    e = r + XLENGTH(sWhat);

    while (r < e) {
	ppacket_t p;
	if (parse1(&p, r, e) != 1)
	    break;
	if (raw) {
	    SEXP ne = PROTECT(allocVector(RAWSXP, p.len));
	    if (!rt) {
		SETCAR(res, ne);
		rt = res;
	    } else {
		SEXP le = PROTECT(CONS(ne, R_NilValue));
		SETCDR(rt, le);
		UNPROTECT(1);
		rt = le;
	    } 
	    if (!tys) tys = Rf_install("type");
	    Rf_setAttrib(ne, tys, Rf_ScalarInteger(p.type));
	    memcpy(RAW(ne), p.data, p.len);
	    UNPROTECT(1);
	} else {
#define MAX_ALG 24
	    static const char *keyfmt_def[] = { /* key-specific data definitions M=MPI, V=var-len; pub/priv */
					        "",        /* undef */
						"MM/MMMM", /* RSA 1 */
						"MM/MMMM", /* RSA 2 */
						"MM/MMMM", /* RSA 3 */
						"", "", "", "", "", "", "", "", "", "", "", "",
						"MMM/M",   /* Elgamal 16 */
						"MMMM/M",  /* DSA 17 */
						"VMV/M",   /* ECDH 18 */
						"VM/M",    /* ECDSA 19 */
						"", "",
						"VM/M",    /* EdDSA 22 */
						"", "" };

	    switch (p.type) {
	    case 6:  /* pub key */
	    case 14: /* pub subkey */
	    case 5:  /* pri key */
	    case 7:  /* pri subkey */
		{
		const unsigned char *c = p.data;
		const char *names[] = { "algorithm", "public", "private", "created", "user.id", "" };
		SEXP sKey = PROTECT(mkNamed(VECSXP, names));
		if (p.len < 10)
		    Rf_error("Invalid (truncated) Key packet");
		if (*c == 4 || *c == 5) {
		    int ki = 0;
		    u32_t t =
			(((u32_t) c[1]) << 24) |
			(((u32_t) c[2]) << 16) |
			(((u32_t) c[3]) << 8) |
			((u32_t) c[4]);
		    unsigned int alg = (unsigned int) c[5];
		    ppacket_t mpi = p;
		    const char *alg_name = "<unknown>";
		    u32_t klen = 0;

		    SET_VECTOR_ELT(sKey, 3, ScalarReal((double) t));
		    mpi.data += 6;
		    mpi.len  -= 6;
		    if (*c == 5) { /* v5 adds key material length */
			if (mpi.len < 4)
			    Rf_error("Truncated v5 Key packet");
			klen =
			    (((u32_t) c[1]) << 24) |
			    (((u32_t) c[2]) << 16) |
			    (((u32_t) c[3]) << 8) |
			    ((u32_t) c[4]);
			mpi.data += 4;
			mpi.len  -= 4;
			if (mpi.len < klen)
			    Rf_error("Truncated v5 Key packet (need %lu, got %lu)", (unsigned long) klen, (unsigned long) mpi.len);
			mpi.len = klen;
		    }
		    if (alg <= MAX_ALG && keyfmt_def[alg][0]) { /* only parse known algorithms */
			const char *fmt = keyfmt_def[alg];
			SEXP tail = 0;
			/* Rprintf("  known alg %d, format: '%s'\n", alg, fmt); */
			while(mpi.len > 0 && *fmt && *fmt != '/') {
			    SEXP mpe = PROTECT(parse_mpi(&mpi, *fmt == 'V'));
			    if (!tail) {
				SET_VECTOR_ELT(sKey, 1, (tail = CONS(mpe, R_NilValue)));
			    } else {
				SETCDR(tail, CONS(mpe, R_NilValue));
				tail = CDR(tail);
			    }
			    UNPROTECT(1);
			    fmt++;
			    ki++;
			}
			if (*fmt != '/' && *fmt)
			    Rf_error("Truncated Key packet, missing components: %s", fmt);
		    } else if (*c == 5) { /* for v5 we can at least return the raw content */
			SEXP rc = Rf_allocVector(RAWSXP, klen);
			SET_VECTOR_ELT(sKey, 1, rc);
			memcpy(RAW(rc), mpi.data, XLENGTH(rc));
		    }
		    if (*c == 5) {
			if (mpi.len)
			    Rf_warning("Key packet v5 parsed content does not match declared length, %d bytes left", (int) mpi.len);
			/* reset assuming valid length entry */
			mpi = p;
			mpi.data += 10 + klen;
			mpi.len  -= 10 + klen;
		    }

		    if (mpi.len > 2 && (p.type == 5 || p.type == 7)) { /* private keys */
			unsigned int s2k = mpi.data[0];
			if (s2k)
			    Rf_warning("Private key is encrypted, skipping");
			else {
			    mpi.data++;
			    mpi.len--;
			    if (*c == 5) {
				unsigned int skip = mpi.data[0];
				if (mpi.len < skip + 5) /* we also count the next 4-byte size */
				    Rf_error("Truncated v5 private key");
				/* FIXME: we ignore the secret payload size for now (32-bit) and jsut skip over it */
				mpi.data += skip + 5;
				mpi.len  -= skip + 5;
			    }
			    /* ok, at this point mpi should point to the priv key secret data */
			    if (alg <= MAX_ALG && keyfmt_def[alg][0]) {
				const char *fmt = keyfmt_def[alg];
				while (*fmt && *fmt != '/') fmt++;
				if (*(fmt++) == '/') { /* do we have private key specs ? */
				    SEXP tail = 0;
				    while(mpi.len > 0 && *fmt && *fmt != '/') {
					SEXP mpe = PROTECT(parse_mpi(&mpi, *fmt == 'V'));
					if (!tail) {
					    SET_VECTOR_ELT(sKey, 2, (tail = CONS(mpe, R_NilValue)));
					} else {
					    SETCDR(tail, CONS(mpe, R_NilValue));
					    tail = CDR(tail);
					}
					UNPROTECT(1);
					fmt++;
					ki++;
				    }
				    if (*fmt != '/' && *fmt)
					Rf_error("Truncated Key packet, missing components: %s", fmt);
				} /* if there are specs, they have priv key specs so there is no else .. */
			    } else { /* return the rest as-is */
				SEXP rc = Rf_allocVector(RAWSXP, mpi.len);
				SET_VECTOR_ELT(sKey, 3, rc);
				memcpy(RAW(rc), mpi.data, XLENGTH(rc));
			    }
			}
		    }

#if 0 /* if we ever want to parse the encrypted keys .. too complex to bother, use libraries for that ... */
		    unsigned int s2k = mpi.data[0], aead = 256, sea = 256, ptr = 0;
		    mpi.data++;
		    mpi.len--;
		    /* s2k = 0 clear, 1..253 = sym key alg, MD5+IDEA, no salt, >= 253 followed by S2K spec */
		    if (s2k >= 253) {
			sea = mpi.data[ptr++]; /* sym enc alg */
			if (a2k == 253)
			    aead = mpi.data[ptr++];
			s2k = mpi.data[1];
			if (s2k != 0 && s2k != 1 && s2k != 3)
			    Rf_error("Invalid S2K specification (%u) in private key", s2k);
			mpi.data++;
			mpi.len--;
			/* S2K: 0 = [hash], 1 = [hash] [salt 8], 3 = [hash] [salt 8] [count 1] */
		    }
#endif

		    switch(alg) { /* RFC 4880 */
		    case 1:
		    case 2:
		    case 3:
			alg_name = "RSA"; break;
		    case 16:	
			alg_name = "Elgamal"; break;
		    case 17:
			alg_name = "DSA"; break;
		    case 18: /* RFC 6637 */
			alg_name = "ECDH"; break;
		    case 19:
			alg_name = "ECDSA"; break;
		    case 21: /* reserved, but has a name */
			alg_name = "DH"; break;
		    case 22: /* draft:
				https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/ */
			alg_name = "EdDSA"; break;
		    case 23: /* following are reserved but named (see above) */
			alg_name = "AEDH"; break;
		    case 24:
			alg_name = "AEDSA"; break;
		    }
		    SET_VECTOR_ELT(sKey, 0, mkString(alg_name));

		    if (p.type == 6) { /* pub key */
			SEXP old = VECTOR_ELT(res, 1);
			if (old != R_NilValue) {
			    SEXP x;
			    if (TYPEOF(old) == VECSXP)
				SET_VECTOR_ELT(res, 1, CONS(old, R_NilValue));
			    x = VECTOR_ELT(res, 1);
			    while (CDR(x) != R_NilValue) x = CDR(x);
			    SETCDR(x, CONS(sKey, R_NilValue));
			} else
			    SET_VECTOR_ELT(res, 1, sKey);
		    } else if (p.type == 5) { /* private key */
			SEXP old = VECTOR_ELT(res, 2);
			if (old != R_NilValue) {
			    SEXP x;
			    if (TYPEOF(old) == VECSXP)
				SET_VECTOR_ELT(res, 2, CONS(old, R_NilValue));
			    x = VECTOR_ELT(res, 2);
			    while (CDR(x) != R_NilValue) x = CDR(x);
			    SETCDR(x, CONS(sKey, R_NilValue));
			} else
			    SET_VECTOR_ELT(res, 2, sKey);
		    } else if (p.type == 14 || p.type == 7) { /* pub/priv subkey */
			int where = (p.type == 14) ? 3 : 4;
			if (VECTOR_ELT(res, where) == R_NilValue)
			    SET_VECTOR_ELT(res, where, CONS(sKey, R_NilValue));
			else {
			    SEXP x = VECTOR_ELT(res, where);
			    while (CDR(x) != R_NilValue) x = CDR(x);
			    SETCDR(x, CONS(sKey, R_NilValue));
			}
		    }
		    lastKey = sKey;
		    /* SK ALG: 0 none, ..., 7 AES128, 8 AES192, 9 AES256 */
		    /* HASH: 1 MD5, 2 SHA1, 3 RIPE-MD/160, 8 SHA256, 9 SHA284, 10 SHA512, 11 SHA224 */
		} else Rf_error("Unsupported key packet version: %d", (int) *c);
		UNPROTECT(1); /* sKey */
		break;
	    }
	    case 13:
		{
		    SEXP cUID = PROTECT(mkCharLenCE((const char*) p.data, p.len, CE_UTF8));
		    if (lastKey != R_NilValue)
			SET_VECTOR_ELT(lastKey, 4, Rf_ScalarString(cUID));
		    SET_VECTOR_ELT(res, 0, Rf_ScalarString(cUID));
		    UNPROTECT(1);
		}
		break;
	    }
	}
	r = p.data + p.len;
    }
    UNPROTECT(1);
    return res;
}
