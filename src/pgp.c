#include <Rinternals.h>
#include <string.h>

typedef unsigned int plen_t;

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
	    } else if (r[0] >= 192 & r[0] < 224) {
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
		len = (e - r); break;
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
static SEXP parse_mpi(ppacket_t *p) {
    SEXP res;
    unsigned char *dst;
    if (p->len < 2)
	Rf_error("Invalid or truncated multiprecision integer entry");
    unsigned int mplen = (((unsigned int) p->data[0]) << 8) | ((unsigned int) p->data[1]);
    unsigned int mpby  = (mplen + 7) / 8;
    dst = (unsigned char*) RAW(res = allocVector(RAWSXP, mpby));
    if (mpby) {
	if (p->len < mpby + 2)
	    Rf_error("Invalid or truncated multiprecision integer entry");
	memcpy(dst, p->data + 2, mpby);
    }
    p->data += 2 + mpby;
    p->len  -= 2 + mpby;
    return res;
}

/* parses OpenPGP binary payload. Note, however, that currently
   we only extract the Public-Key Packet and User ID Packet,
   all other packets are recognised, but ignored.

   If sRaw != FALSE then the result is simply a list of raw
   vectors with "type" attributes, each containing one packet.
*/
SEXP PKI_parse_pgp_key(SEXP sWhat, SEXP sRaw) {
    const unsigned char *r, *b, *e;
    int raw = Rf_asInteger(sRaw) ? 1 : 0;
    SEXP res = PROTECT(raw ? CONS(R_NilValue, R_NilValue) : allocVector(VECSXP, 4)), rt = 0, tys = 0;

    if (TYPEOF(sWhat) != RAWSXP)
	Rf_error("Invalid input, must be a raw vector");
    b = r = (const unsigned char *) RAW(sWhat);
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
	    Rprintf("Type: %02x, length=%d\n", p.type, p.len);
	    {
		int i = 0;
		while (i < p.len && i < 16)
		    Rprintf(" %02x", p.data[i++]);
		Rprintf("\n");
	    }
	    switch (p.type) {
	    case 6: {
		const unsigned char *c = p.data;
		if (p.len < 10)
		    Rf_error("Invalid (truncated) Public-Key packet");
		if (*c == 4) {
		    SEXP tail = 0;
		    unsigned int t =
			(((unsigned int) c[1]) << 24) |
			(((unsigned int) c[2]) << 16) |
			(((unsigned int) c[3]) << 8) |
			((unsigned int) c[4]);
		    int alg = c[5];
		    ppacket_t mpi = p;
		    SET_VECTOR_ELT(res, 3, ScalarReal((double) t));
		    mpi.data += 6;
		    mpi.len  -= 6;
		    while(mpi.len > 0) {
			SEXP mpe = PROTECT(parse_mpi(&mpi));
			if (!tail) {
			    SET_VECTOR_ELT(res, 2, (tail = CONS(mpe, R_NilValue)));
			} else {
			    SETCDR(tail, CONS(mpe, R_NilValue));
			    tail = CDR(tail);
			}
			UNPROTECT(1);
		    }
		    switch(alg) {
		    case 1:
		    case 2:
		    case 3:
			SET_VECTOR_ELT(res, 0, mkString("RSA")); break;
		    case 16:	
			SET_VECTOR_ELT(res, 0, mkString("Elgamal")); break;
		    case 17:
			SET_VECTOR_ELT(res, 0, mkString("DSA")); break;
		    default:
			SET_VECTOR_ELT(res, 0, mkString("<unknown>")); break;
		    }
		    /* PK ALG: 1-3 RSA, 16 Elgamal, 17 DSA */
		    /* SK ALG: 0 none, ..., 7 AES128, 8 AES192, 9 AES256 */
		    /* HASH: 1 MD5, 2 SHA1, 3 RIPE-MD/160, 8 SHA256, 9 SHA284, 10 SHA512, 11 SHA224 */
		} else Rf_error("Unsupported public key packet version: %d", (int) *c);	      
		break;
	    }
	    case 13:
		SET_VECTOR_ELT(res, 1, Rf_ScalarString(mkCharLenCE((const char*) p.data, p.len, CE_UTF8)));
		break;
	    }
	}
	r = p.data + p.len;
    }
    UNPROTECT(1);
    return res;
}
