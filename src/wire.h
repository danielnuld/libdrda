/* Byte-level building blocks: a bounded reader, a growable writer, DSS
 * framing and the EBCDIC names DDM uses. Pure code, no I/O. */
#ifndef DRDA_WIRE_H
#define DRDA_WIRE_H

#include <stddef.h>
#include <stdint.h>

/* Bounded reader. Every byte that came from the network is read through it.
 * Reading past the end sets `err`, returns zeros and never touches memory
 * outside [p, p+n). Check `err` once after a group of reads. */
typedef struct {
    const uint8_t *p;
    size_t n;
    int err;
} rd;

rd       rd_make(const void *p, size_t n);
uint8_t  rd_u8(rd *r);
uint16_t rd_be16(rd *r);
uint32_t rd_be32(rd *r);
/* Integers in server byte order (le = 1 for QTDSQLX86). */
uint16_t rd_u16(rd *r, int le);
uint32_t rd_u32(rd *r, int le);
uint64_t rd_u64(rd *r, int le);
const uint8_t *rd_take(rd *r, size_t n); /* NULL on underflow */
rd       rd_sub(rd *r, size_t n);        /* split off the next n bytes */
/* VCM/VCS: 2-byte big-endian length followed by the bytes. */
const uint8_t *rd_vcs(rd *r, size_t *len);

/* Growable writer. Allocation failure sets `err`; later writes are no-ops. */
typedef struct {
    uint8_t *p;
    size_t n, cap;
    int err;
    size_t last_dss; /* offset of the last DSS header, (size_t)-1 if none */
} wb;

void wb_init(wb *w);
void wb_free(wb *w);
int  wb_reserve(wb *w, size_t n); /* room for n more bytes, -1 on failure */
void wb_put(wb *w, const void *p, size_t n);
void wb_u8(wb *w, uint8_t v);
void wb_be16(wb *w, uint16_t v);
void wb_be32(wb *w, uint32_t v);
void wb_be64(wb *w, uint64_t v);

/* DSS types. */
enum { DSS_RQS = 1, DSS_RPY = 2, DSS_OBJ = 3 };

/* Start a DSS carrying one DDM object with code point `cp`. The previous
 * DSS, if any, gets its chain bit (and same-correlator bit when `corr`
 * matches) so a request is simply a sequence of dss_begin/dss_end calls. */
void dss_begin(wb *w, int type, uint16_t corr, uint16_t cp);
/* Patch the lengths. Fails (err) when the object exceeds one DSS segment. */
void dss_end(wb *w);

/* DDM parameters inside the current object. */
void ddm_bytes(wb *w, uint16_t cp, const void *p, size_t n);
void ddm_u8(wb *w, uint16_t cp, uint8_t v);
void ddm_u16(wb *w, uint16_t cp, uint16_t v);
void ddm_u32(wb *w, uint16_t cp, uint32_t v);
void ddm_u64(wb *w, uint16_t cp, uint64_t v);
/* Printable-ASCII string sent as EBCDIC (CCSID 500), right-padded with
 * EBCDIC spaces to `pad` bytes. Returns -1 for a non-printable byte. */
int  ddm_ebcdic(wb *w, uint16_t cp, const char *s, size_t pad);
int  to_ebcdic(uint8_t *dst, const char *s, size_t n);

#endif
