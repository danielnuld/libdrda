#include "wire.h"

#include <stdlib.h>
#include <string.h>

rd rd_make(const void *p, size_t n)
{
    rd r;
    r.p = (const uint8_t *)p;
    r.n = p ? n : 0;
    r.err = 0;
    return r;
}

const uint8_t *rd_take(rd *r, size_t n)
{
    const uint8_t *p;
    if (r->err || n > r->n) {
        r->err = 1;
        r->n = 0;
        return NULL;
    }
    p = r->p;
    r->p += n;
    r->n -= n;
    return p;
}

uint8_t rd_u8(rd *r)
{
    const uint8_t *p = rd_take(r, 1);
    if (!p)
        return 0;
    return p[0];
}

uint16_t rd_be16(rd *r)
{
    const uint8_t *p = rd_take(r, 2);
    if (!p)
        return 0;
    return (uint16_t)(p[0] << 8 | p[1]);
}

uint32_t rd_be32(rd *r)
{
    const uint8_t *p = rd_take(r, 4);
    return p ? (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3] : 0;
}

static uint64_t rd_int(rd *r, size_t n, int le)
{
    const uint8_t *p = rd_take(r, n);
    uint64_t v = 0;
    size_t i;
    if (!p)
        return 0;
    for (i = 0; i < n; i++)
        v = v << 8 | p[le ? n - 1 - i : i];
    return v;
}

uint16_t rd_u16(rd *r, int le) { return (uint16_t)rd_int(r, 2, le); }
uint32_t rd_u32(rd *r, int le) { return (uint32_t)rd_int(r, 4, le); }
uint64_t rd_u64(rd *r, int le) { return rd_int(r, 8, le); }

rd rd_sub(rd *r, size_t n)
{
    const uint8_t *p = rd_take(r, n);
    rd s = rd_make(p, n);
    if (!p)
        s.err = 1;
    return s;
}

const uint8_t *rd_vcs(rd *r, size_t *len)
{
    *len = rd_be16(r);
    return rd_take(r, *len);
}

void wb_init(wb *w)
{
    memset(w, 0, sizeof *w);
    w->last_dss = (size_t)-1;
}

void wb_free(wb *w)
{
    free(w->p);
    wb_init(w);
}

int wb_reserve(wb *w, size_t n)
{
    if (w->err)
        return -1;
    if (w->n + n > w->cap) {
        size_t cap = w->cap ? w->cap * 2 : 256;
        uint8_t *np;
        while (cap < w->n + n)
            cap *= 2;
        np = (uint8_t *)realloc(w->p, cap);
        if (!np) {
            w->err = 1;
            return -1;
        }
        w->p = np;
        w->cap = cap;
    }
    return 0;
}

void wb_put(wb *w, const void *p, size_t n)
{
    if (wb_reserve(w, n) < 0)
        return;
    if (n)
        memcpy(w->p + w->n, p, n);
    w->n += n;
}

void wb_u8(wb *w, uint8_t v) { wb_put(w, &v, 1); }

void wb_be16(wb *w, uint16_t v)
{
    uint8_t b[2];
    b[0] = (uint8_t)(v >> 8);
    b[1] = (uint8_t)v;
    wb_put(w, b, 2);
}

void wb_be32(wb *w, uint32_t v)
{
    wb_be16(w, (uint16_t)(v >> 16));
    wb_be16(w, (uint16_t)v);
}

void wb_be64(wb *w, uint64_t v)
{
    wb_be32(w, (uint32_t)(v >> 32));
    wb_be32(w, (uint32_t)v);
}

#define DSS_CHAINED  0x40
#define DSS_SAMECORR 0x10

void dss_begin(wb *w, int type, uint16_t corr, uint16_t cp)
{
    if (w->last_dss != (size_t)-1 && !w->err) {
        uint8_t *prev = w->p + w->last_dss;
        prev[3] |= DSS_CHAINED;
        if ((uint16_t)(prev[4] << 8 | prev[5]) == corr)
            prev[3] |= DSS_SAMECORR;
    }
    w->last_dss = w->n;
    wb_be16(w, 0); /* DSS length, patched by dss_end */
    wb_u8(w, 0xD0);
    wb_u8(w, (uint8_t)type);
    wb_be16(w, corr);
    wb_be16(w, 0); /* object length */
    wb_be16(w, cp);
}

void dss_end(wb *w)
{
    size_t len;
    if (w->err)
        return;
    len = w->n - w->last_dss;
    /* ponytail: one segment only, so a request object is capped at 32 KB
     * (a very long SQL text). Continuation segments lift it if needed. */
    if (len > 0x7FFF) {
        w->err = 1;
        return;
    }
    w->p[w->last_dss] = (uint8_t)(len >> 8);
    w->p[w->last_dss + 1] = (uint8_t)len;
    w->p[w->last_dss + 6] = (uint8_t)((len - 6) >> 8);
    w->p[w->last_dss + 7] = (uint8_t)(len - 6);
}

void ddm_bytes(wb *w, uint16_t cp, const void *p, size_t n)
{
    wb_be16(w, (uint16_t)(n + 4));
    wb_be16(w, cp);
    wb_put(w, p, n);
}

void ddm_u8(wb *w, uint16_t cp, uint8_t v) { ddm_bytes(w, cp, &v, 1); }

void ddm_u16(wb *w, uint16_t cp, uint16_t v)
{
    wb_be16(w, 6);
    wb_be16(w, cp);
    wb_be16(w, v);
}

void ddm_u32(wb *w, uint16_t cp, uint32_t v)
{
    wb_be16(w, 8);
    wb_be16(w, cp);
    wb_be32(w, v);
}

void ddm_u64(wb *w, uint16_t cp, uint64_t v)
{
    wb_be16(w, 12);
    wb_be16(w, cp);
    wb_be64(w, v);
}

/* CCSID 500 for printable ASCII 0x20..0x7E. */
static const uint8_t ebcdic500[95] = {
    0x40, 0x4F, 0x7F, 0x7B, 0x5B, 0x6C, 0x50, 0x7D, 0x4D, 0x5D, 0x5C, 0x4E, 0x6B, 0x60, 0x4B, 0x61,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0x7A, 0x5E, 0x4C, 0x7E, 0x6E, 0x6F,
    0x7C, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6,
    0xD7, 0xD8, 0xD9, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0x4A, 0xE0, 0x5A, 0x5F, 0x6D,
    0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
    0x97, 0x98, 0x99, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xC0, 0xBB, 0xD0, 0xA1,
};

int to_ebcdic(uint8_t *dst, const char *s, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c > 0x7E)
            return -1;
        dst[i] = ebcdic500[c - 0x20];
    }
    return 0;
}

int ddm_ebcdic(wb *w, uint16_t cp, const char *s, size_t pad)
{
    uint8_t buf[256];
    size_t n = strlen(s);
    size_t len = n < pad ? pad : n;
    if (len > sizeof buf || to_ebcdic(buf, s, n) < 0)
        return -1;
    memset(buf + n, 0x40, len - n);
    ddm_bytes(w, cp, buf, len);
    return 0;
}
