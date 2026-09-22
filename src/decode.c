#include "decode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- text ---------------------------------------------------------- */

int ccsid_supported(int ccsid)
{
    return ccsid == 0 || ccsid == 1208 || ccsid == 819;
}

static void put_utf8(wb *w, uint32_t c)
{
    uint8_t b[3];
    if (c < 0x80) {
        wb_u8(w, (uint8_t)c);
    } else if (c < 0x800) {
        b[0] = (uint8_t)(0xC0 | c >> 6);
        b[1] = (uint8_t)(0x80 | (c & 0x3F));
        wb_put(w, b, 2);
    } else {
        b[0] = (uint8_t)(0xE0 | c >> 12);
        b[1] = (uint8_t)(0x80 | (c >> 6 & 0x3F));
        b[2] = (uint8_t)(0x80 | (c & 0x3F));
        wb_put(w, b, 3);
    }
}

/* Length of a valid UTF-8 sequence at p, or 0. */
static size_t utf8_seq(const uint8_t *p, size_t n)
{
    size_t len, i;
    uint32_t c;
    if (p[0] < 0x80)
        return 1;
    if ((p[0] & 0xE0) == 0xC0) { len = 2; c = p[0] & 0x1F; }
    else if ((p[0] & 0xF0) == 0xE0) { len = 3; c = p[0] & 0x0F; }
    else if ((p[0] & 0xF8) == 0xF0) { len = 4; c = p[0] & 0x07; }
    else return 0;
    if (len > n)
        return 0;
    for (i = 1; i < len; i++) {
        if ((p[i] & 0xC0) != 0x80)
            return 0;
        c = c << 6 | (p[i] & 0x3F);
    }
    if ((len == 2 && c < 0x80) || (len == 3 && c < 0x800) || (len == 4 && c < 0x10000) ||
        c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF))
        return 0; /* overlong, out of range or a surrogate */
    return len;
}

int utf8_valid(const uint8_t *p, size_t n)
{
    size_t i = 0;
    while (i < n) {
        size_t len = utf8_seq(p + i, n - i);
        if (!len)
            return 0;
        i += len;
    }
    return 1;
}

int append_utf8(wb *w, const uint8_t *p, size_t n, int ccsid)
{
    size_t i = 0;
    if (ccsid == 819) {
        for (i = 0; i < n; i++)
            put_utf8(w, p[i]);
        return 0;
    }
    if (ccsid != 0 && ccsid != 1208)
        return -1;
    /* Invalid bytes become U+FFFD: a consumer must never get broken UTF-8. */
    while (i < n) {
        size_t len = utf8_seq(p + i, n - i);
        if (len) {
            wb_put(w, p + i, len);
            i += len;
        } else {
            put_utf8(w, 0xFFFD);
            i++;
        }
    }
    return 0;
}

/* ---- SQLCA --------------------------------------------------------- */

int decode_sqlca(rd *r, int le, sqlca *ca)
{
    const uint8_t *p;
    size_t n, i;
    memset(ca, 0, sizeof *ca);
    if (rd_u8(r) == 0xFF)
        return r->err ? -1 : 0;
    ca->sqlcode = (int32_t)rd_u32(r, le);
    p = rd_take(r, 5);
    if (p)
        memcpy(ca->sqlstate, p, 5);
    rd_take(r, 8); /* SQLERRPROC */
    if (rd_u8(r) == 0x00) { /* SQLCAXGRP */
        const uint8_t *m, *s;
        size_t mn, sn;
        for (i = 0; i < 6; i++)
            ca->errd[i] = (int32_t)rd_u32(r, le);
        rd_take(r, 11);  /* SQLWARN */
        rd_vcs(r, &n);   /* SQLRDBNAME */
        m = rd_vcs(r, &mn);
        s = rd_vcs(r, &sn);
        if (!mn) {
            m = s;
            mn = sn;
        }
        if (mn > sizeof ca->tokens)
            mn = sizeof ca->tokens;
        if (m)
            memcpy(ca->tokens, m, mn);
        ca->ntokens = mn;
    }
    /* SQLDIAGGRP: only its null form is understood. */
    if (rd_u8(r) != 0xFF)
        return -1;
    return r->err ? -1 : 1;
}

/* ---- SQLDARD ------------------------------------------------------- */

static void skip_vcs(rd *r, int count)
{
    size_t n;
    while (count--)
        rd_vcs(r, &n);
}

void free_cols(dcol *cols, int ncols)
{
    int i;
    if (!cols)
        return;
    for (i = 0; i < ncols; i++)
        free(cols[i].name);
    free(cols);
}

static char *utf8_name(const uint8_t *p, size_t n, int ccsid)
{
    wb w;
    char *s;
    wb_init(&w);
    if (append_utf8(&w, p, n, ccsid) < 0) {
        wb_free(&w);
        return NULL;
    }
    wb_u8(&w, 0);
    if (w.err) {
        wb_free(&w);
        return NULL;
    }
    s = (char *)w.p;
    return s;
}

int decode_sqldard(rd *r, int le, int ccsid, sqlca *ca, dcol **out, int *ncols)
{
    dcol *cols;
    int n, i;
    *out = NULL;
    *ncols = 0;
    if (decode_sqlca(r, le, ca) < 0)
        return -1;
    if (ca->sqlcode < 0)
        return 0;
    if (rd_u8(r) == 0x00) { /* SQLDHGRP */
        rd_take(r, 12);
        skip_vcs(r, 3);
    }
    n = (int16_t)rd_u16(r, le);
    if (r->err || n < 0)
        return -1;
    if (n == 0)
        return 0;
    cols = (dcol *)calloc((size_t)n, sizeof *cols);
    if (!cols)
        return -1;
    for (i = 0; i < n; i++) {
        dcol *c = &cols[i];
        const uint8_t *m, *s;
        size_t mn = 0, sn = 0;
        rd_u16(r, le);           /* SQLPRECISION */
        rd_u16(r, le);           /* SQLSCALE */
        rd_u64(r, le);           /* SQLLENGTH */
        c->sqltype = (int16_t)rd_u16(r, le);
        c->ccsid = rd_be16(r);
        m = s = NULL;
        if (rd_u8(r) == 0x00) {  /* SQLDOPTGRP */
            rd_u16(r, le);       /* SQLUNNAMED */
            m = rd_vcs(r, &mn);
            s = rd_vcs(r, &sn);
            skip_vcs(r, 4);      /* label and comments, mixed and single */
            if (rd_u8(r) == 0x00) { /* SQLUDTGRP */
                rd_u32(r, le);
                skip_vcs(r, 5);
            }
            if (rd_u8(r) == 0x00) { /* SQLDXGRP */
                rd_take(r, 8);
                skip_vcs(r, 9);
            }
        }
        if (r->err)
            break;
        if (!mn) {
            m = s;
            mn = sn;
        }
        c->name = utf8_name(m, mn, ccsid);
        if (!c->name)
            break;
    }
    if (i < n) {
        free_cols(cols, n);
        return -1;
    }
    *out = cols;
    *ncols = n;
    return 0;
}

/* ---- QRYDSC -------------------------------------------------------- */

int decode_qrydsc(rd *r, dcol *cols, int ncols)
{
    int k = 0;
    while (r->n && !r->err) {
        uint8_t len = rd_u8(r), type = rd_u8(r);
        rd t;
        rd_u8(r); /* triplet id */
        if (len < 3)
            return -1;
        t = rd_sub(r, (size_t)len - 3);
        if (type == 0x71) /* row layout: the column descriptions are done */
            break;
        if (type != 0x75 && type != 0x76 && type != 0x7F)
            continue; /* e.g. MDD triplets */
        while (t.n && !t.err) {
            uint8_t ft = rd_u8(&t);
            uint16_t fl = rd_be16(&t);
            if (k >= ncols)
                return -1;
            cols[k].fdtype = ft;
            cols[k].fdlen = fl;
            k++;
        }
        if (t.err)
            return -1;
    }
    return r->err || k != ncols ? -1 : 0;
}

/* ---- rows ---------------------------------------------------------- */

int fd_supported(uint8_t t)
{
    switch (t | 1) {
    case 0x03: case 0x05: case 0x07: case 0x17: /* integers */
    case 0x0B: case 0x0D:                       /* floats */
    case 0x0F:                                  /* packed decimal */
    case 0x21: case 0x23: case 0x25:            /* date, time, timestamp */
    case 0x31: case 0x3D:                       /* fixed char */
    case 0x33: case 0x35: case 0x3F: case 0x41: /* varying char */
    case 0x27: case 0x29:                       /* bytes */
    case 0xBF:                                  /* boolean */
        return 1;
    default:
        return fd_is_lob(t);
    }
}

int fd_is_lob(uint8_t t)
{
    t |= 1;
    return t == 0xC9 || t == 0xCB || t == 0xCF; /* bytes, single-byte and mixed char */
}

static void put_str(wb *w, const char *s) { wb_put(w, s, strlen(s)); }

static int64_t rd_signed(rd *r, size_t n, int le)
{
    const uint8_t *p = rd_take(r, n);
    uint64_t v = 0;
    size_t i;
    if (!p || n == 0 || n > 8)
        return 0;
    for (i = 0; i < n; i++)
        v = v << 8 | p[le ? n - 1 - i : i];
    if (n < 8 && (v >> (8 * n - 1) & 1))
        v |= ~(uint64_t)0 << (8 * n); /* sign-extend */
    return (int64_t)v;
}

static void put_double(wb *w, double d)
{
    char buf[40];
    snprintf(buf, sizeof buf, "%.15g", d);
    if (strtod(buf, NULL) != d)
        snprintf(buf, sizeof buf, "%.17g", d);
    put_str(w, buf);
}

static int put_decimal(wb *w, const uint8_t *p, int prec, int scale)
{
    size_t nbytes = (size_t)prec / 2 + 1, ndig = nbytes * 2 - 1, i, lead;
    char dig[64];
    uint8_t sign = p[nbytes - 1] & 0x0F;
    if (ndig > sizeof dig || scale > (int)ndig)
        return -1;
    for (i = 0; i < ndig; i++) {
        uint8_t v = (uint8_t)(i % 2 ? p[i / 2] & 0x0F : p[i / 2] >> 4);
        if (v > 9)
            return -1;
        dig[i] = (char)('0' + v);
    }
    if (sign == 0x0D || sign == 0x0B)
        wb_u8(w, '-');
    /* Integer part without leading zeros, but at least one digit. */
    lead = 0;
    while (lead + 1 < ndig - (size_t)scale && dig[lead] == '0')
        lead++;
    wb_put(w, dig + lead, ndig - (size_t)scale - lead);
    if (scale > 0) {
        wb_u8(w, '.');
        wb_put(w, dig + ndig - (size_t)scale, (size_t)scale);
    }
    return 0;
}

static void put_hex(wb *w, const uint8_t *p, size_t n)
{
    static const char hx[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        wb_u8(w, (uint8_t)hx[p[i] >> 4]);
        wb_u8(w, (uint8_t)hx[p[i] & 0x0F]);
    }
}

/* DB2 renders TIMESTAMP as YYYY-MM-DD-HH.MM.SS.ffffff and TIME as
 * HH.MM.SS; show them the way Informix does. */
static void put_datetime(wb *w, const uint8_t *p, size_t n, uint8_t kind)
{
    char buf[64];
    size_t i;
    if (n > sizeof buf)
        n = sizeof buf;
    memcpy(buf, p, n);
    while (n && buf[n - 1] == ' ')
        n--;
    if (kind == 0x25 && n >= 19 && buf[10] == '-' && buf[13] == '.' && buf[16] == '.') {
        buf[10] = ' ';
        buf[13] = buf[16] = ':';
    } else if (kind == 0x23) {
        for (i = 0; i < n; i++)
            if (buf[i] == '.')
                buf[i] = ':';
    }
    wb_put(w, buf, n);
}

static int decode_cell(rd *r, int le, const dcol *c, wb *w)
{
    uint8_t t = c->fdtype | 1;
    const uint8_t *p;
    size_t n;
    char buf[32];
    switch (t) {
    case 0x03: case 0x05: case 0x07: case 0x17:
        snprintf(buf, sizeof buf, "%lld", (long long)rd_signed(r, c->fdlen, le));
        put_str(w, buf);
        return 0;
    case 0x0B: {
        uint64_t u = rd_u64(r, le);
        double d;
        memcpy(&d, &u, sizeof d);
        put_double(w, d);
        return 0;
    }
    case 0x0D: {
        uint32_t u = rd_u32(r, le);
        float f;
        memcpy(&f, &u, sizeof f);
        snprintf(buf, sizeof buf, "%.7g", (double)f);
        if (strtof(buf, NULL) != f)
            snprintf(buf, sizeof buf, "%.9g", (double)f);
        put_str(w, buf);
        return 0;
    }
    case 0x0F: {
        int prec = c->fdlen >> 8, scale = c->fdlen & 0xFF;
        p = rd_take(r, (size_t)prec / 2 + 1);
        return p ? put_decimal(w, p, prec, scale) : 0;
    }
    case 0x21: case 0x23: case 0x25:
        p = rd_take(r, c->fdlen);
        if (p)
            put_datetime(w, p, c->fdlen, t);
        return 0;
    case 0x31: case 0x3D:
        n = c->fdlen;
        break;
    case 0x33: case 0x35: case 0x3F: case 0x41:
        n = rd_be16(r);
        break;
    case 0x27:
        p = rd_take(r, c->fdlen & 0x7FFF);
        if (p)
            put_hex(w, p, c->fdlen & 0x7FFF);
        return 0;
    case 0x29:
        n = rd_be16(r);
        p = rd_take(r, n);
        if (p)
            put_hex(w, p, n);
        return 0;
    case 0xBF:
        put_str(w, rd_u8(r) ? "t" : "f");
        return 0;
    default:
        return -1;
    }
    p = rd_take(r, n);
    if (p && append_utf8(w, p, n, c->ccsid) < 0)
        return -1;
    return 0;
}

int decode_lob(rd *ext, const dcol *c, uint64_t len, wb *cells)
{
    const uint8_t *p;
    if (c->fdtype & 1)
        rd_u8(ext); /* status byte of a nullable large object */
    if (ext->err || ext->n != len)
        return -1;
    p = rd_take(ext, ext->n);
    if ((c->fdtype | 1) == 0xC9) {
        put_hex(cells, p, (size_t)len);
        return 0;
    }
    return append_utf8(cells, p, (size_t)len, c->ccsid);
}

int decode_row(rd *r, int le, const dcol *cols, int ncols, wb *cells, size_t *off,
               uint64_t *lobn, sqlca *ca)
{
    rd save = *r;
    size_t start = cells->n;
    uint8_t flag;
    int i;

    memset(ca, 0, sizeof *ca);
    if (r->n == 0)
        return 0;
    if (r->p[0] != 0xFF) { /* the row carries an SQLCA */
        if (decode_sqlca(r, le, ca) < 0)
            goto incomplete;
        if (ca->sqlcode == 100)
            return 2;
        if (ca->sqlcode < 0)
            return -1;
    } else {
        rd_u8(r);
    }
    flag = rd_u8(r);
    if (r->err)
        goto incomplete;
    if (flag != 0x00)
        return -1; /* no row data without an end-of-data SQLCA */

    for (i = 0; i < ncols; i++) {
        if ((cols[i].fdtype & 1) && rd_u8(r) >= 0x80) {
            off[i] = (size_t)-1;
            continue;
        }
        if (fd_is_lob(cols[i].fdtype)) {
            /* The row holds only the length; the bytes follow in EXTDTA. */
            uint64_t n = (uint64_t)rd_signed(r, cols[i].fdlen & 0x7FFF, le);
            if (r->err)
                goto incomplete;
            if (!lobn)
                return -1;
            lobn[i] = n;
            off[i] = LOB_PENDING;
            continue;
        }
        off[i] = cells->n;
        if (decode_cell(r, le, &cols[i], cells) < 0 && !r->err)
            return -1;
        if (r->err)
            goto incomplete;
        wb_u8(cells, 0);
    }
    if (cells->err)
        return -1;
    return 1;

incomplete:
    *r = save;
    cells->n = start;
    return 0;
}
