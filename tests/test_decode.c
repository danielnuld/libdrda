/* Decoder tests on bytes captured from Informix 15.0.1 over DRDA. */
#include "decode.h"
#include "wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond); \
            failures++;                                                 \
        }                                                               \
    } while (0)

static size_t unhex(const char *h, uint8_t *out)
{
    size_t n = 0;
    while (h[0] && h[1]) {
        unsigned v;
        sscanf(h, "%2x", &v);
        out[n++] = (uint8_t)v;
        h += 2;
    }
    return n;
}

/* ---- reader -------------------------------------------------------- */

static void test_reader(void)
{
    const uint8_t b[] = {0x01, 0x02, 0x03};
    rd r = rd_make(b, sizeof b);
    CHECK(rd_be16(&r) == 0x0102 && !r.err);
    CHECK(rd_be16(&r) == 0 && r.err);        /* underflow: zero, flagged */
    CHECK(r.n == 0 && rd_take(&r, 0) == NULL);  /* stays failed */

    r = rd_make(b, sizeof b);
    CHECK(rd_u16(&r, 1) == 0x0201);
    r = rd_make(b, sizeof b);
    {
        rd s = rd_sub(&r, 5);
        CHECK(s.err && r.err);
    }
}

/* ---- writer and framing -------------------------------------------- */

static void test_framing(void)
{
    wb w;
    wb_init(&w);
    dss_begin(&w, DSS_RQS, 1, 0x200D);
    ddm_u8(&w, 0x2116, 0xF1);
    dss_end(&w);
    dss_begin(&w, DSS_OBJ, 1, 0x2414);
    wb_u8(&w, 0xFF);
    dss_end(&w);
    CHECK(!w.err);
    /* First DSS: length 15, chained with the same correlator. */
    CHECK(w.p[0] == 0 && w.p[1] == 15 && w.p[2] == 0xD0 && w.p[3] == (0x01 | 0x40 | 0x10));
    CHECK(w.p[6] == 0 && w.p[7] == 9); /* object length = DSS - 6 */
    /* Last DSS: not chained. */
    CHECK(w.p[15 + 3] == 0x03);
    wb_free(&w);

    wb_init(&w);
    CHECK(ddm_ebcdic(&w, 0x2110, "ab", 4) == 0);
    CHECK(w.n == 8 && w.p[4] == 0x81 && w.p[5] == 0x82 && w.p[6] == 0x40);
    CHECK(ddm_ebcdic(&w, 0x2110, "\xc3\xb1", 0) < 0); /* not printable ASCII */
    wb_free(&w);

    wb_init(&w);
    dss_begin(&w, DSS_RQS, 1, 0x2414);
    {
        static uint8_t big[40000];
        wb_put(&w, big, sizeof big);
    }
    dss_end(&w);
    CHECK(w.err); /* over one segment: refused, not truncated */
    wb_free(&w);
}

/* ---- text ---------------------------------------------------------- */

static void test_text(void)
{
    wb w;
    const uint8_t latin1[] = {'A', 0xF1, 0xE1};
    const uint8_t bad[] = {'a', 0xC3, 'b', 0xED, 0xA0, 0x80}; /* cut + surrogate */
    wb_init(&w);
    CHECK(append_utf8(&w, latin1, 3, 819) == 0);
    CHECK(w.n == 5 && memcmp(w.p, "A\xc3\xb1\xc3\xa1", 5) == 0);
    w.n = 0;
    CHECK(append_utf8(&w, bad, sizeof bad, 1208) == 0);
    CHECK(w.n == 1 + 3 + 1 + 9 && utf8_valid(w.p, w.n)); /* each bad byte -> U+FFFD */
    CHECK(append_utf8(&w, latin1, 3, 1252) < 0);  /* unsupported: explicit */
    CHECK(!utf8_valid(bad, sizeof bad));
    CHECK(utf8_valid((const uint8_t *)"\xc3\xb1", 2));
    CHECK(!utf8_valid((const uint8_t *)"\xc0\xaf", 2)); /* overlong */
    wb_free(&w);
}

/* ---- SQLCA --------------------------------------------------------- */

/* SQLCARD after ACCRDB, with the extension group and tokens. */
static const char *CARD_OK =
    "00000000003030303030494658313231303000010000000100000001000000030000000000000000000000"
    "575720202020202020202000127379736d61737465722020202020202020200000002730ff383139ff696e"
    "666f726d6978ffff4944532f554e49583634ff31ff31ff30ff383139ff30ffff";
/* End of data: SQLCODE 100. */
static const char *CARD_100 =
    "00640000003032303030494658313231303000000000000000000002000000000000000000000000000000"
    "202020202020202020202000127379736d617374657220202020202020202000000000ff";
/* -23103 without the extension group. */
static const char *CARD_ERR = "00c1a5ffff49583030304946583132313030ffff";

static void test_sqlca(void)
{
    uint8_t b[512];
    size_t n;
    sqlca ca;
    rd r;

    n = unhex(CARD_OK, b);
    r = rd_make(b, n);
    CHECK(decode_sqlca(&r, 1, &ca) == 1);
    CHECK(ca.sqlcode == 0 && strcmp(ca.sqlstate, "00000") == 0);
    CHECK(ca.errd[0] == 1 && ca.errd[3] == 3);
    CHECK(ca.ntokens == 39 && ca.tokens[1] == 0xFF);
    CHECK(r.n == 0);

    n = unhex(CARD_100, b);
    r = rd_make(b, n);
    CHECK(decode_sqlca(&r, 1, &ca) == 1 && ca.sqlcode == 100);

    n = unhex(CARD_ERR, b);
    r = rd_make(b, n);
    CHECK(decode_sqlca(&r, 1, &ca) == 1 && ca.sqlcode == -23103);
    CHECK(strcmp(ca.sqlstate, "IX000") == 0);

    b[0] = 0xFF;
    r = rd_make(b, 1);
    CHECK(decode_sqlca(&r, 1, &ca) == 0);

    n = unhex(CARD_OK, b);
    r = rd_make(b, n - 10); /* truncated */
    CHECK(decode_sqlca(&r, 1, &ca) < 0);
}

/* ---- a whole query ------------------------------------------------- */

/* select first 2 tabid, tabname from systables */
static const char *DARD =
    "000000000020202020204946583132313030ffffff0200000000000400000000000000f00100000000000000"
    "000574616269640000000000000000ffff000000008000000000000000c1010333000000000000077461626e"
    "616d650000000000000000ffff";
static const char *DSC = "0976d00200043300800971e0540001d000010671f0e00000";
static const char *DTA =
    "ff00010000000000097379737461626c6573ff000200000000000a737973636f6c756d6e73";

static void test_query(void)
{
    uint8_t b[512];
    size_t n, off[2];
    sqlca ca;
    dcol *cols;
    int ncols, rc;
    wb cells;
    rd r;

    n = unhex(DARD, b);
    r = rd_make(b, n);
    CHECK(decode_sqldard(&r, 1, 819, &ca, &cols, &ncols) == 0);
    CHECK(ncols == 2);
    if (ncols != 2)
        return;
    CHECK(strcmp(cols[0].name, "tabid") == 0 && cols[0].sqltype == 496);
    CHECK(strcmp(cols[1].name, "tabname") == 0 && cols[1].sqltype == 449);
    CHECK(cols[1].ccsid == 819);

    n = unhex(DSC, b);
    r = rd_make(b, n);
    CHECK(decode_qrydsc(&r, cols, ncols) == 0);
    CHECK(cols[0].fdtype == 0x02 && cols[0].fdlen == 4);
    CHECK(cols[1].fdtype == 0x33 && cols[1].fdlen == 128);
    CHECK(fd_supported(0x33) && !fd_supported(0xC9));

    n = unhex(DTA, b);
    wb_init(&cells);
    r = rd_make(b, n);
    rc = decode_row(&r, 1, cols, ncols, &cells, off, &ca);
    CHECK(rc == 1);
    CHECK(strcmp((char *)cells.p + off[0], "1") == 0);
    CHECK(strcmp((char *)cells.p + off[1], "systables") == 0);
    cells.n = 0;
    CHECK(decode_row(&r, 1, cols, ncols, &cells, off, &ca) == 1);
    CHECK(strcmp((char *)cells.p + off[1], "syscolumns") == 0);
    CHECK(r.n == 0 && decode_row(&r, 1, cols, ncols, &cells, off, &ca) == 0);

    /* A row cut anywhere is "incomplete" and leaves the reader untouched. */
    {
        size_t cut;
        for (cut = 1; cut < 18; cut++) {
            rd t = rd_make(b, cut);
            cells.n = 0;
            CHECK(decode_row(&t, 1, cols, ncols, &cells, off, &ca) == 0);
            CHECK(t.n == cut && cells.n == 0);
        }
    }

    /* The wrong column count in QRYDSC is refused. */
    n = unhex(DSC, b);
    r = rd_make(b, n);
    CHECK(decode_qrydsc(&r, cols, 1) < 0);

    wb_free(&cells);
    free_cols(cols, ncols);
}

/* ---- value rendering ----------------------------------------------- */

static const char *one(uint8_t fdtype, uint16_t fdlen, const char *hex, int ccsid)
{
    static wb cells;
    static char out[128];
    uint8_t b[128];
    size_t n, off[1];
    dcol col;
    sqlca ca;
    rd r;
    memset(&col, 0, sizeof col);
    col.fdtype = fdtype;
    col.fdlen = fdlen;
    col.ccsid = ccsid;
    b[0] = 0xFF; /* no SQLCA */
    b[1] = 0x00; /* row data present */
    n = 2 + unhex(hex, b + 2);
    wb_init(&cells);
    r = rd_make(b, n);
    if (decode_row(&r, 1, &col, 1, &cells, off, &ca) != 1)
        snprintf(out, sizeof out, "<error>");
    else if (off[0] == (size_t)-1)
        snprintf(out, sizeof out, "<null>");
    else
        snprintf(out, sizeof out, "%s", (char *)cells.p + off[0]);
    wb_free(&cells);
    return out;
}

static void test_values(void)
{
    CHECK(strcmp(one(0x03, 4, "00d6ffffff", 0), "-42") == 0);
    CHECK(strcmp(one(0x03, 4, "ff", 0), "<null>") == 0);
    CHECK(strcmp(one(0x17, 8, "000100000000002000", 0), "9007199254740993") == 0);
    CHECK(strcmp(one(0x05, 2, "000780", 0), "-32761") == 0);
    CHECK(strcmp(one(0x0B, 8, "006e861bf0f9210940", 0), "3.14159") == 0);
    CHECK(strcmp(one(0x0D, 4, "00cdcccc3d", 0), "0.1") == 0);
    /* DECIMAL(12,3) -1234.567 and DECIMAL(5,0) 99999 */
    CHECK(strcmp(one(0x0F, 12 << 8 | 3, "000000001234567d", 0), "-1234.567") == 0);
    CHECK(strcmp(one(0x0F, 5 << 8 | 0, "0099999c", 0), "99999") == 0);
    CHECK(strcmp(one(0x0F, 5 << 8 | 2, "0000005c", 0), "0.05") == 0);
    CHECK(strcmp(one(0x0F, 5 << 8 | 2, "00000fac", 0), "<error>") == 0); /* bad digit */
    CHECK(strcmp(one(0x33, 40, "000002f16f", 819), "\xc3\xb1o") == 0);
    CHECK(strcmp(one(0x31, 5, "006162202020", 819), "ab   ") == 0);
    CHECK(strcmp(one(0x25, 26, "00323032362d30392d32322d31332e34352e31302e313233303030", 0),
                 "2026-09-22 13:45:10.123000") == 0);
    CHECK(strcmp(one(0x23, 8, "0031332e34352e3030", 0), "13:45:00") == 0);
    CHECK(strcmp(one(0x29, 10, "000002beef", 0), "beef") == 0);
    CHECK(strcmp(one(0xBF, 1, "0001", 0), "t") == 0);
}

/* Garbage in must never read out of bounds: run under a sanitizer. Seeds
 * are the real captures, mutated and truncated. */
static void test_garbage(void)
{
    const char *seeds[] = {CARD_OK, CARD_100, CARD_ERR, DARD, DSC, DTA};
    uint32_t x = 12345;
    size_t s, iter;
    for (s = 0; s < sizeof seeds / sizeof seeds[0]; s++) {
        uint8_t base[512], b[512];
        size_t n = unhex(seeds[s], base);
        for (iter = 0; iter < 20000; iter++) {
            size_t len = n, k, off[4];
            dcol cols[4], *dc;
            int nc;
            sqlca ca;
            wb cells;
            rd r;
            memcpy(b, base, n);
            for (k = 0; k < 1 + iter % 4; k++) {
                x = x * 1103515245u + 12345u;
                b[(x >> 8) % n] = (uint8_t)(x >> 16);
            }
            x = x * 1103515245u + 12345u;
            if (iter % 3 == 0)
                len = (x >> 8) % (n + 1);
            r = rd_make(b, len);
            decode_sqlca(&r, 1, &ca);
            r = rd_make(b, len);
            if (decode_sqldard(&r, 1, 819, &ca, &dc, &nc) == 0)
                free_cols(dc, nc);
            memset(cols, 0, sizeof cols);
            r = rd_make(b, len);
            decode_qrydsc(&r, cols, 4);
            cols[0].fdtype = 0x03; cols[0].fdlen = 4;
            cols[1].fdtype = 0x33; cols[1].fdlen = 128; cols[1].ccsid = 819;
            cols[2].fdtype = 0x0F; cols[2].fdlen = (uint16_t)(b[0] << 8 | b[1]);
            cols[3].fdtype = 0x25; cols[3].fdlen = b[2];
            wb_init(&cells);
            r = rd_make(b, len);
            while (decode_row(&r, 1, cols, 4, &cells, off, &ca) == 1)
                cells.n = 0;
            wb_free(&cells);
        }
    }
}

int main(void)
{
    test_reader();
    test_framing();
    test_text();
    test_sqlca();
    test_query();
    test_values();
    test_garbage();
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("all decode checks passed\n");
    return 0;
}
