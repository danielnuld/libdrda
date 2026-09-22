/* Decoding of DRDA reply structures: SQLCA, SQLDARD (column names),
 * QRYDSC (row layout) and QRYDTA rows rendered as UTF-8 text. Pure code. */
#ifndef DRDA_DECODE_H
#define DRDA_DECODE_H

#include "wire.h"

typedef struct {
    int32_t sqlcode;
    char sqlstate[6];
    int32_t errd[6];
    uint8_t tokens[256]; /* message tokens, 0xFF-separated, server CCSID */
    size_t ntokens;
} sqlca;

typedef struct {
    char *name;       /* UTF-8, owned */
    int sqltype;      /* DB2 SQLTYPE from the SQLDA (odd = nullable) */
    int ccsid;        /* character columns; 0 for the rest */
    uint8_t fdtype;   /* FD:OCA data type from QRYDSC */
    uint16_t fdlen;   /* its length, or precision << 8 | scale for DECIMAL */
} dcol;

/* A nullable SQLCAGRP (flag byte first). 1 = present, 0 = null, -1 = bad. */
int decode_sqlca(rd *r, int le, sqlca *ca);

/* SQLDARD body. Allocates *cols (free with free_cols). 0 ok, -1 malformed. */
int decode_sqldard(rd *r, int le, int ccsid, sqlca *ca, dcol **cols, int *ncols);
void free_cols(dcol *cols, int ncols);

/* QRYDSC body: fills fdtype/fdlen of cols[0..ncols). 0 ok, -1 malformed or
 * a column count that does not match the SQLDA. */
int decode_qrydsc(rd *r, dcol *cols, int ncols);

/* Whether a row of this FD:OCA type can be rendered. */
int fd_supported(uint8_t fdtype);

/* Large objects (TEXT, BYTE) travel outside the row, in EXTDTA objects. */
int fd_is_lob(uint8_t fdtype);
#define LOB_PENDING ((size_t)-2)

/* One row. `cells` receives NUL-terminated UTF-8 texts; off[i] is the
 * offset of column i in cells->p, (size_t)-1 for SQL NULL, or LOB_PENDING
 * for a large object whose byte length is lobn[i] (lobn may be NULL when no
 * column is a large object).
 * Returns 1 = row, 0 = incomplete (r is left untouched), 2 = end of data,
 * -1 = error (ca filled when the server reported one, else malformed). */
int decode_row(rd *r, int le, const dcol *cols, int ncols, wb *cells, size_t *off,
               uint64_t *lobn, sqlca *ca);

/* Render the EXTDTA body of a large object of column c. -1 if its length
 * does not match the row's placeholder or the text cannot be converted. */
int decode_lob(rd *ext, const dcol *c, uint64_t len, wb *cells);

/* Convert server text in `ccsid` to UTF-8, appended to w. -1 if the CCSID
 * is not supported. 0 means "no CCSID" and is treated as UTF-8. */
int ccsid_supported(int ccsid);
int utf8_valid(const uint8_t *p, size_t n);
int append_utf8(wb *w, const uint8_t *p, size_t n, int ccsid);

#endif
