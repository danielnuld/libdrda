#include "drda.h"

#include "decode.h"
#include "wire.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET sock_t;
#define BAD_SOCK INVALID_SOCKET
#define sock_close closesocket
#else
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int sock_t;
#define BAD_SOCK (-1)
#define sock_close close
#endif

/* DDM code points. */
enum {
    EXCSAT = 0x1041, ACCSEC = 0x106D, SECCHK = 0x106E, ACCRDB = 0x2001,
    CLSQRY = 0x2005, CNTQRY = 0x2006, EXCSQLSTT = 0x200B, OPNQRY = 0x200C,
    PRPSQLSTT = 0x200D, RDBCMM = 0x200E, RDBRLLBCK = 0x200F,
    SQLSTT = 0x2414,
    EXCSATRD = 0x1443, ACCSECRD = 0x14AC, EXTDTA = 0x146C,
    SQLCARD = 0x2408, SQLDARD = 0x2411, QRYDSC = 0x241A, QRYDTA = 0x241B,
    SECCHKRM = 0x1219, ACCRDBRM = 0x2201, OPNQRYRM = 0x2205, ENDQRYRM = 0x220B,
    ENDUOWRM = 0x220C,
    AGENT = 0x1403, SQLAM = 0x2407, RDB = 0x240F, SECMGR = 0x1440, CMNTCPIP = 0x1474,
    EXTNAM = 0x115E, SRVNAM = 0x116D, SRVRLSLV = 0x115A, SRVCLSNM = 0x1147,
    MGRLVLLS = 0x1404, SECMEC = 0x11A2, RDBNAM = 0x2110, USRID = 0x11A0,
    PASSWORD = 0x11A1, SECCHKCD = 0x11A4, SVRCOD = 0x1149, RDBACCCL = 0x210F,
    PRDID = 0x112E, TYPDEFNAM = 0x002F, TYPDEFOVR = 0x0035, CCSIDSBC = 0x119C,
    CCSIDDBC = 0x119D, CCSIDMBC = 0x119E, PKGNAMCSN = 0x2113, RTNSQLDA = 0x2116,
    RDBCMTOK = 0x2105, QRYBLKSZ = 0x2114, MAXBLKEXT = 0x2141, QRYCLSIMP = 0x215D,
    QRYINSID = 0x215B, SRVDGN = 0x1153, RTNEXTDTA = 0x2148,
    DSCSQLSTT = 0x2008, TYPSQLDA = 0x2146, SQLDTA = 0x2412,
};

#define SECMEC_USRIDPWD 3
/* Blocks up to one DSS segment, so replies never need continuation. */
#define BLOCK_SIZE 32767
#define MAX_REPLY (64u << 20) /* refuse a reply chain larger than this */

typedef struct {
    uint16_t cp, corr;
    size_t off, len;
} obj;

struct drda_conn {
    sock_t s;
    int le;
    int ccsid;
    char rdbnam[19];
    char err[512];
    int sqlcode;
    char sqlstate[6];
    drda_result *open;
    wb in;      /* payload bytes of the current reply chain */
    obj *objs;
    int nobj, capobj;
};

struct drda_result {
    drda_conn *c;
    dcol *cols;
    int ncols;
    wb data;    /* QRYDTA bytes not decoded yet start at data.p + pos */
    size_t pos;
    uint64_t qryinsid;
    int ended;
    wb cells;
    size_t *off;
    uint64_t *lobn; /* large object lengths of the current row, if any */
    wb ext;         /* EXTDTA bodies not consumed yet: [be32 len][bytes]... */
    size_t ext_pos;
    int have_row;
    long long affected;
};

static int fail(drda_conn *c, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(c->err, sizeof c->err, fmt, ap);
    va_end(ap);
    return -1;
}

/* ---- socket -------------------------------------------------------- */

static int send_all(drda_conn *c, const uint8_t *p, size_t n)
{
    while (n) {
        int k = (int)send(c->s, (const char *)p, (int)(n > 0x10000 ? 0x10000 : n), 0);
        if (k <= 0)
            return fail(c, "connection lost while sending");
        p += k;
        n -= (size_t)k;
    }
    return 0;
}

static int recv_all(drda_conn *c, uint8_t *p, size_t n)
{
    while (n) {
        int k = (int)recv(c->s, (char *)p, (int)(n > 0x10000 ? 0x10000 : n), 0);
        if (k <= 0)
            return fail(c, "connection closed by the server");
        p += k;
        n -= (size_t)k;
    }
    return 0;
}

static sock_t dial(const char *host, int port)
{
    struct addrinfo hints, *res, *ai;
    char svc[16];
    sock_t s = BAD_SOCK;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(svc, sizeof svc, "%d", port);
    if (getaddrinfo(host, svc, &hints, &res) != 0)
        return BAD_SOCK;
    for (ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == BAD_SOCK)
            continue;
        if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0)
            break;
        sock_close(s);
        s = BAD_SOCK;
    }
    freeaddrinfo(res);
    if (s != BAD_SOCK) {
        int one = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
    }
    return s;
}

/* ---- framing ------------------------------------------------------- */

static int send_wb(drda_conn *c, wb *w)
{
    int rc;
    if (w->err)
        rc = fail(c, "request too large or out of memory");
    else
        rc = send_all(c, w->p, w->n);
    wb_free(w);
    return rc;
}

static int add_obj(drda_conn *c, uint16_t cp, uint16_t corr, size_t off, size_t len)
{
    if (c->nobj == c->capobj) {
        int cap = c->capobj ? c->capobj * 2 : 16;
        obj *n = (obj *)realloc(c->objs, (size_t)cap * sizeof *n);
        if (!n)
            return fail(c, "out of memory");
        c->objs = n;
        c->capobj = cap;
    }
    c->objs[c->nobj].cp = cp;
    c->objs[c->nobj].corr = corr;
    c->objs[c->nobj].off = off;
    c->objs[c->nobj].len = len;
    c->nobj++;
    return 0;
}

/* Read a payload of n bytes onto the end of c->in. */
static int recv_payload(drda_conn *c, size_t n)
{
    if (c->in.n + n > MAX_REPLY)
        return fail(c, "reply larger than %u MB", MAX_REPLY >> 20);
    if (wb_reserve(&c->in, n) < 0)
        return fail(c, "out of memory");
    if (recv_all(c, c->in.p + c->in.n, n) < 0)
        return -1;
    c->in.n += n;
    return 0;
}

/* Read one reply chain: DSS after DSS until one without the chain bit.
 * Every DDM object lands in c->objs, its bytes in c->in. */
static int read_chain(drda_conn *c)
{
    int chained = 1;
    c->in.n = 0;
    c->nobj = 0;
    while (chained) {
        uint8_t h[6];
        size_t len, start = c->in.n;
        int more;
        rd r;
        if (recv_all(c, h, 6) < 0)
            return -1;
        if (h[2] != 0xD0)
            return fail(c, "not a DRDA reply (is the port a drsoctcp listener?)");
        len = (size_t)(h[0] << 8 | h[1]);
        chained = h[3] & 0x40;
        more = (len & 0x8000) != 0;
        len &= 0x7FFF;
        if (len < 6)
            return fail(c, "malformed reply header");
        if (recv_payload(c, len - 6) < 0)
            return -1;
        while (more) { /* continuation segments */
            uint8_t l2[2];
            if (recv_all(c, l2, 2) < 0)
                return -1;
            len = (size_t)(l2[0] << 8 | l2[1]);
            more = (len & 0x8000) != 0;
            len &= 0x7FFF;
            if (len < 2)
                return fail(c, "malformed continuation header");
            if (recv_payload(c, len - 2) < 0)
                return -1;
        }
        r = rd_make(c->in.p + start, c->in.n - start);
        while (r.n) {
            uint16_t ll = rd_be16(&r), cp = rd_be16(&r);
            size_t dlen;
            if (ll & 0x8000) { /* extended length: the next bytes hold it */
                size_t k = (size_t)(ll & 0x7FFF) - 4, i;
                const uint8_t *e;
                if ((ll & 0x7FFF) < 4 || k > 8)
                    return fail(c, "malformed extended length");
                e = rd_take(&r, k);
                dlen = 0;
                for (i = 0; e && i < k; i++)
                    dlen = dlen << 8 | e[i];
            } else {
                if (ll < 4)
                    return fail(c, "malformed object length");
                dlen = (size_t)ll - 4;
            }
            if (r.err || dlen > r.n)
                return fail(c, "truncated reply object");
            if (add_obj(c, cp, (uint16_t)(h[4] << 8 | h[5]), (size_t)(r.p - c->in.p), dlen) < 0)
                return -1;
            rd_take(&r, dlen);
        }
    }
    return 0;
}

static rd obj_rd(const drda_conn *c, int i)
{
    return rd_make(c->in.p + c->objs[i].off, c->objs[i].len);
}

/* Find parameter `want` inside a DDM object's body. */
static int find_param(rd body, uint16_t want, rd *out)
{
    while (body.n && !body.err) {
        uint16_t ll = rd_be16(&body), cp = rd_be16(&body);
        rd v;
        if (ll < 4)
            return 0;
        v = rd_sub(&body, (size_t)ll - 4);
        if (v.err)
            return 0;
        if (cp == want) {
            *out = v;
            return 1;
        }
    }
    return 0;
}

static const char *rm_name(uint16_t cp)
{
    switch (cp) {
    case 0x2211: return "database not found (RDBNFNRM)";
    case 0x221A: return "database access failed (RDBAFLRM)";
    case 0x22CB: return "not authorized to the database (RDBATHRM)";
    case 0x2204: return "database not accessed (RDBNACRM)";
    case 0x2207: return "database already accessed (RDBACCRM)";
    case 0x124C: return "data stream syntax error (SYNTAXRM)";
    case 0x1245: return "conversation protocol error (PRCCNVRM)";
    case 0x1250: return "command not supported (CMDNSPRM)";
    case 0x1251: return "parameter not supported (PRMNSPRM)";
    case 0x1252: return "parameter value not supported (VALNSPRM)";
    case 0x1253: return "object not supported (OBJNSPRM)";
    case 0x1210: return "manager level conflict (MGRLVLRM)";
    case 0x1232: return "permanent agent error (AGNPRMRM)";
    case 0x1254: return "command check (CMDCHKRM)";
    case 0x2213: return "SQL error (SQLERRRM)";
    case 0x2212: return "open query failure (OPNQFLRM)";
    case 0x2202: return "query not open (QRYNOPRM)";
    case 0x220E: return "data descriptor mismatch (DTAMCHRM)";
    case 0x220D: return "unit of work ended abnormally (ABNUOWRM)";
    case 0x1233: return "resource limit reached (RSCLMTRM)";
    default: return NULL;
    }
}

static void to_utf8_msg(wb *w, const uint8_t *p, size_t n, int ccsid)
{
    size_t i, s = 0;
    for (i = 0; i <= n; i++) {
        if (i == n || p[i] == 0xFF) {
            if (i > s) {
                if (w->n)
                    wb_put(w, ", ", 2);
                append_utf8(w, p + s, i - s, ccsid ? ccsid : 819);
            }
            s = i + 1;
        }
    }
}

/* Record an SQLCA; a negative SQLCODE becomes the connection error. */
static int apply_sqlca(drda_conn *c, const sqlca *ca)
{
    c->sqlcode = ca->sqlcode;
    memcpy(c->sqlstate, ca->sqlstate[0] ? ca->sqlstate : "00000", 6);
    if (ca->sqlcode >= 0)
        return 0;
    {
        wb w;
        wb_init(&w);
        to_utf8_msg(&w, ca->tokens, ca->ntokens, c->ccsid);
        wb_u8(&w, 0);
        /* Informix puts its ISAM error in SQLERRD(2). */
        if (ca->errd[1])
            fail(c, "SQLCODE %d, ISAM %d, SQLSTATE %s%s%s", ca->sqlcode, ca->errd[1],
                 c->sqlstate, w.n > 1 ? ": " : "", w.err ? "" : (char *)w.p);
        else
            fail(c, "SQLCODE %d, SQLSTATE %s%s%s", ca->sqlcode, c->sqlstate,
                 w.n > 1 ? ": " : "", w.err ? "" : (char *)w.p);
        wb_free(&w);
    }
    return -1;
}

/* Common handling for objects that are not the data a caller waits for:
 * reply messages with an error severity and SQLCARDs. */
static int check_obj(drda_conn *c, int i)
{
    uint16_t cp = c->objs[i].cp;
    rd body = obj_rd(c, i), v;
    if (cp == SQLCARD) {
        sqlca ca;
        if (decode_sqlca(&body, c->le, &ca) < 0)
            return fail(c, "malformed SQLCARD");
        return apply_sqlca(c, &ca);
    }
    if (cp == SECCHKRM && find_param(body, SECCHKCD, &v)) {
        uint8_t code = rd_u8(&v);
        if (code == 0)
            return 0;
        if (code == 0x0F || code == 0x13 || code == 0x14)
            return fail(c, "invalid user or password (SECCHKCD 0x%02X)", code);
        return fail(c, "authentication failed (SECCHKCD 0x%02X)", code);
    }
    if (find_param(body, SVRCOD, &v)) {
        int sev = rd_be16(&v);
        if (sev >= 8) {
            const char *name = rm_name(cp);
            int k;
            /* An SQLCARD later in the chain says what went wrong in SQL
             * terms; prefer it to the bare reply message. */
            for (k = i + 1; k < c->nobj; k++) {
                sqlca ca;
                rd b = obj_rd(c, k);
                if (c->objs[k].cp == SQLCARD && decode_sqlca(&b, c->le, &ca) > 0 && ca.sqlcode < 0)
                    return apply_sqlca(c, &ca);
            }
            if (name)
                return fail(c, "server error: %s, severity %d", name, sev);
            return fail(c, "server error: reply 0x%04X, severity %d", cp, sev);
        }
    }
    return 0;
}

/* ---- requests ------------------------------------------------------ */

static void pkgnamcsn(wb *w, const drda_conn *c)
{
    uint8_t b[64];
    memset(b, 0x40, 54);
    to_ebcdic(b, c->rdbnam, strlen(c->rdbnam));
    to_ebcdic(b + 18, "NULLID", 6);
    to_ebcdic(b + 36, "SYSSH200", 8);
    to_ebcdic(b + 54, "SYSLVL01", 8);
    b[62] = 0;
    b[63] = 65; /* section number */
    ddm_bytes(w, PKGNAMCSN, b, 64);
}

drda_conn *drda_connect(const char *host, int port, const char *database,
                        const char *user, const char *password, char *err, int errlen)
{
    drda_conn *c = (drda_conn *)calloc(1, sizeof *c);
    wb w;
    int i, bad = 0, secmec_ok = 0;
    uint8_t typdef[9];
#ifdef _WIN32
    WSADATA wsa;
#endif
    if (!c) {
        if (err && errlen > 0)
            snprintf(err, (size_t)errlen, "out of memory");
        return NULL;
    }
    wb_init(&c->in);
    c->s = BAD_SOCK;
    c->ccsid = 819;
    memcpy(c->sqlstate, "00000", 6);
#ifdef _WIN32
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    if (strlen(database) > 18) {
        fail(c, "database names over 18 characters are not supported yet");
        goto out;
    }
    strcpy(c->rdbnam, database);
    c->s = dial(host, port);
    if (c->s == BAD_SOCK) {
        fail(c, "cannot connect to %s:%d", host, port);
        goto out;
    }

    /* 1. Exchange server attributes and ask for user/password security. */
    wb_init(&w);
    dss_begin(&w, DSS_RQS, 1, EXCSAT);
    ddm_ebcdic(&w, EXTNAM, "libdrda", 0);
    ddm_ebcdic(&w, SRVNAM, "libdrda", 0);
    ddm_ebcdic(&w, SRVRLSLV, "LDR00100", 0);
    {
        static const uint16_t lv[] = {AGENT, 7, SQLAM, 7, CMNTCPIP, 5, RDB, 7, SECMGR, 7};
        uint8_t b[sizeof lv / sizeof lv[0] * 2];
        size_t k;
        for (k = 0; k < sizeof lv / sizeof lv[0]; k++) {
            b[2 * k] = (uint8_t)(lv[k] >> 8);
            b[2 * k + 1] = (uint8_t)lv[k];
        }
        ddm_bytes(&w, MGRLVLLS, b, sizeof b);
    }
    ddm_ebcdic(&w, SRVCLSNM, "libdrda", 0);
    dss_end(&w);
    dss_begin(&w, DSS_RQS, 2, ACCSEC);
    ddm_u16(&w, SECMEC, SECMEC_USRIDPWD);
    ddm_ebcdic(&w, RDBNAM, c->rdbnam, 18);
    dss_end(&w);
    if (send_wb(c, &w) < 0 || read_chain(c) < 0)
        goto out;
    for (i = 0; i < c->nobj; i++) {
        rd body = obj_rd(c, i), v;
        if (c->objs[i].cp == ACCSECRD) {
            if (find_param(body, SECMEC, &v) && rd_be16(&v) == SECMEC_USRIDPWD)
                secmec_ok = 1;
        } else if (check_obj(c, i) < 0) {
            goto out;
        }
    }
    if (!secmec_ok) {
        fail(c, "the server does not accept user and password authentication (SECMEC 3)");
        goto out;
    }

    /* 2. Log in and open the database. */
    wb_init(&w);
    dss_begin(&w, DSS_RQS, 1, SECCHK);
    ddm_u16(&w, SECMEC, SECMEC_USRIDPWD);
    ddm_ebcdic(&w, RDBNAM, c->rdbnam, 18);
    bad |= ddm_ebcdic(&w, USRID, user, 0);
    bad |= ddm_ebcdic(&w, PASSWORD, password, 0);
    dss_end(&w);
    dss_begin(&w, DSS_RQS, 2, ACCRDB);
    ddm_ebcdic(&w, RDBNAM, c->rdbnam, 18);
    ddm_u16(&w, RDBACCCL, SQLAM);
    ddm_ebcdic(&w, PRDID, "LDR00100", 0);
    ddm_ebcdic(&w, TYPDEFNAM, "QTDSQLX86", 0);
    {
        /* Our data is UTF-8 (1208) and UTF-16 (1200). */
        static const uint8_t ovr[] = {0x00, 0x06, 0x11, 0x9C, 0x04, 0xB8, 0x00, 0x06, 0x11, 0x9D,
                                      0x04, 0xB0, 0x00, 0x06, 0x11, 0x9E, 0x04, 0xB8};
        ddm_bytes(&w, TYPDEFOVR, ovr, sizeof ovr);
    }
    dss_end(&w);
    if (bad) {
        wb_free(&w);
        fail(c, "user and password must be printable ASCII");
        goto out;
    }
    if (send_wb(c, &w) < 0 || read_chain(c) < 0)
        goto out;
    to_ebcdic(typdef, "QTDSQLX86", 9);
    for (i = 0; i < c->nobj; i++) {
        rd body = obj_rd(c, i), v;
        if (check_obj(c, i) < 0)
            goto out;
        if (c->objs[i].cp != ACCRDBRM)
            continue;
        if (find_param(body, TYPDEFNAM, &v))
            c->le = v.n == 9 && memcmp(v.p, typdef, 9) == 0;
        if (find_param(body, TYPDEFOVR, &v)) {
            rd s;
            if (find_param(v, CCSIDMBC, &s) || find_param(v, CCSIDSBC, &s))
                c->ccsid = rd_be16(&s);
        }
        bad = 2; /* the database is open */
    }
    if (bad != 2) {
        fail(c, "the server did not open the database");
        goto out;
    }
    if (!ccsid_supported(c->ccsid)) {
        fail(c, "database code set CCSID %d is not supported yet", c->ccsid);
        goto out;
    }
    return c;

out:
    if (err && errlen > 0)
        snprintf(err, (size_t)errlen, "%s", c->err);
    drda_close(c);
    return NULL;
}

void drda_close(drda_conn *c)
{
    if (!c)
        return;
    if (c->open)
        drda_free(c->open);
    if (c->s != BAD_SOCK)
        sock_close(c->s);
#ifdef _WIN32
    WSACleanup();
#endif
    wb_free(&c->in);
    free(c->objs);
    free(c);
}

const char *drda_error(const drda_conn *c) { return c->err; }
int drda_sqlcode(const drda_conn *c) { return c->sqlcode; }
const char *drda_sqlstate(const drda_conn *c) { return c->sqlstate; }

/* Handle the objects of a query reply chain into r. */
static int absorb(drda_result *r)
{
    drda_conn *c = r->c;
    int i;
    for (i = 0; i < c->nobj; i++) {
        rd body = obj_rd(c, i), v;
        switch (c->objs[i].cp) {
        case OPNQRYRM:
            if (find_param(body, QRYINSID, &v))
                r->qryinsid = rd_u64(&v, 0);
            break;
        case QRYDSC:
            if (decode_qrydsc(&body, r->cols, r->ncols) < 0)
                return fail(c, "malformed or unexpected row descriptor (QRYDSC)");
            break;
        case QRYDTA:
            wb_put(&r->data, body.p, body.n);
            if (r->data.err)
                return fail(c, "out of memory");
            break;
        case ENDQRYRM:
            r->ended = 1;
            break;
        case EXTDTA:
            wb_be32(&r->ext, (uint32_t)body.n);
            wb_put(&r->ext, body.p, body.n);
            if (r->ext.err)
                return fail(c, "out of memory");
            break;
        case SQLCARD: {
            sqlca ca;
            if (decode_sqlca(&body, c->le, &ca) < 0)
                return fail(c, "malformed SQLCARD");
            if (ca.sqlcode == 100)
                r->ended = 1;
            else if (apply_sqlca(c, &ca) < 0)
                return -1;
            break;
        }
        default:
            if (check_obj(c, i) < 0)
                return -1;
        }
    }
    return 0;
}

/* Append the parameter values: SQLDTA, then one EXTDTA per large object,
 * all on correlator 1 after the command that uses them. */
static int put_params(drda_conn *c, wb *w, const dcol *pd, const drda_param *params, int n)
{
    const void **data;
    size_t *len;
    wb ext;
    int i, bad, rc;
    if (n == 0)
        return 0;
    data = (const void **)calloc((size_t)n, sizeof *data);
    len = (size_t *)calloc((size_t)n, sizeof *len);
    if (!data || !len) {
        free(data);
        free(len);
        return fail(c, "out of memory");
    }
    for (i = 0; i < n; i++) {
        data[i] = params[i].data;
        len[i] = params[i].len;
    }
    wb_init(&ext);
    dss_begin(w, DSS_OBJ, 1, SQLDTA);
    rc = encode_sqldta(w, pd, data, len, n, &ext, &bad);
    dss_end(w);
    free(data);
    free(len);
    if (rc < 0) {
        wb_free(&ext);
        if (bad >= 0)
            return fail(c, "parameter %d is too long or not valid UTF-8 for its column", bad + 1);
        return fail(c, "too many parameters or parameter values too large together");
    }
    {
        rd q = rd_make(ext.p, ext.n);
        while (q.n) {
            uint32_t k = rd_be32(&q);
            const uint8_t *b = rd_take(&q, k);
            dss_begin(w, DSS_OBJ, 1, EXTDTA);
            wb_put(w, b, k);
            dss_end(w);
        }
    }
    wb_free(&ext);
    return w->err ? fail(c, "out of memory") : 0;
}

int drda_query(drda_conn *c, const char *sql, drda_result **out)
{
    return drda_query_params(c, sql, NULL, 0, out);
}

int drda_query_params(drda_conn *c, const char *sql, const drda_param *params, int nparams,
                      drda_result **out)
{
    drda_result *r;
    size_t n = strlen(sql);
    dcol *pd = NULL;
    int npd = 0;
    wb w;
    int i;
    *out = NULL;
    c->err[0] = 0;
    c->sqlcode = 0;
    memcpy(c->sqlstate, "00000", 6);
    if (c->open)
        return fail(c, "another result is still open on this connection");
    if (!utf8_valid((const uint8_t *)sql, n))
        return fail(c, "the SQL text is not valid UTF-8");
    if (n > 32000) /* its object must fit one DSS segment */
        return fail(c, "SQL text over 32000 bytes is not supported over DRDA");
    if (nparams < 0 || (nparams > 0 && !params))
        return fail(c, "invalid parameter list");
    r = (drda_result *)calloc(1, sizeof *r);
    if (!r)
        return fail(c, "out of memory");
    r->c = c;
    wb_init(&r->data);
    wb_init(&r->cells);
    wb_init(&r->ext);

    /* Prepare, asking for the column descriptions, and for the parameter
     * descriptions too when there are values to send. */
    wb_init(&w);
    dss_begin(&w, DSS_RQS, 1, PRPSQLSTT);
    pkgnamcsn(&w, c);
    ddm_u8(&w, RTNSQLDA, 0xF1);
    dss_end(&w);
    dss_begin(&w, DSS_OBJ, 1, SQLSTT);
    wb_u8(&w, 0x00);
    wb_be32(&w, (uint32_t)n);
    wb_put(&w, sql, n);
    wb_u8(&w, 0xFF);
    dss_end(&w);
    if (nparams > 0) {
        dss_begin(&w, DSS_RQS, 2, DSCSQLSTT);
        pkgnamcsn(&w, c);
        ddm_u8(&w, TYPSQLDA, 1); /* input */
        dss_end(&w);
    }
    if (send_wb(c, &w) < 0 || read_chain(c) < 0)
        goto fail;
    for (i = 0; i < c->nobj; i++) {
        rd body = obj_rd(c, i);
        if (c->objs[i].cp == SQLDARD) {
            sqlca ca;
            int input = c->objs[i].corr == 2;
            if (decode_sqldard(&body, c->le, c->ccsid, &ca, input ? &pd : &r->cols,
                               input ? &npd : &r->ncols) < 0) {
                fail(c, "malformed %s description (SQLDARD)", input ? "parameter" : "column");
                goto fail;
            }
            if (apply_sqlca(c, &ca) < 0)
                goto fail;
        } else if (check_obj(c, i) < 0) {
            goto fail;
        }
    }
    if (npd != nparams) {
        fail(c, "the statement has %d parameter marker(s) but %d value(s) were given", npd,
             nparams);
        goto fail;
    }

    wb_init(&w);
    if (r->ncols == 0) {
        /* Not a query: run it. */
        dss_begin(&w, DSS_RQS, 1, EXCSQLSTT);
        pkgnamcsn(&w, c);
        ddm_u8(&w, RDBCMTOK, 0xF1);
        dss_end(&w);
        if (put_params(c, &w, pd, params, nparams) < 0) {
            wb_free(&w);
            goto fail;
        }
        if (send_wb(c, &w) < 0 || read_chain(c) < 0)
            goto fail;
        for (i = 0; i < c->nobj; i++) {
            rd body = obj_rd(c, i);
            if (c->objs[i].cp == SQLCARD) {
                sqlca ca;
                if (decode_sqlca(&body, c->le, &ca) < 0) {
                    fail(c, "malformed SQLCARD");
                    goto fail;
                }
                if (apply_sqlca(c, &ca) < 0)
                    goto fail;
                r->affected = ca.errd[2];
            } else if (check_obj(c, i) < 0) {
                goto fail;
            }
        }
        r->ended = 1;
        free_cols(pd, npd);
        *out = r;
        return 0;
    }

    /* A query: open a cursor. */
    dss_begin(&w, DSS_RQS, 1, OPNQRY);
    pkgnamcsn(&w, c);
    ddm_u32(&w, QRYBLKSZ, BLOCK_SIZE);
    ddm_u16(&w, MAXBLKEXT, 0);
    ddm_u8(&w, QRYCLSIMP, 0x01);
    dss_end(&w);
    if (put_params(c, &w, pd, params, nparams) < 0) {
        wb_free(&w);
        goto fail;
    }
    if (send_wb(c, &w) < 0 || read_chain(c) < 0 || absorb(r) < 0)
        goto fail;
    for (i = 0; i < r->ncols; i++) {
        if (!fd_supported(r->cols[i].fdtype)) {
            fail(c, "column \"%s\" has a data type not supported yet (FD:OCA 0x%02X, SQLTYPE %d)",
                 r->cols[i].name, r->cols[i].fdtype, r->cols[i].sqltype);
            goto fail;
        }
    }
    r->off = (size_t *)calloc((size_t)r->ncols, sizeof *r->off);
    r->lobn = (uint64_t *)calloc((size_t)r->ncols, sizeof *r->lobn);
    if (!r->off || !r->lobn) {
        fail(c, "out of memory");
        goto fail;
    }
    free_cols(pd, npd);
    c->open = r;
    *out = r;
    return 0;

fail:
    free_cols(pd, npd);
    c->open = r; /* let drda_free close the cursor if it got opened */
    drda_free(r);
    return -1;
}

int drda_col_count(const drda_result *r) { return r->ncols; }

const char *drda_col_name(const drda_result *r, int col)
{
    return col >= 0 && col < r->ncols ? r->cols[col].name : NULL;
}

int drda_col_sqltype(const drda_result *r, int col)
{
    return col >= 0 && col < r->ncols ? r->cols[col].sqltype : 0;
}

long long drda_rows_affected(const drda_result *r) { return r->affected; }

static int cntqry(drda_result *r)
{
    drda_conn *c = r->c;
    wb w;
    wb_init(&w);
    dss_begin(&w, DSS_RQS, 1, CNTQRY);
    pkgnamcsn(&w, c);
    ddm_u32(&w, QRYBLKSZ, BLOCK_SIZE);
    ddm_u64(&w, QRYINSID, r->qryinsid);
    ddm_u8(&w, RTNEXTDTA, 0x02); /* large objects of every row in the block */
    dss_end(&w);
    if (send_wb(c, &w) < 0 || read_chain(c) < 0)
        return -1;
    return absorb(r);
}

/* Fill the large object cells of the row just decoded from the EXTDTA
 * queue, which the server sends in column order, one per non-null value. */
static int take_lobs(drda_result *r)
{
    int i;
    for (i = 0; i < r->ncols; i++) {
        rd q, ext;
        uint32_t n;
        if (r->off[i] != LOB_PENDING)
            continue;
        if (r->lobn[i] == 0) {
            /* An empty large object comes with no EXTDTA at all. */
            r->off[i] = r->cells.n;
            wb_u8(&r->cells, 0);
            continue;
        }
        q = rd_make(r->ext.p + r->ext_pos, r->ext.n - r->ext_pos);
        n = rd_be32(&q);
        ext = rd_sub(&q, n);
        if (ext.err)
            return fail(r->c, "large object data missing for column \"%s\"", r->cols[i].name);
        r->ext_pos += 4 + n;
        r->off[i] = r->cells.n;
        if (decode_lob(&ext, &r->cols[i], r->lobn[i], &r->cells) < 0)
            return fail(r->c, "large object data out of step for column \"%s\"",
                        r->cols[i].name);
        wb_u8(&r->cells, 0);
    }
    return r->cells.err ? fail(r->c, "out of memory") : 0;
}

int drda_next(drda_result *r)
{
    drda_conn *c = r->c;
    sqlca ca;
    r->have_row = 0;
    if (r->ncols == 0)
        return 0;
    for (;;) {
        rd in = rd_make(r->data.p + r->pos, r->data.n - r->pos);
        size_t before = in.n;
        int rc;
        r->cells.n = 0;
        rc = decode_row(&in, c->le, r->cols, r->ncols, &r->cells, r->off, r->lobn, &ca);
        r->pos += before - in.n;
        if (rc == 1) {
            if (take_lobs(r) < 0)
                return -1;
            r->have_row = 1;
            return 1;
        }
        if (rc == 2) {
            r->ended = 1;
            r->pos = r->data.n;
            return 0;
        }
        if (rc < 0)
            return ca.sqlcode < 0 ? apply_sqlca(c, &ca) : fail(c, "malformed row data");
        /* Incomplete: need another block. */
        if (r->ended) {
            if (r->pos < r->data.n)
                return fail(c, "truncated row data");
            return 0;
        }
        if (r->pos)
            memmove(r->data.p, r->data.p + r->pos, r->data.n - r->pos);
        r->data.n -= r->pos;
        r->pos = 0;
        if (r->ext_pos == r->ext.n)
            r->ext.n = r->ext_pos = 0;
        before = r->data.n;
        if (cntqry(r) < 0)
            return -1;
        if (r->data.n == before && !r->ended)
            return fail(c, "the server sent no rows and did not end the query");
    }
}

const char *drda_text(const drda_result *r, int col)
{
    if (!r->have_row || col < 0 || col >= r->ncols || r->off[col] == (size_t)-1)
        return NULL;
    return (const char *)r->cells.p + r->off[col];
}

void drda_free(drda_result *r)
{
    drda_conn *c;
    if (!r)
        return;
    c = r->c;
    if (c->open == r) {
        if (!r->ended && r->qryinsid) {
            wb w;
            wb_init(&w);
            dss_begin(&w, DSS_RQS, 1, CLSQRY);
            pkgnamcsn(&w, c);
            ddm_u64(&w, QRYINSID, r->qryinsid);
            dss_end(&w);
            if (send_wb(c, &w) == 0)
                read_chain(c); /* errors closing are not the caller's */
        }
        c->open = NULL;
    }
    free_cols(r->cols, r->ncols);
    wb_free(&r->data);
    wb_free(&r->cells);
    wb_free(&r->ext);
    free(r->lobn);
    free(r->off);
    free(r);
}

static int end_uow(drda_conn *c, uint16_t cp)
{
    wb w;
    int i;
    c->err[0] = 0;
    wb_init(&w);
    dss_begin(&w, DSS_RQS, 1, cp);
    dss_end(&w);
    if (send_wb(c, &w) < 0 || read_chain(c) < 0)
        return -1;
    for (i = 0; i < c->nobj; i++)
        if (check_obj(c, i) < 0)
            return -1;
    return 0;
}

int drda_commit(drda_conn *c) { return end_uow(c, RDBCMM); }
int drda_rollback(drda_conn *c) { return end_uow(c, RDBRLLBCK); }
