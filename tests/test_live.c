/* Live tests against an Informix DRDA listener. Skipped (exit 77) unless
 * DRDA_TEST_HOST is set; also reads DRDA_TEST_PORT, DRDA_TEST_DB,
 * DRDA_TEST_USER and DRDA_TEST_PASSWORD. The database must be logged
 * and writable: the test creates and drops table drda_live. */
/* nanosleep and pthreads are hidden by a strict -std=c11; ask for them. */
#if !defined(_WIN32)
#  ifndef _POSIX_C_SOURCE
#    define _POSIX_C_SOURCE 200809L
#  endif
#  if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#    define _DARWIN_C_SOURCE
#  endif
#endif

#include "drda.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
static void sleep_ms(int ms) { Sleep((DWORD)ms); }
#else
#include <pthread.h>
static void sleep_ms(int ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}
#endif

static int failures;

/* Cancel c after a second, from another thread. */
#ifdef _WIN32
static DWORD WINAPI canceller(LPVOID arg)
#else
static void *canceller(void *arg)
#endif
{
    sleep_ms(1000);
    drda_cancel((drda_conn *)arg);
    return 0;
}

static void start_canceller(drda_conn *c)
{
#ifdef _WIN32
    HANDLE h = CreateThread(NULL, 0, canceller, c, 0, NULL);
    if (h)
        CloseHandle(h);
#else
    pthread_t t;
    if (pthread_create(&t, NULL, canceller, c) == 0)
        pthread_detach(t);
#endif
}

#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            fprintf(stderr, "%s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond); \
            failures++;                                                 \
        }                                                               \
    } while (0)

static const char *env(const char *k, const char *def)
{
    const char *v = getenv(k);
    return v && *v ? v : def;
}

static int run(drda_conn *c, const char *sql)
{
    drda_result *r;
    if (drda_query(c, sql, &r) < 0) {
        fprintf(stderr, "  %s\n  -> %s\n", sql, drda_error(c));
        return -1;
    }
    drda_free(r);
    return 0;
}

/* First column of the first row, copied; "" when there is no row. */
static char *scalar(drda_conn *c, const char *sql)
{
    static char buf[256];
    drda_result *r;
    buf[0] = 0;
    if (drda_query(c, sql, &r) < 0) {
        fprintf(stderr, "  %s\n  -> %s\n", sql, drda_error(c));
        return buf;
    }
    if (drda_next(r) == 1) {
        const char *t = drda_text(r, 0);
        snprintf(buf, sizeof buf, "%s", t ? t : "<null>");
    }
    drda_free(r);
    return buf;
}

int main(void)
{
    const char *host = getenv("DRDA_TEST_HOST");
    int port = atoi(env("DRDA_TEST_PORT", "9089"));
    const char *db = env("DRDA_TEST_DB", "drdatest");
    const char *user = env("DRDA_TEST_USER", "informix");
    const char *pw = env("DRDA_TEST_PASSWORD", "in4mix");
    char err[512];
    drda_conn *c;
    drda_result *r;
    int n;

    if (!host) {
        printf("DRDA_TEST_HOST not set, skipping\n");
        return 77;
    }

    /* Wrong password and wrong database fail with a message. */
    CHECK(drda_connect(host, port, db, user, "wrong-password", err, sizeof err) == NULL);
    CHECK(strstr(err, "password") != NULL);
    CHECK(drda_connect(host, port, "no_such_db", user, pw, err, sizeof err) == NULL);
    CHECK(strstr(err, "not found") != NULL);

    c = drda_connect(host, port, db, user, pw, err, sizeof err);
    if (!c) {
        fprintf(stderr, "connect: %s\n", err);
        return 1;
    }
    run(c, "drop table drda_live"); /* left over by an aborted run */
    drda_commit(c);
    CHECK(run(c, "create table drda_live (id int, name varchar(40), amount decimal(10,2))") == 0);
    CHECK(drda_commit(c) == 0);

    /* Rows affected, non-ASCII text round trip, NULL. */
    CHECK(drda_query(c, "insert into drda_live values (1, 'Año ñandú', 10.50)", &r) == 0);
    CHECK(drda_rows_affected(r) == 1);
    drda_free(r);
    CHECK(run(c, "insert into drda_live values (2, null, null)") == 0);
    CHECK(strcmp(scalar(c, "select name from drda_live where id = 1"), "Año ñandú") == 0);
    CHECK(strcmp(scalar(c, "select amount from drda_live where id = 1"), "10.50") == 0);
    CHECK(strcmp(scalar(c, "select name from drda_live where id = 2"), "<null>") == 0);
    CHECK(drda_query(c, "update drda_live set amount = 1 where id > 0", &r) == 0);
    CHECK(drda_rows_affected(r) == 2);
    drda_free(r);

    /* Rollback undoes, commit keeps. */
    CHECK(drda_rollback(c) == 0);
    CHECK(strcmp(scalar(c, "select count(*) from drda_live"), "0") == 0);
    CHECK(run(c, "insert into drda_live values (3, 'kept', 3)") == 0);
    CHECK(drda_commit(c) == 0);
    CHECK(strcmp(scalar(c, "select count(*) from drda_live"), "1") == 0);

    /* SQL errors carry SQLCODE and leave the connection usable. */
    CHECK(drda_query(c, "selec 1", &r) < 0 && drda_sqlcode(c) == -201);
    CHECK(drda_query(c, "select * from drda_missing", &r) < 0 && drda_sqlcode(c) == -206);
    CHECK(strcmp(scalar(c, "select id from drda_live"), "3") == 0);
    CHECK(drda_sqlcode(c) == 0);

    /* A result spanning many query blocks, read to the end. */
    CHECK(drda_query(c, "select tabname, colname, colno from syscolumns c, systables t "
                        "where c.tabid = t.tabid", &r) == 0);
    n = 0;
    while (drda_next(r) == 1)
        n++;
    CHECK(n > 500);
    CHECK(strcmp(drda_col_name(r, 1), "colname") == 0);
    drda_free(r);
    CHECK(atoi(scalar(c, "select count(*) from syscolumns c, systables t "
                         "where c.tabid = t.tabid")) == n);

    /* Several results open at once: a cursor paged across blocks while other
     * statements run in between, as Squaero pages a grid. */
    {
        drda_result *r2;
        int m = 0, rc2;
        CHECK(drda_query(c, "select tabname, colname, colno from syscolumns c, systables t "
                            "where c.tabid = t.tabid", &r) == 0);
        while (m < 700 && drda_next(r) == 1)
            m++; /* partway, past the first block */
        CHECK(drda_query(c, "select tabname from systables order by tabid", &r2) == 0);
        CHECK(drda_next(r2) == 1 && strcmp(drda_text(r2, 0), "systables") == 0);
        CHECK(run(c, "update drda_live set name = 'x' where id = 3") == 0);
        while ((rc2 = drda_next(r2)) == 1)
            ;
        CHECK(rc2 == 0);
        drda_free(r2);
        while (drda_next(r) == 1)
            m++;
        CHECK(m == n); /* nothing lost or repeated around the interleaving */
        drda_free(r);

        /* A commit while a cursor is open keeps it open (cursors are held:
         * package SYSSH200), so a caller can commit each statement. */
        m = 0;
        CHECK(drda_query(c, "select tabname, colname, colno from syscolumns c, systables t "
                            "where c.tabid = t.tabid", &r) == 0);
        while (m < 700 && drda_next(r) == 1)
            m++;
        CHECK(run(c, "update drda_live set name = 'y' where id = 3") == 0);
        CHECK(drda_commit(c) == 0);
        while (drda_next(r) == 1)
            m++;
        CHECK(m == n);
        drda_free(r);
    }

    /* A result abandoned early closes its cursor; the next query works. */
    CHECK(drda_query(c, "select tabname from systables", &r) == 0);
    CHECK(drda_next(r) == 1);
    drda_free(r);
    CHECK(strcmp(scalar(c, "select id from drda_live"), "3") == 0);

    /* TEXT and BYTE, from the fixture of tests/load_lob_fixture.sh. */
    if (drda_query(c, "select id, tx, by, n from drda_lob order by id", &r) < 0) {
        printf("no drda_lob table (tests/load_lob_fixture.sh), skipping TEXT/BYTE\n");
    } else {
        size_t k;
        int ok = 1;
        CHECK(drda_next(r) == 1);
        CHECK(drda_text(r, 1) == NULL && drda_text(r, 2) == NULL);
        CHECK(strcmp(drda_text(r, 3), "1") == 0);
        CHECK(drda_next(r) == 1);
        CHECK(strcmp(drda_text(r, 1), "Año ñandú") == 0);
        CHECK(strcmp(drda_text(r, 2), "0001feff") == 0);
        CHECK(drda_next(r) == 1);
        /* 40000 characters and 20000 bytes: several DSS segments each. */
        CHECK(strlen(drda_text(r, 1)) == 40000 && strlen(drda_text(r, 2)) == 40000);
        for (k = 0; ok && k < 40000; k++)
            ok = drda_text(r, 1)[k] == "abcdefghij"[k % 10];
        for (k = 0; ok && k < 20000; k++) {
            char hx[3];
            snprintf(hx, sizeof hx, "%02x", (unsigned)(k % 256));
            ok = memcmp(drda_text(r, 2) + 2 * k, hx, 2) == 0;
        }
        CHECK(ok);
        CHECK(strcmp(drda_text(r, 3), "3") == 0);
        CHECK(drda_next(r) == 0);
        drda_free(r);
        /* Abandoned after the first row: the cursor closes cleanly. */
        CHECK(drda_query(c, "select tx from drda_lob order by id desc", &r) == 0);
        CHECK(drda_next(r) == 1 && strlen(drda_text(r, 0)) == 40000);
        drda_free(r);
        CHECK(strcmp(scalar(c, "select count(*) from drda_lob"), "3") == 0);
    }

    /* Parameters: text converted by the server, NULL, a count mismatch. */
    {
        drda_param p[3];
        p[0].data = "5";
        p[0].len = 1;
        p[1].data = "Año ñandú";
        p[1].len = strlen("Año ñandú");
        p[2].data = NULL;
        p[2].len = 0;
        CHECK(drda_query_params(c, "insert into drda_live values (?, ?, ?)", p, 3, &r) == 0);
        CHECK(drda_rows_affected(r) == 1);
        drda_free(r);
        CHECK(drda_query_params(c, "select name, amount from drda_live where id = ?", p, 1,
                                &r) == 0);
        CHECK(drda_next(r) == 1 && strcmp(drda_text(r, 0), "Año ñandú") == 0);
        CHECK(drda_text(r, 1) == NULL);
        CHECK(drda_next(r) == 0);
        drda_free(r);
        CHECK(drda_query_params(c, "select 1 from drda_live where id = ?", p, 2, &r) < 0);
        CHECK(strstr(drda_error(c), "1 parameter marker") != NULL);
        p[0].data = "not a number";
        p[0].len = strlen("not a number");
        CHECK(drda_query_params(c, "select 1 from drda_live where id = ?", p, 1, &r) < 0);
        CHECK(drda_sqlcode(c) < 0); /* the server's conversion error */
        CHECK(run(c, "delete from drda_live where id = 5") == 0);
    }

    /* An SQL text over 32 KB is refused before it reaches the server. */
    {
        char *sql = (char *)malloc(40001);
        memset(sql, ' ', 40000);
        memcpy(sql, "select 1 from systables", 23);
        sql[40000] = 0;
        CHECK(drda_query(c, sql, &r) < 0 && strstr(drda_error(c), "32000") != NULL);
        free(sql);
        CHECK(strcmp(scalar(c, "select id from drda_live"), "3") == 0);
    }

    /* TEXT and BYTE written through parameters, small and over 32 KB. */
    CHECK(run(c, "create temp table drda_lobw (id int, tx text, by byte) with no log") == 0);
    {
        size_t sizes[] = {0, 5, 100000}, k;
        int s;
        for (s = 0; s < 3; s++) {
            size_t len = sizes[s];
            char *tx = (char *)malloc(len + 1);
            unsigned char *by = (unsigned char *)malloc(len + 1);
            char id[8];
            drda_param p[3];
            for (k = 0; k < len; k++) {
                tx[k] = "abcdefghij"[k % 10];
                by[k] = (unsigned char)(k * 7 % 256);
            }
            snprintf(id, sizeof id, "%d", s);
            p[0].data = id;
            p[0].len = strlen(id);
            p[1].data = tx;
            p[1].len = len;
            p[2].data = by;
            p[2].len = len;
            CHECK(drda_query_params(c, "insert into drda_lobw values (?, ?, ?)", p, 3, &r) == 0);
            drda_free(r);
            CHECK(drda_query_params(c, "select tx, by from drda_lobw where id = ?", p, 1, &r) == 0);
            CHECK(drda_next(r) == 1);
            if (drda_text(r, 0) && drda_text(r, 1)) {
                int ok = strlen(drda_text(r, 0)) == len && strlen(drda_text(r, 1)) == 2 * len &&
                         memcmp(drda_text(r, 0), tx, len) == 0;
                for (k = 0; ok && k < len; k++) {
                    char hx[3];
                    snprintf(hx, sizeof hx, "%02x", by[k]);
                    ok = memcmp(drda_text(r, 1) + 2 * k, hx, 2) == 0;
                }
                CHECK(ok);
            } else {
                CHECK(len == 0); /* Informix may store an empty large object as NULL */
            }
            drda_free(r);
            free(tx);
            free(by);
        }
    }
    CHECK(run(c, "drop table drda_lobw") == 0);

    CHECK(drda_query(c, "select 1 from drda_live where name = '\xff'", &r) < 0);
    CHECK(strstr(drda_error(c), "UTF-8") != NULL);

    CHECK(run(c, "drop table drda_live") == 0);
    CHECK(drda_commit(c) == 0);
    CHECK(!drda_conn_lost(c)); /* SQL errors along the way did not lose it */
    drda_close(c);

    /* drda_cancel from another thread stops a long query at once and loses
     * the connection; a new one works. */
    c = drda_connect(host, port, db, user, pw, err, sizeof err);
    CHECK(c != NULL);
    if (c) {
        time_t t0 = time(NULL);
        int rc;
        start_canceller(c);
        rc = drda_query(c, "select count(*) from syscolumns a, syscolumns b, systables t", &r);
        if (rc == 0) {
            rc = drda_next(r) == 1 ? 0 : -1;
            drda_free(r);
        }
        CHECK(rc < 0 && drda_conn_lost(c));
        CHECK(strstr(drda_error(c), "cancelled") != NULL);
        CHECK(time(NULL) - t0 < 10);
        CHECK(drda_query(c, "select 1 from systables", &r) < 0); /* fails fast now */
        sleep_ms(1500); /* the canceller thread is done with c */
        drda_close(c);
        c = drda_connect(host, port, db, user, pw, err, sizeof err);
        CHECK(c != NULL && strcmp(scalar(c, "select count(*) from systables where tabid = 1"),
                                  "1") == 0);
        drda_close(c);
    }

    /* TLS, against a drsocssl listener whose certificate names
     * DRDA_TEST_TLS_HOST (default localhost) and is signed by the PEM in
     * DRDA_TEST_CA_FILE. Only its sysmaster database is used. */
    if (getenv("DRDA_TEST_TLS_PORT") && getenv("DRDA_TEST_CA_FILE")) {
        int tport = atoi(getenv("DRDA_TEST_TLS_PORT"));
        const char *thost = env("DRDA_TEST_TLS_HOST", "localhost");
        drda_options o;
        drda_param p;
        memset(&o, 0, sizeof o);
        o.tls = DRDA_TLS_VERIFY_FULL;
        o.ca_file = getenv("DRDA_TEST_CA_FILE");
        c = drda_connect_opts(thost, tport, "sysmaster", user, pw, &o, err, sizeof err);
        CHECK(c != NULL);
        if (c) {
            /* Many blocks, so TLS records split rows and DSS headers. */
            CHECK(drda_query(c, "select tabname, colname from syscolumns c, systables t "
                                "where c.tabid = t.tabid", &r) == 0);
            n = 0;
            while (drda_next(r) == 1)
                n++;
            drda_free(r);
            CHECK(n > 500 && atoi(scalar(c, "select count(*) from syscolumns c, systables t "
                                            "where c.tabid = t.tabid")) == n);
            p.data = "systables";
            p.len = 9;
            CHECK(drda_query_params(c, "select tabid from systables where tabname = ?", &p, 1,
                                    &r) == 0);
            CHECK(drda_next(r) == 1 && strcmp(drda_text(r, 0), "1") == 0);
            drda_free(r);
            drda_close(c);
        } else {
            fprintf(stderr, "  TLS connect: %s\n", err);
        }

        /* The certificate is for the host name, not for the address. */
        CHECK(drda_connect_opts("127.0.0.1", tport, "sysmaster", user, pw, &o, err, sizeof err) ==
              NULL);
        CHECK(strstr(err, "mismatch") != NULL);
        o.tls = DRDA_TLS_VERIFY_CA;
        c = drda_connect_opts("127.0.0.1", tport, "sysmaster", user, pw, &o, err, sizeof err);
        CHECK(c != NULL);
        drda_close(c);

        /* Without the CA the self-signed certificate is not trusted, unless
         * only encryption was asked for. */
        o.ca_file = NULL;
        CHECK(drda_connect_opts(thost, tport, "sysmaster", user, pw, &o, err, sizeof err) == NULL);
        CHECK(strstr(err, "certificate") != NULL);
        o.tls = DRDA_TLS_REQUIRE;
        c = drda_connect_opts(thost, tport, "sysmaster", user, pw, &o, err, sizeof err);
        CHECK(c != NULL);
        drda_close(c);

        /* TLS against a plain listener ends at the timeout, with a hint. */
        o.connect_timeout_ms = 2000;
        CHECK(drda_connect_opts(host, port, db, user, pw, &o, err, sizeof err) == NULL);
        CHECK(strstr(err, "drsocssl") != NULL);
    } else {
        printf("DRDA_TEST_TLS_PORT/DRDA_TEST_CA_FILE not set, skipping TLS\n");
    }

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("all live checks passed\n");
    return 0;
}
