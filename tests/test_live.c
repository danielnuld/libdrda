/* Live tests against an Informix DRDA listener. Skipped (exit 77) unless
 * DRDA_TEST_HOST is set; also reads DRDA_TEST_PORT, DRDA_TEST_DB,
 * DRDA_TEST_USER and DRDA_TEST_PASSWORD. The database must be logged
 * and writable: the test creates and drops table drda_live. */
#include "drda.h"

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

    /* A result abandoned early closes its cursor; the next query works. */
    CHECK(drda_query(c, "select tabname from systables", &r) == 0);
    CHECK(drda_next(r) == 1);
    {
        drda_result *r2;
        CHECK(drda_query(c, "select 1 from systables", &r2) < 0); /* one open result */
        CHECK(r2 == NULL);
    }
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

    CHECK(drda_query(c, "select 1 from drda_live where name = '\xff'", &r) < 0);
    CHECK(strstr(drda_error(c), "UTF-8") != NULL);

    CHECK(run(c, "drop table drda_live") == 0);
    CHECK(drda_commit(c) == 0);
    drda_close(c);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("all live checks passed\n");
    return 0;
}
