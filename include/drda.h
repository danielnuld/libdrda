/* libdrda: a native DRDA client for IBM Informix.
 *
 * Every function that can fail returns a negative value and leaves a
 * UTF-8 message in drda_error(). Strings are UTF-8 in both directions. */
#ifndef DRDA_H
#define DRDA_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct drda_conn drda_conn;
typedef struct drda_result drda_result;

/* Open a connection to a DRDA listener (an sqlhosts entry of protocol
 * drsoctcp) and log in with user and password. Without TLS the password
 * travels in clear text: use drda_connect_opts on an untrusted network.
 * Returns NULL and fills err (if given) on failure. */
drda_conn *drda_connect(const char *host, int port, const char *database,
                        const char *user, const char *password,
                        char *err, int errlen);

typedef enum {
    DRDA_TLS_OFF = 0,     /* plain TCP */
    DRDA_TLS_REQUIRE,     /* encrypted, the server's certificate not checked */
    DRDA_TLS_VERIFY_CA,   /* encrypted, certificate signed by a trusted CA */
    DRDA_TLS_VERIFY_FULL, /* and issued for the host name or IP connected to */
} drda_tls_mode;

typedef struct {
    drda_tls_mode tls;
    const char *ca_file; /* PEM of the CAs to trust; NULL = OpenSSL's default
                          * paths (Windows has none: pass a file there) */
    int connect_timeout_ms; /* for each wait while logging in; 0 = 30000.
                             * Queries run without a timeout. */
} drda_options; /* zero it before filling it in */

/* drda_connect with options. For TLS the listener must be of protocol
 * drsocssl. A library built without OpenSSL refuses any TLS mode. */
drda_conn *drda_connect_opts(const char *host, int port, const char *database,
                             const char *user, const char *password,
                             const drda_options *opts, char *err, int errlen);
void drda_close(drda_conn *c);

const char *drda_error(const drda_conn *c);

/* 1 once the connection is unusable: the network failed, the server sent
 * something unreadable, or drda_cancel cut it. Every later call fails fast;
 * the only way on is drda_close and a new connection. An SQL error is not a
 * lost connection. */
int drda_conn_lost(const drda_conn *c);

/* Stop the statement running on c, from any thread. DRDA has no reliable
 * way to interrupt a query on the same connection, so this shuts the socket
 * down: the running call returns an error, the connection is lost and any
 * open transaction is rolled back by the server. The caller must keep c
 * alive (not drda_close it) until drda_cancel returns. */
void drda_cancel(drda_conn *c);
/* SQLCODE and SQLSTATE of the last statement (0 and "00000" on success). */
int drda_sqlcode(const drda_conn *c);
const char *drda_sqlstate(const drda_conn *c);

/* Run any statement. A statement that returns rows yields a result with
 * columns to fetch; any other runs to completion and reports
 * drda_rows_affected(). Up to 64 results may be open on a connection at
 * once, each fetched independently; free them all before drda_close. */
int drda_query(drda_conn *c, const char *sql, drda_result **out);

/* A value for a `?` marker. data NULL = SQL NULL. Text is UTF-8 and the
 * server converts it to the column type (numbers, dates in the server's
 * format); for BYTE and BLOB, data holds the raw bytes. */
typedef struct {
    const void *data;
    size_t len;
} drda_param;

/* drda_query with values for the statement's `?` markers, in order. The
 * count must match the markers. Large objects (TEXT, BYTE) of any size
 * are sent as such; other values are limited to 32767 bytes. */
int drda_query_params(drda_conn *c, const char *sql, const drda_param *params, int nparams,
                      drda_result **out);

int drda_col_count(const drda_result *r);
const char *drda_col_name(const drda_result *r, int col);
int drda_col_sqltype(const drda_result *r, int col); /* DB2 SQLTYPE */

/* 1 = a row is ready, 0 = no more rows, <0 = error. */
int drda_next(drda_result *r);
/* Text of a cell in the current row, NULL for SQL NULL. Valid until the
 * next drda_next() or drda_free(). */
const char *drda_text(const drda_result *r, int col);
long long drda_rows_affected(const drda_result *r);
void drda_free(drda_result *r);

int drda_commit(drda_conn *c);
int drda_rollback(drda_conn *c);

#ifdef __cplusplus
}
#endif

#endif
