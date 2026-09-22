/* libdrda: a native DRDA client for IBM Informix.
 *
 * Every function that can fail returns a negative value and leaves a
 * UTF-8 message in drda_error(). Strings are UTF-8 in both directions. */
#ifndef DRDA_H
#define DRDA_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct drda_conn drda_conn;
typedef struct drda_result drda_result;

/* Open a connection to a DRDA listener (an sqlhosts entry of protocol
 * drsoctcp) and log in with user and password, sent in clear text: use it
 * on a trusted network until TLS lands. Returns NULL and fills err (if
 * given) on failure. */
drda_conn *drda_connect(const char *host, int port, const char *database,
                        const char *user, const char *password,
                        char *err, int errlen);
void drda_close(drda_conn *c);

const char *drda_error(const drda_conn *c);
/* SQLCODE and SQLSTATE of the last statement (0 and "00000" on success). */
int drda_sqlcode(const drda_conn *c);
const char *drda_sqlstate(const drda_conn *c);

/* Run any statement. A statement that returns rows yields a result with
 * columns to fetch; any other runs to completion and reports
 * drda_rows_affected(). Only one result may be open per connection. */
int drda_query(drda_conn *c, const char *sql, drda_result **out);

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
