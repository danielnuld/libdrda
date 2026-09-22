/* drdacli host port database user "sql" [...]
 * The password comes from DRDA_PASSWORD. Each SQL argument runs in turn and
 * its rows print tab-separated; the work is committed at the end. */
#include "drda.h"

#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>

/* argv arrives in the ANSI code page; the library wants UTF-8. */
static char **utf8_argv(int *argc)
{
    wchar_t **w = CommandLineToArgvW(GetCommandLineW(), argc);
    char **a = (char **)calloc((size_t)*argc + 1, sizeof *a);
    int i;
    for (i = 0; w && a && i < *argc; i++) {
        int n = WideCharToMultiByte(CP_UTF8, 0, w[i], -1, NULL, 0, NULL, NULL);
        a[i] = (char *)malloc((size_t)n);
        if (a[i])
            WideCharToMultiByte(CP_UTF8, 0, w[i], -1, a[i], n, NULL, NULL);
    }
    SetConsoleOutputCP(CP_UTF8);
    return a;
}
#endif

int main(int argc, char **argv)
{
    char err[512];
    const char *pw = getenv("DRDA_PASSWORD");
    drda_conn *c;
    int i, rc = 0;
#ifdef _WIN32
    argv = utf8_argv(&argc);
#endif
    if (argc < 6 || !pw) {
        fprintf(stderr, "usage: DRDA_PASSWORD=... drdacli host port database user \"sql\" [...]\n");
        return 2;
    }
    c = drda_connect(argv[1], atoi(argv[2]), argv[3], argv[4], pw, err, sizeof err);
    if (!c) {
        fprintf(stderr, "connect: %s\n", err);
        return 1;
    }
    for (i = 5; i < argc && rc == 0; i++) {
        drda_result *r;
        int k, n, rows = 0;
        if (drda_query(c, argv[i], &r) < 0) {
            fprintf(stderr, "error: %s\n", drda_error(c));
            rc = 1;
            break;
        }
        n = drda_col_count(r);
        if (n == 0) {
            printf("%lld row(s) affected\n", drda_rows_affected(r));
        } else {
            for (k = 0; k < n; k++)
                printf("%s%s", k ? "\t" : "", drda_col_name(r, k));
            printf("\n");
            while ((rc = drda_next(r)) == 1) {
                for (k = 0; k < n; k++) {
                    const char *t = drda_text(r, k);
                    printf("%s%s", k ? "\t" : "", t ? t : "NULL");
                }
                printf("\n");
                rows++;
            }
            if (rc < 0) {
                fprintf(stderr, "error: %s\n", drda_error(c));
                rc = 1;
            } else {
                printf("(%d row(s))\n", rows);
            }
        }
        drda_free(r);
    }
    if (rc == 0 && drda_commit(c) < 0) {
        fprintf(stderr, "commit: %s\n", drda_error(c));
        rc = 1;
    }
    drda_close(c);
    return rc;
}
