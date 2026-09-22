# libdrda

A native DRDA client written in C for IBM Informix. It talks to the server
over the network directly, so it needs neither the Informix Client SDK (CSDK)
nor any other IBM client.

It implements the open DRDA specification published by The Open Group, not
the proprietary SQLI protocol.

## Why

The CSDK is closed, 32-bit only on some platforms and unavailable on iOS,
macOS and many Linux targets. A small, dependency-free client makes Informix
reachable from anywhere a C compiler runs. The first consumer is
[Squaero](https://github.com/danielnuld/squaero).

## Server requirement

The Informix server must expose a DRDA listener: an `sqlhosts` entry with
protocol `drsoctcp` (Informix 11.10 or later). Check with `onstat -g ntt`.

## Status

Proof of concept, verified against Informix 15.0.1 (the
`icr.io/informix/informix-developer-database` container) and read-only
against an Informix 11.70.FC7 server:

- Connect, log in with user and password, open a database.
- Run any statement. Queries stream through a cursor, block by block, so a
  large result is never held in memory at once. Other statements report the
  rows they affected.
- Commit and rollback.
- Types: SMALLINT, INTEGER, BIGINT, INT8, SERIAL, FLOAT, SMALLFLOAT, DECIMAL,
  MONEY, CHAR, VARCHAR, LVARCHAR, NCHAR, NVARCHAR, DATE, DATETIME, TEXT,
  BYTE and NULL. Values come back as UTF-8 text; BYTE as hexadecimal.
- Errors carry the Informix SQLCODE, SQLSTATE and message tokens (the
  server sends no message text over DRDA).

## Known limits

Each one fails with an explicit error, never silently:

- The password travels in clear text (SECMEC 3) and there is no TLS yet. Use
  it only on a trusted network.
- Database code sets: CCSID 819 (Latin-1) and 1208 (UTF-8) only.
- No `?` parameters, so TEXT and BYTE can be read but not written (Informix
  takes them only through host variables).
- Smart large objects (BLOB, CLOB) are untested.
- Database names up to 18 characters, SQL text up to 32 KB.
- Not tested yet against Informix 12.10, nor writes against 11.70.

Quirks of Informix over DRDA, shown as they arrive:

- BOOLEAN arrives as SMALLINT (1/0).
- DATETIME HOUR TO MINUTE shows seconds, and fractions show six digits.

## Build

```sh
cmake -S . -B build -G Ninja -DDRDA_WERROR=ON
cmake --build build
ctest --test-dir build
```

The live test runs when `DRDA_TEST_HOST` is set (also `DRDA_TEST_PORT`,
`DRDA_TEST_DB`, `DRDA_TEST_USER`, `DRDA_TEST_PASSWORD`). It needs a logged
database it can write to:

```sh
docker run -d --name libdrda-ifx -h ifx -e LICENSE=accept \
  -p 19088:9088 -p 19089:9089 icr.io/informix/informix-developer-database
DRDA_PASSWORD=in4mix ./build/drdacli 127.0.0.1 19089 sysmaster informix \
  "create database drdatest with log"
sh tests/load_lob_fixture.sh   # TEXT/BYTE rows; skipped when absent
DRDA_TEST_HOST=127.0.0.1 DRDA_TEST_PORT=19089 ctest --test-dir build
```

`drdacli` runs statements from the command line and prints rows
tab-separated; it reads the password from `DRDA_PASSWORD`.

## Design rules

- C11, no dependencies.
- Every byte from the network is read through one bounded reader
  (`src/wire.c`); no parser indexes a buffer directly.
- The decoder is tested on bytes captured from a real server, and on
  mutated and truncated copies of them under AddressSanitizer.
- Unsupported features return an explicit error, never a fake success.

## Acknowledgements

[pydrda](https://github.com/nakagami/pydrda) (MIT) served as a reference
for message layouts while reading the specification. No code was copied.

## License

Apache-2.0
