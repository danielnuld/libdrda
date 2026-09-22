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
protocol `drsoctcp` (Informix 11.10 or later).

## Scope of the first milestone

1. Exchange server attributes (`EXCSAT`).
2. Authenticate with user and password (`ACCSEC` / `SECCHK`).
3. Open the database (`ACCRDB`).
4. Run a `SELECT` and fetch rows (`PRPSQLSTT` / `OPNQRY` / `CNTQRY`).
5. Run statements, then commit or roll back (`EXCSQLIMM`, `RDBCMM`, `RDBRLLBCK`).

## Design rules

- C11, no dependencies except optional OpenSSL for TLS.
- Every byte from the network is read through one bounded reader; no parser
  indexes a buffer directly.
- The message decoder is fuzzed.
- Unsupported features return an explicit error, never a fake success.

## License

Apache-2.0
