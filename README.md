# poc-logids — Log-Based Anomaly Detection Tool

[![CI](https://github.com/tahovig/poc-logids/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tahovig/poc-logids/actions/workflows/ci.yml)

A Go CLI that parses log data and flags suspicious patterns — a "mini IDS" for log analysis. First detection target: SSH brute-force attempts in auth.log-style logs (repeated failed-auth attempts from a single source within a time window).

Second in a series of portfolio projects supporting a pivot from software engineering to cybersecurity engineering. First: [poc-osint](https://github.com/tahovig/poc-osint), an automated subdomain recon tool.

## Status

Core detection works: parse an auth.log-style file, flag SSH brute-force bursts, output as a table or JSON. Live-tail mode not yet built.

```
$ poc-logids -file resources/loghub-linux/Linux_2k.log
SOURCE                                    ATTEMPTS  FIRST SEEN       LAST SEEN        USERS TRIED
220-135-151-1.hinet-ip.hinet.net          10        Jun 15 02:04:59  Jun 15 02:04:59  root
218.188.2.4                               12        Jun 15 12:12:34  Jun 15 12:13:20
...
```

Run against [loghub](https://github.com/logpai/loghub)'s real Linux syslog sample (`resources/loghub-linux/`) — genuine production data, not synthetic.

## Usage

```
go build -o poc-logids ./cmd/poc-logids
./poc-logids -file <path> [-json] [-threshold N] [-window 60s]
```

- `-threshold` (default 5) — minimum failed attempts from one source to flag as brute-force.
- `-window` (default 60s) — max gap allowed between consecutive attempts for them to count as the same burst.
- `-json` — JSON output instead of the table.

## Planned functionality

- Live-tail mode (`fsnotify`-based file watching) for near-real-time detection on a growing log file, including logrotate-safe handling.

## Repo structure

- `cmd/poc-logids/` — CLI entry point
- `internal/parser/` — extracts failed SSH auth events from log lines (syslog `pam_unix` and modern OpenSSH formats)
- `internal/detector/` — flags brute-force bursts per source
- `internal/output/` — JSON / ASCII table rendering
- `resources/` — supporting/reference materials (non-code), including real-world log samples

## Tech stack

Go. See `CLAUDE.md` for full design notes and rationale.
