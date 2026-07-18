# poc-logids — Log-Based Anomaly Detection Tool

A Go CLI that parses log data and flags suspicious patterns — a "mini IDS" for log analysis. First detection target: SSH brute-force attempts in auth.log-style logs (repeated failed-auth attempts from a single source within a time window).

Second in a series of portfolio projects supporting a pivot from software engineering to cybersecurity engineering. First: [poc-osint](https://github.com/tahovig/poc-osint), an automated subdomain recon tool.

## Status

Early-stage scaffold — core functionality not yet implemented.

## Planned functionality

- Parse auth.log-style SSH authentication events (syslog format).
- Detect brute-force patterns: repeated failed-auth attempts from one source within a configurable time window.
- Live-tail mode (`fsnotify`-based file watching) for near-real-time detection on a growing log file, including logrotate-safe handling.
- Structured output: JSON and a human-readable table.

## Repo structure

- `code/` — application source
- `resources/` — supporting/reference materials (non-code), including test fixtures and real-world log samples

## Tech stack

Go. See `CLAUDE.md` for full design notes and rationale.
