# poc-logids — Log-Based Anomaly Detection Tool

[![CI](https://github.com/tahovig/poc-logids/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tahovig/poc-logids/actions/workflows/ci.yml)

A Go CLI that parses log data and flags suspicious patterns — a "mini IDS" for log analysis. First detection target: SSH brute-force attempts in auth.log-style logs (repeated failed-auth attempts from a single source within a time window).

Second in a series of portfolio projects supporting a pivot from software engineering to cybersecurity engineering. First: [poc-osint](https://github.com/tahovig/poc-osint), an automated subdomain recon tool.

## Status

Full pipeline works: scan an auth.log-style file for SSH brute-force bursts, then optionally keep watching it live (`-follow`, `tail -f`-style) and alert on new activity as it happens — including through log rotation (rename+recreate or in-place truncation).

```
$ poc-logids -file resources/loghub-linux/Linux.log
SOURCE                                               ATTEMPTS  RATE       FIRST SEEN       LAST SEEN        USERS TRIED
150.183.249.110                                      80        50.5/min   Jul 10 16:01:43  Jul 10 16:03:18  root
220.82.197.48                                        80        53.3/min   Aug 29 07:22:24  Aug 29 07:23:54  root
85.17.1.3                                            64        45.2/min   Oct 15 15:49:47  Oct 15 15:51:12  root
...
(327 alerts total: 25 critical, 207 warning, 95 normal, spanning the full 263.9-day dataset)

$ poc-logids -file auth.log -follow
No brute-force activity detected.
Watching auth.log for new activity (threshold=5, window=1m0s)... press Ctrl+C to stop
[ALERT] Jul 17 22:41:05  source=203.0.113.7  attempts=5  rate=5.0/min  users=root
```

(both are real captured terminal output, not illustrative text — the first is trimmed with `...`/a summary line added, the rest is verbatim, worst-first as it actually sorts; the second is `poc-logids -follow` running against an empty file while five failed-login lines were appended live, one every ~0.3s. On a real terminal, rows are also colored by severity — red/yellow/plain — which a markdown code block can't show; see "How it works" below.)

Run against [loghub](https://github.com/logpai/loghub)'s full real Linux syslog dataset (`resources/loghub-linux/`) — genuine production data spanning 263.9 days, not synthetic. The dataset genuinely crosses a calendar year boundary, which is why the parser infers a consistent year across `Dec 31 -> Jan 1` (see `internal/parser`) rather than assuming everything happened in the same year.

## Usage

```
go build -o poc-logids ./cmd/poc-logids
./poc-logids -file <path> [-json] [-summary] [-threshold N] [-window 60s] [-follow] [-quiet-startup] [-cti]
```

- `-threshold` (default 5) — minimum failed attempts from one source to flag as brute-force.
- `-window` (default 60s) — max gap allowed between consecutive attempts for them to count as the same burst.
- `-json` — JSON output instead of the table/one-line format.
- `-summary` — plain-English outline grouped by severity instead of the table, with best-effort reverse-DNS naming (mutually exclusive with `-json`).
- `-follow` — after the initial scan, keep watching the file and print each new alert as soon as it's detected (Ctrl+C to stop). Unlike the batch scan, which reports a burst only once it's fully over, `-follow` alerts the instant a burst first crosses `-threshold`, since waiting for an in-progress attack to stop before reporting it defeats the point of live monitoring.
- `-quiet-startup` — with `-follow`, suppress the initial batch scan's printed alerts (the scan/offset/year-inference tracking still happens) so a restarted long-running service doesn't re-report the whole file's history every time it comes back up.
- `-cti` — enable passive threat-intel enrichment for repeat or unusually severe source IPs: RDAP (network/org ownership) and ip-api.com (GeoIP/ASN), both keyless public-registry lookups — never traffic to the source itself. Off by default since it makes outbound HTTP calls. Output goes to stderr as `[CTI] ...` (or a tagged `"type":"cti"` JSON line with `-json`), separate from the alert stream on stdout.
  - `-cti-threshold` (default 3) — failed-auth events from the same source within `-cti-window` that trigger enrichment (catches a source too patient to ever trip `-threshold`/`-window`'s own burst detection).
  - `-cti-window` (default 1h) — time window `-cti-threshold` repeats are counted within.
  - `-cti-cooldown` (default 24h) — minimum time between repeat enrichments of the same source.

On a real terminal, the table and `-follow`'s one-line alerts are sorted/colored by severity — critical (red, ≥4x `-threshold`) and warning (yellow, ≥2x `-threshold`) rows stand out from routine ones, and the table sorts worst-first rather than chronologically, so the alerts most worth reviewing don't get buried in an equally-weighted list. Color is skipped automatically for piped/redirected output (`-json`, `| less`, a log file) — never invisible ANSI bytes cluttering non-terminal output. A RATE column (attempts/minute) is included alongside the raw count, since a fast burst is a stronger signal than a slow one at the same attempt count.

## How it works

A few decisions worth calling out, since they came from real bugs/data rather than being obvious upfront:

- **Year inference for syslog timestamps.** Classic syslog format (`Jun 14 15:16:01 ...`) has no year field. The parser processes lines in order and increments an internal year counter whenever a line's month is earlier than the previous line's — the standard heuristic, since only a genuine Dec→Jan wrap can trigger that, not ordinary out-of-order jitter. Found and fixed after confirming the full loghub dataset genuinely crosses a year boundary; verified the gap across a real wrap computes as seconds, not as a false ~364-day jump.
- **Log rotation handling in `-follow`.** Both of logrotate's common strategies are handled: rename+recreate (retries opening the path until the new file appears) and in-place `copytruncate` truncation. The truncation case had a real ~50%-flaky race — a truncate immediately followed by a rewrite can leave the file no smaller than the last read position by the next check, so a bare size comparison misses it. Fixed with a bounded trailing-content verification rather than trusting size alone.
- **Live alerts fire the instant a burst crosses the threshold**, not after it ends. A separate streaming detector (`internal/detector.Live`) exists specifically for this — the batch detector's "wait until the burst is fully over" approach is right for analyzing a static file, but useless for real-time monitoring, where you want to know about an attack while it's still happening.
- **Severity scales with `-threshold`, not a fixed number.** A source is "critical" at ≥4x whatever threshold is configured, not some hardcoded attempt count — so the tiers stay meaningful whether you're running with the default (5) or a much stricter/looser one. JSON output includes the `Severity` field too, so downstream consumers get it without recomputing.
- **Real data over synthetic where it matters.** Automated tests use synthetic fixtures (deterministic, no live dependency), but the demo/verification data is [loghub](https://github.com/logpai/loghub)'s real production syslog — genuine attacker behavior, not invented log lines.

## Repo structure

- `cmd/poc-logids/` — CLI entry point
- `internal/parser/` — extracts failed SSH auth events from log lines (syslog `pam_unix` and modern OpenSSH formats), inferring a consistent year across a Dec 31 -> Jan 1 boundary since syslog timestamps don't carry one
- `internal/detector/` — flags brute-force bursts per source (batch mode, and a streaming variant for `-follow`)
- `internal/output/` — JSON / ASCII table / one-line rendering
- `internal/tail/` — `fsnotify`-based file following for `-follow`, handling log rotation
- `resources/` — supporting/reference materials (non-code), including real-world log samples

## Tech stack

Go. See `CLAUDE.md` for full design notes and rationale.
