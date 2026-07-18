# Project: poc-logids (working title)

## Goal

Second in a series of portfolio projects supporting a career pivot from software engineering to cybersecurity engineering (first: `poc-osint`, at `~/dev-projects/tah-osint-poc`). A log-based anomaly detection tool — a "mini IDS" — that parses log data (initially file-based, likely with a live-tail mode) and flags suspicious patterns. Demonstrates blue-team/detection-engineering skill, complementing `poc-osint`'s offensive/recon-leaning first project.

## Decided so far (from planning discussion in the poc-osint session, before this project existed)

- **Type: log-based, not raw packet capture.** A true real-time NIDS (live packet sniffing) was considered and rejected: packet capture needs libpcap/raw sockets + elevated privileges (root or `CAP_NET_RAW`), WSL2's NAT'd virtual networking limits what real external traffic you'd even observe (you'd mostly be capturing your own loopback/Docker traffic, which would need synthesizing anyway), and it breaks the deterministic/mockable testing philosophy that worked well for `poc-osint`. Log-based detection (auth logs, web server logs, etc.) is far more buildable and testable — feed known log lines, assert known detections, no privilege escalation, no environment-specific networking quirks. A live-tail mode (watching a growing log file, like `tail -f`) can still deliver most of the "real-time" feel without packet-capture complexity, and maps more directly to actual SOC/blue-team log-analysis work than a packet sniffer would.
- **Language: Go.** The task shape (tail log → parse → detect → alert, streaming) is a concurrency-pipeline problem, not a raw-throughput/bare-metal one. Go's goroutines/channels fit that shape naturally; it distributes as a single static binary (no venv story, a nice contrast to `poc-osint`'s Python setup); it's genuinely common in modern security tooling (Suricata's newer tooling, trivy, syft, grype); and it carries far lower project-risk/dev-time than C++ or C for equivalent portfolio payoff, since this isn't a wire-speed/bare-metal problem. C++ and C were considered but rejected on the grounds that their low-level control only pays off for packet-level processing, which was already ruled out. Rust was considered as a security-conscious systems-language alternative (increasingly the real industry choice for security tooling, since a memory-corruption bug in a security tool is a uniquely bad failure mode) but not chosen for this project — steeper learning curve, more time would go to language mechanics than detection logic. Worth remembering as a candidate for a *future* portfolio project if a systems-language/memory-safety narrative becomes the goal.

## Repo

[https://github.com/tahovig/poc-logids.git](https://github.com/tahovig/poc-logids.git) — `main` + `develop` pushed, public, default branch `main`.

## Branch strategy

- `main` — stable, deployable state
- `develop` — active development (working branch)

## Current state

- Git repo initialized at `~/dev-projects/poc-logids`. `main` has the initial commit (README, .gitignore, `code/`, `resources/`, CLAUDE.md); `develop` branched from it and is the active working branch. Both pushed to GitHub (`origin`), tracking branches set.

## Scope: SSH brute-force detection in auth.log

**Detection target**: repeated failed-auth attempts from a single source IP within a configurable time window, in SSH/syslog auth-log-style data (`sshd(pam_unix)[...]: authentication failure; ... rhost=<ip>` and equivalent modern OpenSSH `Failed password for ... from <ip> port ... ssh2` lines). Chosen over web-log scanning detection (repeated 4xx bursts) to keep v1 tightly scoped to one well-defined signal — same discipline as `poc-osint` shipping one narrow module well rather than two loose ones. Web-log scanning detection is documented future work, not built now.

**Log data sources** (decided after evaluating real vs. synthetic — user wanted real, non-self-generated data for the demo, not just synthetic):
- **Real demo data**: [loghub](https://github.com/logpai/loghub) `Linux` dataset — genuine production syslog from a real system, 263.9 days / 25,567 lines / 2.25 MiB, freely available for research/academic use with attribution (full dataset via Zenodo, sample at `Linux/Linux_2k.log`). Verified via direct fetch: contains real SSH brute-force patterns (e.g. dozens of `authentication failure; ... rhost=218.188.2.4` from one IP within the same second). Two other real-data options were considered and set aside for now: standing up a real internet-facing SSH honeypot/VPS (more authentic, mirrors `poc-osint`'s live-testing approach, but costs money and needs days to accumulate a sample — a candidate stretch goal later) and other public honeypot datasets.
- **Test/CI fixtures**: synthetic generated log lines, deterministic, no live dependency — same philosophy as `poc-osint`'s Docker fixtures.

**Explicitly deferred — not part of this project**: DNP3/ICS-SCADA log or protocol analysis. User has a strong background in critical infrastructure protection (energy generation/transmission/distribution, EMS) and raised DNP3 detection as a possible angle, using public pcap datasets (e.g. Netresec's 4SICS ICS lab captures). Correctly self-identified as a poor fit here: DNP3 analysis is pcap-native, and this project's whole premise (see "Decided so far" above) is log-based specifically to avoid packet-capture complexity. A technical bridge exists (Zeek's DNP3 analyzer converts pcap → structured `dnp3.log`), but folding it in as a secondary format would dilute both this project's focus and the ICS angle's own value. Flagged as a strong candidate for one of the "2-3 more POC projects" mentioned in the `poc-osint` Goal section — deserves to be its own pcap-native project built around the EMS background as the headline, not a footnote here.

**Live-tail mechanism**: `fsnotify`-based file watching, not polling. Event-driven, handles log rotation/truncation (real auth.log gets rotated by logrotate) better than a naive poll loop, and is the standard approach Go tail implementations use (e.g. patterns from `nxadm/tail`). One added dependency, well-maintained. Rotation-handling behavior should be documented explicitly in the README once built — a legitimate engineering-rigor point, similar to how `poc-osint` documented its crt.sh Postgres fallback.

**CLI framework**: stdlib `flag`, not `cobra` — decided provisionally, to revisit only if the tool ends up needing real subcommands (e.g. `scan` vs. `tail` vs. a future `compare`, mirroring `poc-osint`'s subcommand shape). Starting minimal-dependency, consistent with `poc-osint`'s style.

## Package skeleton — built

Go toolchain: installed Go 1.26.5 from the official tarball to `~/.local/go` (Ubuntu 20.04's `apt` only offers a stale `golang-go 1.13`), added to `PATH` via `~/.bashrc`. No `sudo` available non-interactively in this environment, so it's a user-local install rather than `/usr/local/go`.

**Module layout** — deviated from `poc-osint`'s `code/`-nested src-layout: Go's convention is `go.mod` at the repo root (every Go tool assumes this), so `code/` was dropped as a source container; `resources/` still holds non-code material. Module path `github.com/tahovig/poc-logids`, no external dependencies yet (added once `fsnotify`-based live-tail is built).

- `cmd/poc-logids/main.go` — CLI entry point. Flags: `-file` (required), `-json`, `-threshold` (default 5), `-window` (default 60s, Go duration syntax). Reads the file with a buffered line scanner, parses, detects, renders. Bad/missing `-file` produces a clean stderr message + usage + exit 1, not a panic.
- `internal/parser/parser.go` — `ParseLine(line string) (AuthFailureEvent, bool)`, pure/no I/O. Two regex formats tried in order: the older `sshd(pam_unix)[pid]: authentication failure; ... rhost=<host>` syslog format (needed for the loghub dataset — `rhost` may be a raw IP or a reverse-DNS hostname, `user=` only present on some lines) and the modern OpenSSH `sshd[pid]: Failed password for (invalid user )?<user> from <ip> port <port> ssh2` format. `ok` is `false` for the many unrelated lines in a real auth log (session open/close, cron, logrotate, the `pam_unix` "check pass; user unknown" precursor line that has no `rhost` and would double-count if matched) — not an error. Syslog timestamps have no year (`Jan _2 15:04:05` layout, parses into year 0000); detection only relies on relative deltas within one log, so this is an accepted, documented limitation, not a bug — would need real handling before ingesting logs spanning a Dec 31 → Jan 1 boundary.
- `internal/detector/detector.go` — `Detect(events, Config{Threshold, Window}) []Alert`. Groups by source, sorts by timestamp, then chains consecutive attempts into a burst as long as each gap stays within `Window`; a chain flagged if its length reaches `Threshold`. **Bug found via real-data verification, fixed**: an earlier sliding-window version capped each alert at exactly `Threshold` events and restarted the window immediately after crossing it, which fragmented one real 10-attempt burst (loghub data, syslog's 1-second timestamp resolution means several attempts often land on the same second) into two artificial 5-attempt alerts. Rewritten to chain-until-the-burst-actually-ends instead of capping at threshold; regression test (`TestDetect_LongBurstNotFragmented`) added. `DefaultConfig` is 5 attempts / 60s.
- `internal/output/output.go` — `ToJSON` (indented `encoding/json`) and `ToTable` (column-width-aligned ASCII table, `SOURCE | ATTEMPTS | FIRST SEEN | LAST SEEN | USERS TRIED`) — the terminal/ASCII visualization preference applied from the start rather than retrofitted.
- 18 tests across all three packages (table-driven), `go vet` clean, all real fixture lines in `parser_test.go` are taken verbatim from the real loghub sample, not invented.
- **Verified end-to-end against real data**: built the binary and ran it against `resources/loghub-linux/Linux_2k.log` (real production syslog, not synthetic) — 41 genuine brute-force bursts detected at default thresholds, table and `-json` output both confirmed, missing-`-file` error path confirmed. This run is what surfaced the burst-fragmentation bug above.
- `resources/loghub-linux/Linux_2k.log` — vendored real loghub sample (2,000 lines) + `README.md` noting source/license/fetch date, per the data-source decision above.

## CI — built

`.github/workflows/ci.yml` — single `build-test` job on `push`/`pull_request` to `main`/`develop`: `actions/setup-go@v5` (version pinned via `go-version-file: go.mod`, dependency cache disabled for now — no `go.sum` yet since there are zero external dependencies), `gofmt -l` check, `go vet ./...`, `go build ./...`, `go test ./... -v`.

Deliberately no version matrix, unlike `poc-osint`'s Python 3.11/3.12 matrix: `go.mod` already pins a minimum Go version (1.26.5), so an older-version matrix entry would just fail on that floor rather than catch a genuine compatibility gap. Also no second (integration) job — there's no live target or Docker fixture here, since the real demo data is a vendored static file, not something fetched at test time.

**Confirmed green on GitHub**: `gh run watch` on two consecutive pushes — the first surfaced a noisy-but-harmless "Restore cache failed" annotation (no `go.sum` for the cache step to key on), fixed by disabling the cache; the second run is fully clean except an unrelated upstream Node.js 20 deprecation notice from the action runtimes themselves (`actions/checkout`, `actions/setup-go`) — not something in our control, will resolve when those actions bump their major version. README CI badge added, pointing at `main` (will go green once `develop` is merged there).

## Open decisions for the next session

1. **Live-tail mode** — `fsnotify`-based watching of a growing file, including logrotate-safe handling (documented as planned in the README, not yet built).
2. **Full loghub dataset vs. 2k sample** — currently only the 2,000-line sample is vendored; decide whether to fetch the full 263.9-day dataset (via Zenodo) for a more thorough demo, or whether the sample is sufficient.
3. **LICENSE** — not yet added; `poc-osint` added it in a later portfolio-readiness pass rather than the initial scaffold, likely fine to defer here too.
4. **Merging `develop` into `main`** — not yet done; `main` still only has the initial scaffold commit. Worth doing once there's a natural checkpoint (e.g. after live-tail, or after a portfolio-readiness pass like `poc-osint` did).

## Working preferences (carried over from `poc-osint`)

- User prefers concise, direct communication — minimal explanation, no unnecessary verbosity.
- User is comfortable with CLI workflows.
- User wants critical, fact-checked pushback grounded in analysis/logic, not agreement-seeking or validation — verify claims (including your own) rather than assuming they hold.
- User values terminal/ASCII visualizations for tool output where applicable (checklist grids, diff views, progress indicators) — worth considering from the start here rather than retrofitting later.
