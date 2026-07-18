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

## Open decisions for the next session

1. **Go project structure** — module layout (single `main` package vs. `cmd/` + `internal/`), testing approach (Go's built-in `testing` package, table-driven tests are idiomatic — not yet discussed in detail).
2. **Parser design specifics** — exact fields to extract from auth-log lines (timestamp, source IP, target user, attempt outcome), and whether to support both the loghub dataset's older `pam_unix` line format and the more common modern OpenSSH format, or pick one canonical shape for v1.
3. **Brute-force detection thresholds** — what counts as "brute-force" (N failed attempts within T seconds/minutes) — needs concrete default values plus configurability.
4. **Engineering requirements checklist** — likely mirrors `poc-osint`'s: separate parsing/detection layers for testability, structured output (JSON + human-readable), README with an explicit scope/usage section, CI via GitHub Actions. Not yet explicitly confirmed for this project.
5. **Package skeleton** — not yet built; `code/` currently has only a `.gitkeep`.

## Working preferences (carried over from `poc-osint`)

- User prefers concise, direct communication — minimal explanation, no unnecessary verbosity.
- User is comfortable with CLI workflows.
- User wants critical, fact-checked pushback grounded in analysis/logic, not agreement-seeking or validation — verify claims (including your own) rather than assuming they hold.
- User values terminal/ASCII visualizations for tool output where applicable (checklist grids, diff views, progress indicators) — worth considering from the start here rather than retrofitting later.
