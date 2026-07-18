# Project: poc-logids (working title)

## Goal

Second in a series of portfolio projects supporting a career pivot from software engineering to cybersecurity engineering (first: `poc-osint`, at `~/dev-projects/tah-osint-poc`). A log-based anomaly detection tool — a "mini IDS" — that parses log data (initially file-based, likely with a live-tail mode) and flags suspicious patterns. Demonstrates blue-team/detection-engineering skill, complementing `poc-osint`'s offensive/recon-leaning first project.

## Decided so far (from planning discussion in the poc-osint session, before this project existed)

- **Type: log-based, not raw packet capture.** A true real-time NIDS (live packet sniffing) was considered and rejected: packet capture needs libpcap/raw sockets + elevated privileges (root or `CAP_NET_RAW`), WSL2's NAT'd virtual networking limits what real external traffic you'd even observe (you'd mostly be capturing your own loopback/Docker traffic, which would need synthesizing anyway), and it breaks the deterministic/mockable testing philosophy that worked well for `poc-osint`. Log-based detection (auth logs, web server logs, etc.) is far more buildable and testable — feed known log lines, assert known detections, no privilege escalation, no environment-specific networking quirks. A live-tail mode (watching a growing log file, like `tail -f`) can still deliver most of the "real-time" feel without packet-capture complexity, and maps more directly to actual SOC/blue-team log-analysis work than a packet sniffer would.
- **Language: Go.** The task shape (tail log → parse → detect → alert, streaming) is a concurrency-pipeline problem, not a raw-throughput/bare-metal one. Go's goroutines/channels fit that shape naturally; it distributes as a single static binary (no venv story, a nice contrast to `poc-osint`'s Python setup); it's genuinely common in modern security tooling (Suricata's newer tooling, trivy, syft, grype); and it carries far lower project-risk/dev-time than C++ or C for equivalent portfolio payoff, since this isn't a wire-speed/bare-metal problem. C++ and C were considered but rejected on the grounds that their low-level control only pays off for packet-level processing, which was already ruled out. Rust was considered as a security-conscious systems-language alternative (increasingly the real industry choice for security tooling, since a memory-corruption bug in a security tool is a uniquely bad failure mode) but not chosen for this project — steeper learning curve, more time would go to language mechanics than detection logic. Worth remembering as a candidate for a *future* portfolio project if a systems-language/memory-safety narrative becomes the goal.

## Open decisions for the next session

Everything below still needs the same kind of scoping conversation `poc-osint` went through (tech stack was easy here since it's decided; scope/architecture is not yet):

1. **Repo setup** — GitHub repo name/creation (this local directory is named `poc-logids` but that's a placeholder, not committed to), branch strategy (`poc-osint` used `main` + `develop`, worked well, probably just reuse it).
2. **Detection scope** — what specific anomalies/rules to detect first. Candidates to discuss: SSH brute-force attempts in `auth.log`, repeated 4xx/scanning behavior in web server logs, something else entirely. Needs the same kind of "core functionality" scoping `poc-osint`'s CLAUDE.md went through (see that project's "Scope" section for the shape of that discussion).
3. **Target log format(s)** — which log source(s) to parse first (real syslog/auth.log format, a specific web server log format, or a synthetic/generic format designed for the demo) — this drives parser design.
4. **Live-tail mechanism** — how to implement in Go (`fsnotify`-based file watching vs. polling) — needs research before deciding.
5. **Go project structure** — module layout, CLI framework choice (stdlib `flag` package vs. `cobra`), testing approach (Go's built-in `testing` package, table-driven tests are idiomatic).
6. **Test/demo log sources** — synthetic generated logs for CI (deterministic, no live dependency — same philosophy as `poc-osint`'s Docker fixtures) vs. any real log samples. Given no live "target" exists here the way a domain did for `poc-osint`, this is probably simpler: just synthetic fixture logs from the start.
7. **Engineering requirements checklist** — likely mirrors `poc-osint`'s: separate parsing/detection layers for testability, structured output (JSON + human-readable), README with an explicit scope/usage section, CI via GitHub Actions. Confirm these are still the right bar before assuming so.

## Working preferences (carried over from `poc-osint`)

- User prefers concise, direct communication — minimal explanation, no unnecessary verbosity.
- User is comfortable with CLI workflows.
- User wants critical, fact-checked pushback grounded in analysis/logic, not agreement-seeking or validation — verify claims (including your own) rather than assuming they hold.
- User values terminal/ASCII visualizations for tool output where applicable (checklist grids, diff views, progress indicators) — worth considering from the start here rather than retrofitting later.
