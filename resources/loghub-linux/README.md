# loghub Linux dataset (full)

`Linux.log` — the full real production syslog dataset (263.9 days, 25,567 lines, 2.25 MiB,
includes genuine SSH brute-force activity from many real sources), fetched 2026-07-17 from:

https://zenodo.org/records/8196385/files/Linux.tar.gz?download=1

Source project: [logpai/loghub](https://github.com/logpai/loghub) — real-world log datasets
collected from production systems, freely available for research/academic use.

Note: this file genuinely spans a calendar year boundary (June through the following
February), which is exactly the case `internal/parser.Parser`'s year-inference logic exists
to handle correctly — see its doc comment.

If you use this data, cite the loghub project per its repository's guidance.
