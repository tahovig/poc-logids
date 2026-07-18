// Package output renders detected alerts as JSON or a human-readable
// ASCII table.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tahovig/poc-logids/internal/detector"
)

// ToJSON renders alerts as indented JSON. A nil/empty slice renders
// as "[]", not "null", so consumers don't need to special-case it.
// Order is chronological (Detect's natural order), not severity-
// sorted -- unlike the table, this is for machine consumption, where
// a stable, predictable order matters more than visual triage.
func ToJSON(alerts []detector.Alert) ([]byte, error) {
	if alerts == nil {
		alerts = []detector.Alert{}
	}
	return json.MarshalIndent(alerts, "", "  ")
}

// ToJSONLine renders a single alert as compact JSON, suited to
// live-tail mode where alerts arrive one at a time and each line of
// output should be independently valid JSON (composable with tools
// like jq, one alert per line).
func ToJSONLine(a detector.Alert) ([]byte, error) {
	return json.Marshal(a)
}

const tableTimeLayout = "Jan _2 15:04:05"

const (
	ansiReset  = "\x1b[0m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
)

// severityColor returns the ANSI color code for s, or "" if color is
// disabled or s doesn't warrant one (SeverityNormal renders plain --
// it already met Threshold just by being an alert at all; color is
// reserved for standing out further than that).
func severityColor(s detector.Severity, color bool) string {
	if !color {
		return ""
	}
	switch s {
	case detector.SeverityCritical:
		return ansiRed
	case detector.SeverityWarning:
		return ansiYellow
	default:
		return ""
	}
}

// isTerminal reports whether f is a real terminal, so color escape
// codes are only ever written to an actual TTY -- never to a pipe,
// redirected file, or captured test output, matching poc-osint's
// spinner doing the same isatty() check before animating.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// rate returns a's attempts per minute, useful alongside the raw
// count since a fast burst is a stronger signal than a slow one at
// the same attempt count. Duration is floored at one second: syslog's
// one-second timestamp resolution means a fast burst can report a
// zero FirstSeen-LastSeen span, which would otherwise divide by zero.
func rate(a detector.Alert) float64 {
	d := a.LastSeen.Sub(a.FirstSeen)
	if d < time.Second {
		d = time.Second
	}
	return float64(a.Attempts) / d.Minutes()
}

func formatRate(a detector.Alert) string {
	return fmt.Sprintf("%.1f/min", rate(a))
}

// severityRank orders SeverityCritical highest, for worst-first
// display sorting.
func severityRank(s detector.Severity) int {
	switch s {
	case detector.SeverityCritical:
		return 2
	case detector.SeverityWarning:
		return 1
	default:
		return 0
	}
}

// sortedForDisplay returns a copy of alerts ordered worst-first
// (highest severity tier, then highest attempt count), leaving the
// input (and its chronological order, as ToJSON relies on) untouched.
func sortedForDisplay(alerts []detector.Alert) []detector.Alert {
	sorted := make([]detector.Alert, len(alerts))
	copy(sorted, alerts)
	sort.SliceStable(sorted, func(i, j int) bool {
		si, sj := severityRank(sorted[i].Severity), severityRank(sorted[j].Severity)
		if si != sj {
			return si > sj
		}
		return sorted[i].Attempts > sorted[j].Attempts
	})
	return sorted
}

// ToLine renders a single alert as a one-line human-readable summary,
// suited to live-tail mode where alerts arrive one at a time rather
// than as a batch table. Colored by severity on a real terminal.
func ToLine(a detector.Alert) string {
	return renderLine(a, isTerminal(os.Stdout))
}

func renderLine(a detector.Alert, color bool) string {
	users := "-"
	if len(a.Users) > 0 {
		users = strings.Join(a.Users, ",")
	}
	line := fmt.Sprintf("[ALERT] %s  source=%s  attempts=%d  rate=%s  users=%s",
		a.LastSeen.Format(tableTimeLayout), a.Source, a.Attempts, formatRate(a), users)
	if c := severityColor(a.Severity, color); c != "" {
		return c + line + ansiReset
	}
	return line
}

// ToTable renders alerts as a column-aligned ASCII table, sorted
// worst-first and colored by severity on a real terminal, so the
// alerts most worth reviewing don't have to compete on equal footing
// with routine ones.
func ToTable(alerts []detector.Alert) string {
	return renderTable(alerts, isTerminal(os.Stdout))
}

func renderTable(alerts []detector.Alert, color bool) string {
	if len(alerts) == 0 {
		return "No brute-force activity detected.\n"
	}
	sorted := sortedForDisplay(alerts)

	headers := []string{"SOURCE", "ATTEMPTS", "RATE", "FIRST SEEN", "LAST SEEN", "USERS TRIED"}
	rows := make([][]string, 0, len(sorted))
	for _, a := range sorted {
		rows = append(rows, []string{
			a.Source,
			fmt.Sprintf("%d", a.Attempts),
			formatRate(a),
			a.FirstSeen.Format(tableTimeLayout),
			a.LastSeen.Format(tableTimeLayout),
			strings.Join(a.Users, ", "),
		})
	}

	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	pad := func(cells []string) string {
		var line strings.Builder
		for i, cell := range cells {
			fmt.Fprintf(&line, "%-*s", widths[i]+2, cell)
		}
		return line.String()
	}

	var b strings.Builder
	b.WriteString(pad(headers))
	b.WriteByte('\n')
	for i, row := range rows {
		line := pad(row)
		if c := severityColor(sorted[i].Severity, color); c != "" {
			b.WriteString(c)
			b.WriteString(line)
			b.WriteString(ansiReset)
		} else {
			b.WriteString(line)
		}
		b.WriteByte('\n')
	}
	return b.String()
}
