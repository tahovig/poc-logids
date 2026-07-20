// Package output renders detected alerts as JSON or a human-readable
// ASCII table.
package output

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
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

// summaryDetailCap bounds how many alerts within one severity tier
// get a full plain-English sentence before the rest are rolled up
// into a single "...and N more" line -- the whole point of -summary
// is a reader who isn't a security analyst getting the headline
// picture, not one paragraph per row of a 300-row dataset.
const summaryDetailCap = 5

// summaryTierOrder is worst-first, matching the table's visual
// triage, and summaryTierLabel avoids the Severity jargon ("warning",
// "critical") in favor of plain language for a non-analyst reader.
var summaryTierOrder = []detector.Severity{detector.SeverityCritical, detector.SeverityWarning, detector.SeverityNormal}

var summaryTierLabel = map[detector.Severity]string{
	detector.SeverityCritical: "Severe attacks",
	detector.SeverityWarning:  "Moderate attacks",
	detector.SeverityNormal:   "Minor attempts",
}

// ToSummary renders alerts as a plain-English outline grouped by
// severity, for a reader who doesn't need (or want) the table's raw
// columns. Source IPs shown in detail get a best-effort reverse-DNS
// name via a real network lookup; rolled-up entries don't, since
// resolving hundreds of IPs just to discard most of them would be
// wasted latency for no benefit.
func ToSummary(alerts []detector.Alert) string {
	return renderSummary(alerts, resolveHostnames)
}

func renderSummary(alerts []detector.Alert, resolve func([]string) map[string]string) string {
	if len(alerts) == 0 {
		return "No brute-force activity detected.\n"
	}

	byTier := make(map[detector.Severity][]detector.Alert, len(summaryTierOrder))
	for _, a := range alerts {
		byTier[a.Severity] = append(byTier[a.Severity], a)
	}
	for _, tier := range summaryTierOrder {
		list := byTier[tier]
		sort.SliceStable(list, func(i, j int) bool { return list[i].Attempts > list[j].Attempts })
	}

	// Only resolve hostnames for alerts that will actually be shown
	// in detail, not ones headed for a rollup line.
	var toResolve []string
	for _, tier := range summaryTierOrder {
		list := byTier[tier]
		for _, a := range list[:min(len(list), summaryDetailCap)] {
			toResolve = append(toResolve, a.Source)
		}
	}
	names := resolve(toResolve)

	first, last := seenRange(alerts)

	var b strings.Builder
	fmt.Fprintf(&b, "SSH Brute-Force Summary\n")
	fmt.Fprintf(&b, "%d source(s) flagged, %s to %s\n\n",
		len(alerts), first.Format(tableTimeLayout), last.Format(tableTimeLayout))

	for _, tier := range summaryTierOrder {
		list := byTier[tier]
		if len(list) == 0 {
			continue
		}
		fmt.Fprintf(&b, "%s (%d):\n", summaryTierLabel[tier], len(list))
		shown := min(len(list), summaryDetailCap)
		for _, a := range list[:shown] {
			fmt.Fprintf(&b, "  - %s\n", summarySentence(a, names[a.Source]))
		}
		if remaining := list[shown:]; len(remaining) > 0 {
			fmt.Fprintf(&b, "  ...and %d more, most commonly targeting: %s\n", len(remaining), topUsers(remaining, 3))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// ToSummaryLine renders a single alert as a plain-English sentence,
// suited to live-tail mode where alerts arrive one at a time rather
// than as a batch to group into tiers.
func ToSummaryLine(a detector.Alert) string {
	name := resolveHostnames([]string{a.Source})[a.Source]
	return summarySentence(a, name)
}

func summarySentence(a detector.Alert, hostname string) string {
	who := a.Source
	if hostname != "" {
		who = fmt.Sprintf("%s (%s)", a.Source, hostname)
	}
	return fmt.Sprintf("%s tried %d password(s)%s over %s (%s) — last seen %s",
		who, a.Attempts, describeUsers(a.Users), humanDuration(a.LastSeen.Sub(a.FirstSeen)),
		formatRate(a), a.LastSeen.Format(tableTimeLayout))
}

// describeUsers renders the attempted usernames as a short English
// clause. More than two collapses to "X, Y, and N other account(s)"
// rather than listing every username a real burst tries dozens of.
func describeUsers(users []string) string {
	switch len(users) {
	case 0:
		return ""
	case 1:
		return fmt.Sprintf(" against %s", users[0])
	case 2:
		return fmt.Sprintf(" against %s and %s", users[0], users[1])
	default:
		return fmt.Sprintf(" against %s, %s, and %d other account(s)", users[0], users[1], len(users)-2)
	}
}

// humanDuration renders a burst's span in plain English rather than
// Go's default duration formatting (e.g. "1m30s").
func humanDuration(d time.Duration) string {
	switch {
	case d < time.Second:
		return "under a second"
	case d < time.Minute:
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	default:
		return fmt.Sprintf("%d minute(s)", int(d.Minutes()))
	}
}

// topUsers summarizes the most-attempted usernames across alerts as
// "root (18), admin (9)", used for the rollup line covering alerts
// that didn't get their own detailed sentence. Ties break
// alphabetically for deterministic output.
func topUsers(alerts []detector.Alert, topN int) string {
	counts := make(map[string]int)
	for _, a := range alerts {
		for _, u := range a.Users {
			counts[u]++
		}
	}
	if len(counts) == 0 {
		return "unknown accounts"
	}
	type userCount struct {
		user  string
		count int
	}
	list := make([]userCount, 0, len(counts))
	for u, c := range counts {
		list = append(list, userCount{u, c})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].count != list[j].count {
			return list[i].count > list[j].count
		}
		return list[i].user < list[j].user
	})
	if len(list) > topN {
		list = list[:topN]
	}
	parts := make([]string, len(list))
	for i, uc := range list {
		parts[i] = fmt.Sprintf("%s (%d)", uc.user, uc.count)
	}
	return strings.Join(parts, ", ")
}

// seenRange returns the earliest FirstSeen and latest LastSeen across
// alerts. Not assumed to already be sorted either way: Detect's
// output is ordered by FirstSeen, but a burst that starts early can
// still end later than one that starts after it.
func seenRange(alerts []detector.Alert) (first, last time.Time) {
	first, last = alerts[0].FirstSeen, alerts[0].LastSeen
	for _, a := range alerts[1:] {
		if a.FirstSeen.Before(first) {
			first = a.FirstSeen
		}
		if a.LastSeen.After(last) {
			last = a.LastSeen
		}
	}
	return first, last
}

// lookupTimeout bounds each individual reverse-DNS lookup so a
// slow or unresponsive resolver can't stall the whole run.
const lookupTimeout = 1500 * time.Millisecond

// lookupAddr is a package var (not a direct net.DefaultResolver call)
// so tests can substitute a stub -- no live DNS in the test suite,
// matching the project's deterministic/mockable testing philosophy.
var lookupAddr = net.DefaultResolver.LookupAddr

// resolveHostnames looks up reverse-DNS names for ips concurrently,
// each bounded by lookupTimeout. Best-effort: an IP with no PTR
// record, or one that times out, is simply omitted from the result
// rather than treated as an error -- a missing hostname just means
// the summary shows the bare IP.
func resolveHostnames(ips []string) map[string]string {
	names := make(map[string]string, len(ips))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
			defer cancel()
			hosts, err := lookupAddr(ctx, ip)
			if err != nil || len(hosts) == 0 {
				return
			}
			mu.Lock()
			names[ip] = strings.TrimSuffix(hosts[0], ".")
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return names
}
