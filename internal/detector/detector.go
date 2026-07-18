// Package detector flags bursts of failed SSH authentication
// attempts that look like brute-force activity.
package detector

import (
	"sort"
	"time"

	"github.com/tahovig/poc-logids/internal/parser"
)

// Config controls what counts as a brute-force burst.
type Config struct {
	Threshold int           // minimum failed attempts to flag as brute-force
	Window    time.Duration // attempts must fall within this span of each other
}

// DefaultConfig is a reasonable starting point: 5 failed attempts
// within 60 seconds from the same source.
var DefaultConfig = Config{Threshold: 5, Window: 60 * time.Second}

// Alert flags a burst of failed authentication attempts from one
// source that met the configured threshold within the configured
// window.
type Alert struct {
	Source    string
	Attempts  int
	FirstSeen time.Time
	LastSeen  time.Time
	Users     []string // deduped, in order of first appearance
}

// Detect groups failed-auth events by source and flags each burst —
// a maximal run of consecutive attempts where no gap between
// adjacent attempts exceeds Window — that reaches Threshold or more
// attempts. One alert is emitted per burst, covering its full length
// (not capped at Threshold), so a single sustained burst isn't
// fragmented into several threshold-sized alerts.
func Detect(events []parser.AuthFailureEvent, cfg Config) []Alert {
	bySource := make(map[string][]parser.AuthFailureEvent)
	for _, e := range events {
		bySource[e.Source] = append(bySource[e.Source], e)
	}

	var alerts []Alert
	for source, evs := range bySource {
		sort.Slice(evs, func(i, j int) bool { return evs[i].Timestamp.Before(evs[j].Timestamp) })
		alerts = append(alerts, detectBursts(source, evs, cfg)...)
	}

	sort.Slice(alerts, func(i, j int) bool { return alerts[i].FirstSeen.Before(alerts[j].FirstSeen) })
	return alerts
}

// detectBursts walks a single source's events, already sorted by
// timestamp, chaining consecutive attempts into a burst as long as
// each gap stays within Window. Whenever a chain ends (the next gap
// exceeds Window, or the events run out), it's flagged if it reached
// Threshold length.
func detectBursts(source string, evs []parser.AuthFailureEvent, cfg Config) []Alert {
	var alerts []Alert
	start := 0
	for i := 1; i <= len(evs); i++ {
		if i < len(evs) && evs[i].Timestamp.Sub(evs[i-1].Timestamp) <= cfg.Window {
			continue // still within the same burst chain
		}
		if i-start >= cfg.Threshold {
			alerts = append(alerts, buildAlert(source, evs[start:i]))
		}
		start = i
	}
	return alerts
}

func buildAlert(source string, evs []parser.AuthFailureEvent) Alert {
	users := make([]string, 0, len(evs))
	seen := make(map[string]bool, len(evs))
	for _, e := range evs {
		if e.User == "" || seen[e.User] {
			continue
		}
		seen[e.User] = true
		users = append(users, e.User)
	}
	return Alert{
		Source:    source,
		Attempts:  len(evs),
		FirstSeen: evs[0].Timestamp,
		LastSeen:  evs[len(evs)-1].Timestamp,
		Users:     users,
	}
}
