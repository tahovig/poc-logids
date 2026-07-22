// Package counterintel decides when a source has earned a closer
// look -- a repeat offender or an unusually severe burst -- and
// gathers passive intelligence about it from public registries.
// "Passive" is load-bearing: nothing in this package ever sends
// traffic to the source IP itself, only to third-party lookup
// services (RDAP registries, GeoIP databases), the same way a human
// analyst would look someone up rather than probe them.
//
// Repeat-offender tracking is deliberately driven off individual
// parsed events, not detector.Alerts: a source making single-attempt
// connections minutes apart never trips detector.Detect/Live's own
// burst threshold (no Alert is ever produced for it), but it's
// exactly the kind of low-and-slow, keeps-coming-back source worth a
// closer look. Severity-based triggering, by contrast, only makes
// sense off an Alert, since only an Alert carries a Severity.
package counterintel

import (
	"time"

	"github.com/tahovig/poc-logids/internal/detector"
	"github.com/tahovig/poc-logids/internal/parser"
)

// Config controls when a source IP is worth enriching.
type Config struct {
	// RepeatThreshold is how many individual failed-auth events (not
	// full brute-force bursts -- see the package doc) from the same
	// source within RepeatWindow trigger enrichment. This catches a
	// "low and slow" source that never bursts fast enough to trip
	// detector.Detect/Live's own Threshold -- e.g. a handful of
	// single-attempt connections minutes apart, no faster than an
	// ordinary user mistyping a password, that would otherwise never
	// produce an Alert at all.
	RepeatThreshold int
	RepeatWindow    time.Duration
	// Cooldown is the minimum time between enrichments of the same
	// source, so one that keeps re-triggering doesn't repeatedly
	// spend external lookups.
	Cooldown time.Duration
}

// DefaultConfig fires on a source's 3rd failed-auth event within an
// hour, or immediately on any single critical-severity alert (see
// detector.SeverityCritical), and won't re-enrich the same source
// again for 24 hours.
var DefaultConfig = Config{
	RepeatThreshold: 3,
	RepeatWindow:    time.Hour,
	Cooldown:        24 * time.Hour,
}

// Reason explains why Observe decided a source was worth enriching.
type Reason string

const (
	// ReasonRepeat: RepeatThreshold failed-auth events from this
	// source landed within RepeatWindow -- it keeps coming back, even
	// if no single visit was fast enough to trip a brute-force Alert.
	ReasonRepeat Reason = "repeat_offender"
	// ReasonSeverity: a single alert reached detector.SeverityCritical
	// -- worth a look on first sighting, without waiting for a repeat
	// history. Note: detector.Live's alerts always fire at exactly
	// Threshold attempts and are therefore always SeverityNormal (see
	// live.go) -- in practice this reason only ever comes from
	// detector.Detect's batch alerts, which can run well past
	// Threshold before a chain breaks.
	ReasonSeverity Reason = "critical_severity"
)

// Tracker decides, event by event and alert by alert, whether a
// source has just crossed the bar for enrichment. All windowing and
// cooldown math uses each event/alert's own timestamp rather than
// wall-clock time, so replaying a batch log file behaves the same as
// watching it live -- consistent with the rest of the project, where
// detection already relies on log-timestamp deltas rather than real
// time.
type Tracker struct {
	cfg       Config
	eventHist map[string][]time.Time // per-source failed-auth event timestamps within the current window
	lastHit   map[string]time.Time   // per-source time of last enrichment, shared across both trigger reasons
}

// NewTracker creates a Tracker using cfg.
func NewTracker(cfg Config) *Tracker {
	return &Tracker{
		cfg:       cfg,
		eventHist: make(map[string][]time.Time),
		lastHit:   make(map[string]time.Time),
	}
}

// ObserveEvent records a single failed-auth event against its
// source's history, then reports whether it just pushed that source
// to RepeatThreshold events within RepeatWindow. Call this for every
// parsed event, not just ones that end up part of a burst -- it's the
// signal that catches a source too patient to trip Detect/Live's own
// threshold.
func (t *Tracker) ObserveEvent(e parser.AuthFailureEvent) (Reason, bool) {
	hist := append(t.eventHist[e.Source], e.Timestamp)
	cutoff := e.Timestamp.Add(-t.cfg.RepeatWindow)
	kept := hist[:0]
	for _, ts := range hist {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	t.eventHist[e.Source] = kept

	if len(kept) < t.cfg.RepeatThreshold {
		return "", false
	}
	return t.fire(e.Source, e.Timestamp, ReasonRepeat)
}

// ObserveAlert reports whether a's severity alone is enough to
// trigger enrichment, independent of repeat history.
func (t *Tracker) ObserveAlert(a detector.Alert) (Reason, bool) {
	if a.Severity != detector.SeverityCritical {
		return "", false
	}
	return t.fire(a.Source, a.LastSeen, ReasonSeverity)
}

// fire applies the shared cooldown check and, if source isn't still
// within Cooldown of its last enrichment, records ts as its new last
// enrichment time and reports reason.
func (t *Tracker) fire(source string, ts time.Time, reason Reason) (Reason, bool) {
	if last, seen := t.lastHit[source]; seen && ts.Sub(last) < t.cfg.Cooldown {
		return "", false
	}
	t.lastHit[source] = ts
	return reason, true
}
