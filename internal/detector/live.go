package detector

import "github.com/tahovig/poc-logids/internal/parser"

// Live tracks per-source burst state incrementally, for use with a
// stream of events (e.g. live-tail mode) rather than a fully-known
// batch. Unlike Detect, which only reports a burst once it has fully
// ended, Live alerts the instant a chain first reaches Threshold --
// appropriate for real-time monitoring, where waiting for an
// in-progress attack to stop before reporting it defeats the point.
// Exactly one alert is emitted per chain, at the moment it crosses
// the threshold; the chain is not re-alerted as it continues to grow.
type Live struct {
	cfg    Config
	chains map[string]*liveChain
}

type liveChain struct {
	events  []parser.AuthFailureEvent
	alerted bool
}

// NewLive creates a Live detector using cfg.
func NewLive(cfg Config) *Live {
	return &Live{cfg: cfg, chains: make(map[string]*liveChain)}
}

// Feed processes one new event. It returns an alert and ok=true if
// this event just pushed its source's current chain to Threshold
// length for the first time.
func (l *Live) Feed(e parser.AuthFailureEvent) (Alert, bool) {
	c, exists := l.chains[e.Source]
	if !exists || e.Timestamp.Sub(c.events[len(c.events)-1].Timestamp) > l.cfg.Window {
		c = &liveChain{}
		l.chains[e.Source] = c
	}
	c.events = append(c.events, e)

	if !c.alerted && len(c.events) >= l.cfg.Threshold {
		c.alerted = true
		// Always fires at exactly Threshold attempts (that's the
		// point -- report the instant it's crossed, not after), so
		// Severity here is always SeverityNormal; it exists mainly
		// for Detect's fully-ended bursts, which can run well past
		// Threshold before the chain breaks.
		return buildAlert(e.Source, c.events, l.cfg.Threshold), true
	}
	return Alert{}, false
}
