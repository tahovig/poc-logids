package counterintel

import (
	"testing"
	"time"

	"github.com/tahovig/poc-logids/internal/detector"
	"github.com/tahovig/poc-logids/internal/parser"
)

func ts(seconds int) time.Time {
	base := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	return base.Add(time.Duration(seconds) * time.Second)
}

func eventAt(source string, seconds int) parser.AuthFailureEvent {
	return parser.AuthFailureEvent{Source: source, Timestamp: ts(seconds)}
}

func alertAt(source string, severity detector.Severity, seconds int) detector.Alert {
	t := ts(seconds)
	return detector.Alert{Source: source, Severity: severity, FirstSeen: t, LastSeen: t, Attempts: 5}
}

func TestTracker_FiresOnRepeatThresholdWithinWindow(t *testing.T) {
	tr := NewTracker(Config{RepeatThreshold: 3, RepeatWindow: time.Hour, Cooldown: 24 * time.Hour})

	if _, ok := tr.ObserveEvent(eventAt("1.2.3.4", 0)); ok {
		t.Fatal("1st event: fired early")
	}
	if _, ok := tr.ObserveEvent(eventAt("1.2.3.4", 60)); ok {
		t.Fatal("2nd event: fired early")
	}
	reason, ok := tr.ObserveEvent(eventAt("1.2.3.4", 120))
	if !ok || reason != ReasonRepeat {
		t.Fatalf("3rd event: got (%q, %v), want (ReasonRepeat, true)", reason, ok)
	}
}

func TestTracker_CatchesLowAndSlowSourceNoAlertEverProduced(t *testing.T) {
	// Reproduces the real motivating case: single-attempt connections
	// ~90s apart, never fast enough to trip a burst Alert at all, but
	// unmistakably the same source repeatedly probing.
	tr := NewTracker(DefaultConfig)

	tr.ObserveEvent(eventAt("195.178.110.217", 0))
	tr.ObserveEvent(eventAt("195.178.110.217", 90))
	reason, ok := tr.ObserveEvent(eventAt("195.178.110.217", 180))
	if !ok || reason != ReasonRepeat {
		t.Fatalf("got (%q, %v), want (ReasonRepeat, true) on the 3rd sparse connection", reason, ok)
	}
}

func TestTracker_RepeatsOutsideWindowDontAccumulate(t *testing.T) {
	tr := NewTracker(Config{RepeatThreshold: 3, RepeatWindow: time.Hour, Cooldown: 24 * time.Hour})

	tr.ObserveEvent(eventAt("1.2.3.4", 0))
	tr.ObserveEvent(eventAt("1.2.3.4", 60))
	// 2 hours later -- the first two have aged out of the 1h window,
	// so this is only the 2nd event within the window, not the 3rd.
	if _, ok := tr.ObserveEvent(eventAt("1.2.3.4", 7260)); ok {
		t.Fatal("fired without 3 events inside the window")
	}
}

func TestTracker_CriticalSeverityFiresImmediately(t *testing.T) {
	tr := NewTracker(DefaultConfig)
	reason, ok := tr.ObserveAlert(alertAt("9.9.9.9", detector.SeverityCritical, 0))
	if !ok || reason != ReasonSeverity {
		t.Fatalf("got (%q, %v), want (ReasonSeverity, true) on first critical alert", reason, ok)
	}
}

func TestTracker_NonCriticalAlertNeverFiresOnItsOwn(t *testing.T) {
	tr := NewTracker(DefaultConfig)
	if _, ok := tr.ObserveAlert(alertAt("9.9.9.9", detector.SeverityWarning, 0)); ok {
		t.Fatal("warning-severity alert fired the severity trigger")
	}
}

func TestTracker_CooldownSuppressesReenrichment(t *testing.T) {
	tr := NewTracker(Config{RepeatThreshold: 1, RepeatWindow: time.Hour, Cooldown: time.Hour})

	if _, ok := tr.ObserveAlert(alertAt("1.2.3.4", detector.SeverityCritical, 0)); !ok {
		t.Fatal("1st critical alert didn't fire")
	}
	if _, ok := tr.ObserveAlert(alertAt("1.2.3.4", detector.SeverityCritical, 60)); ok {
		t.Fatal("2nd critical alert fired within cooldown")
	}
	// Past the cooldown window: should fire again.
	if _, ok := tr.ObserveAlert(alertAt("1.2.3.4", detector.SeverityCritical, 3700)); !ok {
		t.Fatal("alert past cooldown didn't fire")
	}
}

func TestTracker_CooldownSharedAcrossBothTriggerReasons(t *testing.T) {
	tr := NewTracker(Config{RepeatThreshold: 1, RepeatWindow: time.Hour, Cooldown: time.Hour})

	if _, ok := tr.ObserveAlert(alertAt("1.2.3.4", detector.SeverityCritical, 0)); !ok {
		t.Fatal("severity trigger didn't fire")
	}
	// Same source, same cooldown window, but via the repeat-event path
	// this time -- should still be suppressed.
	if _, ok := tr.ObserveEvent(eventAt("1.2.3.4", 60)); ok {
		t.Fatal("repeat trigger fired within the severity trigger's cooldown")
	}
}

func TestTracker_SourcesTrackedIndependently(t *testing.T) {
	tr := NewTracker(Config{RepeatThreshold: 2, RepeatWindow: time.Hour, Cooldown: 24 * time.Hour})

	tr.ObserveEvent(eventAt("1.1.1.1", 0))
	if _, ok := tr.ObserveEvent(eventAt("2.2.2.2", 1)); ok {
		t.Fatal("a different source's first event shouldn't inherit another source's count")
	}
}
