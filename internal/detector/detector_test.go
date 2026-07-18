package detector

import (
	"testing"
	"time"

	"github.com/tahovig/poc-logids/internal/parser"
)

func ev(source, user string, t time.Time) parser.AuthFailureEvent {
	return parser.AuthFailureEvent{Timestamp: t, Source: source, User: user}
}

func at(seconds int) time.Time {
	base := time.Date(0, time.January, 1, 0, 0, 0, 0, time.UTC)
	return base.Add(time.Duration(seconds) * time.Second)
}

func TestDetect_FlagsBurstWithinWindow(t *testing.T) {
	cfg := Config{Threshold: 5, Window: 60 * time.Second}
	events := []parser.AuthFailureEvent{
		ev("10.0.0.1", "root", at(0)),
		ev("10.0.0.1", "root", at(5)),
		ev("10.0.0.1", "admin", at(10)),
		ev("10.0.0.1", "admin", at(15)),
		ev("10.0.0.1", "test", at(20)),
	}

	alerts := Detect(events, cfg)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1: %+v", len(alerts), alerts)
	}
	a := alerts[0]
	if a.Source != "10.0.0.1" || a.Attempts != 5 {
		t.Errorf("alert = %+v, want source=10.0.0.1 attempts=5", a)
	}
	wantUsers := []string{"root", "admin", "test"}
	if len(a.Users) != len(wantUsers) {
		t.Fatalf("Users = %v, want %v", a.Users, wantUsers)
	}
	for i, u := range wantUsers {
		if a.Users[i] != u {
			t.Errorf("Users[%d] = %q, want %q", i, a.Users[i], u)
		}
	}
}

func TestDetect_BelowThresholdNotFlagged(t *testing.T) {
	cfg := Config{Threshold: 5, Window: 60 * time.Second}
	events := []parser.AuthFailureEvent{
		ev("10.0.0.1", "root", at(0)),
		ev("10.0.0.1", "root", at(5)),
		ev("10.0.0.1", "root", at(10)),
		ev("10.0.0.1", "root", at(15)),
	}

	alerts := Detect(events, cfg)
	if len(alerts) != 0 {
		t.Fatalf("got %d alerts, want 0: %+v", len(alerts), alerts)
	}
}

func TestDetect_SpreadOutAttemptsNotFlagged(t *testing.T) {
	cfg := Config{Threshold: 5, Window: 60 * time.Second}
	events := []parser.AuthFailureEvent{
		ev("10.0.0.1", "root", at(0)),
		ev("10.0.0.1", "root", at(100)),
		ev("10.0.0.1", "root", at(200)),
		ev("10.0.0.1", "root", at(300)),
		ev("10.0.0.1", "root", at(400)),
	}

	alerts := Detect(events, cfg)
	if len(alerts) != 0 {
		t.Fatalf("got %d alerts, want 0 (attempts too spread out): %+v", len(alerts), alerts)
	}
}

func TestDetect_TwoSeparateBurstsSameSource(t *testing.T) {
	cfg := Config{Threshold: 3, Window: 10 * time.Second}
	events := []parser.AuthFailureEvent{
		// first burst
		ev("10.0.0.1", "root", at(0)),
		ev("10.0.0.1", "root", at(2)),
		ev("10.0.0.1", "root", at(4)),
		// gap > window
		ev("10.0.0.1", "root", at(100)),
		ev("10.0.0.1", "root", at(102)),
		ev("10.0.0.1", "root", at(104)),
	}

	alerts := Detect(events, cfg)
	if len(alerts) != 2 {
		t.Fatalf("got %d alerts, want 2: %+v", len(alerts), alerts)
	}
	if !alerts[0].FirstSeen.Before(alerts[1].FirstSeen) {
		t.Errorf("alerts not sorted by FirstSeen: %+v", alerts)
	}
}

func TestDetect_IndependentPerSource(t *testing.T) {
	cfg := Config{Threshold: 3, Window: 60 * time.Second}
	events := []parser.AuthFailureEvent{
		ev("10.0.0.1", "root", at(0)),
		ev("10.0.0.1", "root", at(1)),
		ev("10.0.0.1", "root", at(2)),
		ev("10.0.0.2", "root", at(0)),
		ev("10.0.0.2", "root", at(1)),
	}

	alerts := Detect(events, cfg)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1 (only .1 crosses threshold): %+v", len(alerts), alerts)
	}
	if alerts[0].Source != "10.0.0.1" {
		t.Errorf("alert source = %q, want 10.0.0.1", alerts[0].Source)
	}
}

func TestDetect_LongBurstNotFragmented(t *testing.T) {
	// Regression test: a single sustained burst of 10 near-simultaneous
	// attempts (real loghub data has this - syslog's 1-second timestamp
	// resolution means several connection attempts often land on the
	// exact same second) must produce one alert covering all 10, not
	// two 5-attempt alerts.
	cfg := Config{Threshold: 5, Window: 60 * time.Second}
	var events []parser.AuthFailureEvent
	for i := 0; i < 10; i++ {
		events = append(events, ev("10.0.0.1", "root", at(0)))
	}

	alerts := Detect(events, cfg)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1: %+v", len(alerts), alerts)
	}
	if alerts[0].Attempts != 10 {
		t.Errorf("Attempts = %d, want 10", alerts[0].Attempts)
	}
}

func TestDetect_NoEvents(t *testing.T) {
	alerts := Detect(nil, DefaultConfig)
	if len(alerts) != 0 {
		t.Fatalf("got %d alerts, want 0", len(alerts))
	}
}
