package detector

import (
	"testing"
	"time"
)

func TestLive_AlertsExactlyOnceAtThreshold(t *testing.T) {
	l := NewLive(Config{Threshold: 3, Window: 60 * time.Second})

	if _, ok := l.Feed(ev("10.0.0.1", "root", at(0))); ok {
		t.Fatal("alerted before threshold reached")
	}
	if _, ok := l.Feed(ev("10.0.0.1", "root", at(1))); ok {
		t.Fatal("alerted before threshold reached")
	}
	alert, ok := l.Feed(ev("10.0.0.1", "root", at(2)))
	if !ok {
		t.Fatal("expected alert on the 3rd attempt")
	}
	if alert.Attempts != 3 || alert.Source != "10.0.0.1" {
		t.Errorf("alert = %+v, want attempts=3 source=10.0.0.1", alert)
	}
	if alert.Severity != SeverityNormal {
		t.Errorf("Severity = %v, want %v (Live always fires at exactly Threshold)", alert.Severity, SeverityNormal)
	}

	// Same chain continues; must not alert again.
	if _, ok := l.Feed(ev("10.0.0.1", "root", at(3))); ok {
		t.Fatal("should not re-alert on the same chain")
	}
}

func TestLive_NewChainAfterGapCanAlertAgain(t *testing.T) {
	l := NewLive(Config{Threshold: 2, Window: 10 * time.Second})

	if _, ok := l.Feed(ev("10.0.0.1", "root", at(0))); ok {
		t.Fatal("unexpected alert")
	}
	if _, ok := l.Feed(ev("10.0.0.1", "root", at(1))); !ok {
		t.Fatal("expected alert on 2nd attempt of first chain")
	}

	// Gap exceeds window: starts a new chain.
	if _, ok := l.Feed(ev("10.0.0.1", "root", at(100))); ok {
		t.Fatal("unexpected alert on lone new-chain event")
	}
	if _, ok := l.Feed(ev("10.0.0.1", "root", at(101))); !ok {
		t.Fatal("expected a fresh alert once the new chain also reaches threshold")
	}
}

func TestLive_IndependentPerSource(t *testing.T) {
	l := NewLive(Config{Threshold: 2, Window: 60 * time.Second})

	if _, ok := l.Feed(ev("10.0.0.1", "root", at(0))); ok {
		t.Fatal("unexpected alert")
	}
	if _, ok := l.Feed(ev("10.0.0.2", "root", at(0))); ok {
		t.Fatal("unexpected alert")
	}
	if _, ok := l.Feed(ev("10.0.0.2", "root", at(1))); !ok {
		t.Fatal("expected alert for 10.0.0.2 reaching threshold")
	}
}
