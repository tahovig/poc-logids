package output

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tahovig/poc-logids/internal/detector"
)

func TestToStats_Empty(t *testing.T) {
	got := ToStats(nil)
	want := "No brute-force activity detected.\n"
	if got != want {
		t.Errorf("ToStats(nil) = %q, want %q", got, want)
	}
}

func TestHistogramBuckets_GroupsByAutoSelectedGranularity(t *testing.T) {
	mk := func(y int, month time.Month, day, hour int) detector.Alert {
		ts := time.Date(y, month, day, hour, 0, 0, 0, time.UTC)
		return detector.Alert{Source: "x", Attempts: 5, FirstSeen: ts, LastSeen: ts}
	}
	alerts := []detector.Alert{
		mk(0, time.July, 20, 10),
		mk(0, time.July, 20, 14),
		mk(0, time.July, 21, 9),
		mk(0, time.July, 22, 1),
		mk(0, time.July, 22, 12),
		mk(0, time.July, 22, 23),
	}

	got := histogramBuckets(alerts)

	want := []struct {
		label string
		count int
	}{
		{"Jul 20", 2},
		{"Jul 21", 1},
		{"Jul 22", 3},
	}
	if len(got) != len(want) {
		t.Fatalf("histogramBuckets returned %d buckets, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].label != w.label || got[i].count != w.count {
			t.Errorf("bucket %d = {%q, %d}, want {%q, %d}", i, got[i].label, got[i].count, w.label, w.count)
		}
	}
}

func TestSeverityCounts_TalliesByTier(t *testing.T) {
	alerts := []detector.Alert{
		{Source: "a", Severity: detector.SeverityCritical},
		{Source: "b", Severity: detector.SeverityCritical},
		{Source: "c", Severity: detector.SeverityWarning},
		{Source: "d", Severity: detector.SeverityNormal},
		{Source: "e", Severity: detector.SeverityNormal},
		{Source: "f", Severity: detector.SeverityNormal},
	}

	got := severityCounts(alerts)

	want := map[detector.Severity]int{
		detector.SeverityCritical: 2,
		detector.SeverityWarning:  1,
		detector.SeverityNormal:   3,
	}
	for sev, want := range want {
		if got[sev] != want {
			t.Errorf("severityCounts[%v] = %d, want %d", sev, got[sev], want)
		}
	}
}

func TestBar_ScalesToMaxWidth(t *testing.T) {
	tests := []struct {
		name       string
		count, max int
		width      int
		wantLen    int
	}{
		{"zero count is empty", 0, 10, 40, 0},
		{"count equals max fills the width", 10, 10, 40, 40},
		{"half of max is half the width", 5, 10, 40, 20},
		{"tiny fraction still gets a minimum of one char", 1, 100, 40, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bar(tt.count, tt.max, tt.width)
			if len([]rune(got)) != tt.wantLen {
				t.Errorf("bar(%d, %d, %d) = %q (len %d), want len %d", tt.count, tt.max, tt.width, got, len([]rune(got)), tt.wantLen)
			}
		})
	}
}

func TestTopOffenders_CapsAndReportsRemainder(t *testing.T) {
	alerts := make([]detector.Alert, 12)
	for i := range alerts {
		alerts[i] = detector.Alert{
			Source:   fmt.Sprintf("10.0.0.%d", i),
			Attempts: 12 - i, // descending, so index order already matches worst-first
			Severity: detector.SeverityNormal,
		}
	}

	top, remaining := topOffenders(alerts, 10)

	if len(top) != 10 {
		t.Fatalf("topOffenders returned %d entries, want 10", len(top))
	}
	if remaining != 2 {
		t.Errorf("remaining = %d, want 2", remaining)
	}
	if top[0].Source != "10.0.0.0" || top[9].Source != "10.0.0.9" {
		t.Errorf("top offenders not in worst-first order: %+v", top)
	}
}

func TestTopOffenders_UnderCapReturnsAllWithZeroRemainder(t *testing.T) {
	alerts := []detector.Alert{
		{Source: "a", Attempts: 5},
		{Source: "b", Attempts: 3},
	}

	top, remaining := topOffenders(alerts, 10)

	if len(top) != 2 || remaining != 0 {
		t.Errorf("topOffenders(2 alerts, cap 10) = (%d entries, remaining %d), want (2, 0)", len(top), remaining)
	}
}

func TestRenderStats_HeaderTotalsAndSeverityBreakdown(t *testing.T) {
	alerts := []detector.Alert{
		{Source: "45.148.10.152", Attempts: 80, Severity: detector.SeverityCritical,
			FirstSeen: time.Date(0, time.June, 14, 15, 16, 0, 0, time.UTC), LastSeen: time.Date(0, time.June, 14, 15, 16, 20, 0, time.UTC), Users: []string{"root"}},
		{Source: "45.148.10.157", Attempts: 20, Severity: detector.SeverityWarning,
			FirstSeen: time.Date(0, time.June, 14, 15, 17, 0, 0, time.UTC), LastSeen: time.Date(0, time.June, 14, 15, 17, 10, 0, time.UTC), Users: []string{"root", "admin"}},
		{Source: "10.0.0.5", Attempts: 5, Severity: detector.SeverityNormal,
			FirstSeen: time.Date(0, time.June, 15, 9, 0, 0, 0, time.UTC), LastSeen: time.Date(0, time.June, 15, 9, 0, 5, 0, time.UTC), Users: []string{"root"}},
	}

	got := renderStats(alerts, false)

	for _, want := range []string{
		"3 alerts", "3 sources", "105 attempts",
		"critical", "warning", "normal",
		"ACTIVITY",
		"TOP OFFENDERS",
		"45.148.10.152", "80 attempts",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("renderStats output missing %q; got:\n%s", want, got)
		}
	}

	iCritical := strings.Index(got, "45.148.10.152")
	iWarning := strings.Index(got, "45.148.10.157")
	iNormal := strings.Index(got, "10.0.0.5")
	if !(iCritical < iWarning && iWarning < iNormal) {
		t.Errorf("top offenders not worst-first; got:\n%s", got)
	}

	if strings.Contains(got, "...and") {
		t.Errorf("only 3 alerts (under statsTopN) should not produce a rollup line; got:\n%s", got)
	}
}

func TestRenderStats_TopOffendersRollupPastCap(t *testing.T) {
	alerts := make([]detector.Alert, statsTopN+3)
	for i := range alerts {
		alerts[i] = detector.Alert{
			Source:    fmt.Sprintf("10.0.0.%d", i),
			Attempts:  100 - i,
			Severity:  detector.SeverityNormal,
			FirstSeen: at(0),
			LastSeen:  at(60),
		}
	}

	got := renderStats(alerts, false)

	if !strings.Contains(got, "...and 3 more sources") {
		t.Errorf("expected rollup line for the 3 sources past statsTopN; got:\n%s", got)
	}
}

func TestRenderStats_ColorsBySeverityOnlyWhenEnabled(t *testing.T) {
	critical := detector.Alert{Source: "critical-src", Attempts: 20, Severity: detector.SeverityCritical, FirstSeen: at(0), LastSeen: at(60)}
	normal := detector.Alert{Source: "normal-src", Attempts: 5, Severity: detector.SeverityNormal, FirstSeen: at(0), LastSeen: at(60)}
	alerts := []detector.Alert{normal, critical}

	colored := renderStats(alerts, true)
	if !strings.Contains(colored, ansiRed) {
		t.Errorf("color=true should include the critical-severity color code; got:\n%s", colored)
	}

	uncolored := renderStats(alerts, false)
	if strings.Contains(uncolored, ansiRed) || strings.Contains(uncolored, ansiReset) {
		t.Errorf("color=false must not emit any ANSI codes; got:\n%s", uncolored)
	}
}

func TestPickBucketDuration_ChoosesFinestGranularityUnderTargetBuckets(t *testing.T) {
	tests := []struct {
		name string
		span time.Duration
		want time.Duration
	}{
		{"short span picks hour", 30 * time.Minute, time.Hour},
		{"~9 day span picks day", 9 * 24 * time.Hour, 24 * time.Hour},
		{"~6 week span picks week", 42 * 24 * time.Hour, 7 * 24 * time.Hour},
		{"~264 day span (real full loghub dataset) picks month", 264 * 24 * time.Hour, 30 * 24 * time.Hour},
		{"span beyond largest tier scales the coarsest unit up further", 1000 * 24 * time.Hour, 60 * 24 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pickBucketDuration(tt.span)
			if got != tt.want {
				t.Errorf("pickBucketDuration(%v) = %v, want %v", tt.span, got, tt.want)
			}
		})
	}
}
