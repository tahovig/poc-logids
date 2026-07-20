package output

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tahovig/poc-logids/internal/detector"
)

func at(seconds int) time.Time {
	base := time.Date(0, time.January, 1, 0, 0, 0, 0, time.UTC)
	return base.Add(time.Duration(seconds) * time.Second)
}

func TestToTable_Empty(t *testing.T) {
	got := ToTable(nil)
	want := "No brute-force activity detected.\n"
	if got != want {
		t.Errorf("ToTable(nil) = %q, want %q", got, want)
	}
}

func TestToJSON_EmptyRendersAsEmptyArrayNotNull(t *testing.T) {
	data, err := ToJSON(nil)
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	got := strings.TrimSpace(string(data))
	if got != "[]" {
		t.Errorf("ToJSON(nil) = %q, want %q", got, "[]")
	}
}

func TestToTable_ContainsExpectedValues(t *testing.T) {
	alerts := []detector.Alert{
		{
			Source:    "10.0.0.1",
			Attempts:  7,
			FirstSeen: time.Date(0, time.June, 14, 15, 16, 1, 0, time.UTC),
			LastSeen:  time.Date(0, time.June, 14, 15, 16, 20, 0, time.UTC),
			Users:     []string{"root", "admin"},
		},
	}

	got := ToTable(alerts)
	for _, want := range []string{"SOURCE", "ATTEMPTS", "RATE", "10.0.0.1", "7", "root, admin"} {
		if !strings.Contains(got, want) {
			t.Errorf("ToTable output missing %q; got:\n%s", want, got)
		}
	}
}

func TestRate_FloorsZeroDuration(t *testing.T) {
	// FirstSeen == LastSeen happens for real: syslog's one-second
	// timestamp resolution can put an entire fast burst in one
	// second. Must not divide by zero or produce +Inf.
	a := detector.Alert{Attempts: 10, FirstSeen: at(0), LastSeen: at(0)}
	got := rate(a)
	want := 600.0 // 10 attempts / (1s floored duration = 1/60 min)
	if got != want {
		t.Errorf("rate() = %v, want %v", got, want)
	}
}

func TestRenderTable_ColorsBySeverityOnlyWhenEnabled(t *testing.T) {
	critical := detector.Alert{Source: "critical-src", Attempts: 20, Severity: detector.SeverityCritical, FirstSeen: at(0), LastSeen: at(60)}
	normal := detector.Alert{Source: "normal-src", Attempts: 5, Severity: detector.SeverityNormal, FirstSeen: at(0), LastSeen: at(60)}
	alerts := []detector.Alert{normal, critical}

	colored := renderTable(alerts, true)
	if !strings.Contains(colored, ansiRed) {
		t.Errorf("color=true should include the critical-severity color code; got:\n%s", colored)
	}
	if !strings.Contains(colored, ansiReset) {
		t.Errorf("color=true should reset color after a colored row; got:\n%s", colored)
	}

	uncolored := renderTable(alerts, false)
	if strings.Contains(uncolored, ansiRed) || strings.Contains(uncolored, ansiReset) {
		t.Errorf("color=false must not emit any ANSI codes; got:\n%s", uncolored)
	}
}

func TestRenderTable_NormalSeverityNeverColored(t *testing.T) {
	normal := detector.Alert{Source: "normal-src", Attempts: 5, Severity: detector.SeverityNormal, FirstSeen: at(0), LastSeen: at(60)}
	got := renderTable([]detector.Alert{normal}, true)
	if strings.Contains(got, ansiRed) || strings.Contains(got, ansiYellow) {
		t.Errorf("SeverityNormal should never be colored, even with color enabled; got:\n%s", got)
	}
}

func TestRenderTable_SortedWorstFirst(t *testing.T) {
	normal := detector.Alert{Source: "normal-src", Attempts: 5, Severity: detector.SeverityNormal, FirstSeen: at(0), LastSeen: at(60)}
	warning := detector.Alert{Source: "warning-src", Attempts: 10, Severity: detector.SeverityWarning, FirstSeen: at(0), LastSeen: at(60)}
	critical := detector.Alert{Source: "critical-src", Attempts: 20, Severity: detector.SeverityCritical, FirstSeen: at(0), LastSeen: at(60)}
	// Deliberately not already worst-first, and not chronological
	// either, so the sort is what's actually under test.
	alerts := []detector.Alert{normal, critical, warning}

	got := renderTable(alerts, false)
	iCritical := strings.Index(got, "critical-src")
	iWarning := strings.Index(got, "warning-src")
	iNormal := strings.Index(got, "normal-src")
	if !(iCritical < iWarning && iWarning < iNormal) {
		t.Errorf("expected order critical, warning, normal; got:\n%s", got)
	}

	// The original slice (e.g. what ToJSON would use) must be
	// untouched -- table sorting is a display-only concern.
	if alerts[0].Source != "normal-src" || alerts[1].Source != "critical-src" || alerts[2].Source != "warning-src" {
		t.Errorf("input slice order was mutated: %+v", alerts)
	}
}

func TestRenderLine_ColorsBySeverityOnlyWhenEnabled(t *testing.T) {
	critical := detector.Alert{Source: "10.0.0.1", Attempts: 20, Severity: detector.SeverityCritical, FirstSeen: at(0), LastSeen: at(60)}

	colored := renderLine(critical, true)
	if !strings.Contains(colored, ansiRed) || !strings.Contains(colored, ansiReset) {
		t.Errorf("color=true should wrap a critical alert in color codes; got: %s", colored)
	}

	uncolored := renderLine(critical, false)
	if strings.Contains(uncolored, ansiRed) {
		t.Errorf("color=false must not emit ANSI codes; got: %s", uncolored)
	}
}

func TestToLine_ContainsExpectedValues(t *testing.T) {
	a := detector.Alert{
		Source:    "10.0.0.1",
		Attempts:  3,
		FirstSeen: time.Date(0, time.June, 14, 15, 16, 1, 0, time.UTC),
		LastSeen:  time.Date(0, time.June, 14, 15, 16, 5, 0, time.UTC),
		Users:     []string{"root", "admin"},
	}
	got := ToLine(a)
	for _, want := range []string{"[ALERT]", "10.0.0.1", "attempts=3", "root,admin"} {
		if !strings.Contains(got, want) {
			t.Errorf("ToLine output missing %q; got: %s", want, got)
		}
	}
}

func TestToLine_NoUsers(t *testing.T) {
	a := detector.Alert{Source: "10.0.0.1", Attempts: 5}
	got := ToLine(a)
	if !strings.Contains(got, "users=-") {
		t.Errorf("ToLine with no users should render users=-; got: %s", got)
	}
}

func stubResolve(names map[string]string) func([]string) map[string]string {
	return func(ips []string) map[string]string {
		got := make(map[string]string)
		for _, ip := range ips {
			if n, ok := names[ip]; ok {
				got[ip] = n
			}
		}
		return got
	}
}

func TestRenderSummary_Empty(t *testing.T) {
	got := renderSummary(nil, stubResolve(nil))
	want := "No brute-force activity detected.\n"
	if got != want {
		t.Errorf("renderSummary(nil) = %q, want %q", got, want)
	}
}

func TestRenderSummary_GroupsBySeverityAndOrdersWorstFirst(t *testing.T) {
	normal := detector.Alert{Source: "normal-src", Attempts: 5, Severity: detector.SeverityNormal, Users: []string{"user"}, FirstSeen: at(0), LastSeen: at(10)}
	warning := detector.Alert{Source: "warning-src", Attempts: 10, Severity: detector.SeverityWarning, Users: []string{"admin"}, FirstSeen: at(0), LastSeen: at(10)}
	critical := detector.Alert{Source: "critical-src", Attempts: 20, Severity: detector.SeverityCritical, Users: []string{"root"}, FirstSeen: at(0), LastSeen: at(10)}
	alerts := []detector.Alert{normal, critical, warning}

	got := renderSummary(alerts, stubResolve(nil))
	for _, want := range []string{"Severe attacks (1):", "Moderate attacks (1):", "Minor attempts (1):", "3 source(s) flagged"} {
		if !strings.Contains(got, want) {
			t.Errorf("renderSummary missing %q; got:\n%s", want, got)
		}
	}
	iCritical := strings.Index(got, "critical-src")
	iWarning := strings.Index(got, "warning-src")
	iNormal := strings.Index(got, "normal-src")
	if !(iCritical < iWarning && iWarning < iNormal) {
		t.Errorf("expected tier order critical, warning, normal; got:\n%s", got)
	}
}

func TestRenderSummary_CapsDetailAndRollsUpRemainder(t *testing.T) {
	var alerts []detector.Alert
	for i := 0; i < summaryDetailCap+3; i++ {
		alerts = append(alerts, detector.Alert{
			Source: fmt.Sprintf("10.0.0.%d", i), Attempts: 5, Severity: detector.SeverityNormal,
			Users: []string{"root"}, FirstSeen: at(0), LastSeen: at(10),
		})
	}

	got := renderSummary(alerts, stubResolve(nil))
	if !strings.Contains(got, "...and 3 more, most commonly targeting: root (3)") {
		t.Errorf("renderSummary should roll up alerts past summaryDetailCap; got:\n%s", got)
	}
	if n := strings.Count(got, "tried 5 password(s)"); n != summaryDetailCap {
		t.Errorf("expected exactly %d detailed sentences, got %d; output:\n%s", summaryDetailCap, n, got)
	}
}

func TestRenderSummary_IncludesResolvedHostname(t *testing.T) {
	alerts := []detector.Alert{{Source: "10.0.0.1", Attempts: 5, Severity: detector.SeverityNormal, FirstSeen: at(0), LastSeen: at(10)}}
	got := renderSummary(alerts, stubResolve(map[string]string{"10.0.0.1": "bad-actor.example.com"}))
	if !strings.Contains(got, "10.0.0.1 (bad-actor.example.com)") {
		t.Errorf("renderSummary should include a resolved hostname; got:\n%s", got)
	}
}

func TestRenderSummary_NoHostnameWhenUnresolved(t *testing.T) {
	alerts := []detector.Alert{{Source: "10.0.0.1", Attempts: 5, Severity: detector.SeverityNormal, FirstSeen: at(0), LastSeen: at(10)}}
	got := renderSummary(alerts, stubResolve(nil))
	if strings.Contains(got, "10.0.0.1 (") {
		t.Errorf("renderSummary should show a bare IP when unresolved; got:\n%s", got)
	}
}

func TestDescribeUsers(t *testing.T) {
	tests := []struct {
		users []string
		want  string
	}{
		{nil, ""},
		{[]string{"root"}, " against root"},
		{[]string{"root", "admin"}, " against root and admin"},
		{[]string{"root", "admin", "user"}, " against root, admin, and 1 other account(s)"},
	}
	for _, tt := range tests {
		if got := describeUsers(tt.users); got != tt.want {
			t.Errorf("describeUsers(%v) = %q, want %q", tt.users, got, tt.want)
		}
	}
}

func TestHumanDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{0, "under a second"},
		{500 * time.Millisecond, "under a second"},
		{12 * time.Second, "12 seconds"},
		{90 * time.Second, "1 minute(s)"},
	}
	for _, tt := range tests {
		if got := humanDuration(tt.d); got != tt.want {
			t.Errorf("humanDuration(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestTopUsers_TiesBreakAlphabetically(t *testing.T) {
	alerts := []detector.Alert{
		{Users: []string{"root", "admin"}},
		{Users: []string{"root"}},
	}
	got := topUsers(alerts, 3)
	want := "root (2), admin (1)"
	if got != want {
		t.Errorf("topUsers() = %q, want %q", got, want)
	}
}

func TestTopUsers_NoUsers(t *testing.T) {
	got := topUsers([]detector.Alert{{}}, 3)
	if got != "unknown accounts" {
		t.Errorf("topUsers with no users = %q, want %q", got, "unknown accounts")
	}
}

func TestSeenRange_NotAssumedSorted(t *testing.T) {
	// A burst that starts earliest doesn't necessarily end latest --
	// seenRange must scan, not just look at the first/last element.
	alerts := []detector.Alert{
		{FirstSeen: at(0), LastSeen: at(5)},
		{FirstSeen: at(1), LastSeen: at(100)},
	}
	first, last := seenRange(alerts)
	if !first.Equal(at(0)) || !last.Equal(at(100)) {
		t.Errorf("seenRange() = (%v, %v), want (%v, %v)", first, last, at(0), at(100))
	}
}

func TestResolveHostnames_UsesStubAndSkipsFailures(t *testing.T) {
	orig := lookupAddr
	defer func() { lookupAddr = orig }()
	lookupAddr = func(ctx context.Context, addr string) ([]string, error) {
		if addr == "10.0.0.1" {
			return []string{"resolved.example.com."}, nil
		}
		return nil, errors.New("no PTR record")
	}

	got := resolveHostnames([]string{"10.0.0.1", "10.0.0.2"})
	if got["10.0.0.1"] != "resolved.example.com" {
		t.Errorf("expected trailing dot trimmed, got %q", got["10.0.0.1"])
	}
	if _, ok := got["10.0.0.2"]; ok {
		t.Errorf("a lookup error should be omitted from the result, not zero-valued; got %v", got)
	}
}

func TestToSummaryLine_UsesStubResolver(t *testing.T) {
	orig := lookupAddr
	defer func() { lookupAddr = orig }()
	lookupAddr = func(ctx context.Context, addr string) ([]string, error) {
		return []string{"scanner.example.com"}, nil
	}

	a := detector.Alert{Source: "10.0.0.1", Attempts: 5, Users: []string{"root"}, FirstSeen: at(0), LastSeen: at(10)}
	got := ToSummaryLine(a)
	if !strings.Contains(got, "10.0.0.1 (scanner.example.com)") || !strings.Contains(got, "tried 5 password(s) against root") {
		t.Errorf("ToSummaryLine() = %q", got)
	}
}

func TestToJSONLine_RoundTrips(t *testing.T) {
	a := detector.Alert{
		Source:    "10.0.0.1",
		Attempts:  4,
		FirstSeen: time.Date(0, time.June, 14, 15, 16, 1, 0, time.UTC),
		LastSeen:  time.Date(0, time.June, 14, 15, 16, 5, 0, time.UTC),
		Users:     []string{"root"},
	}
	data, err := ToJSONLine(a)
	if err != nil {
		t.Fatalf("ToJSONLine: %v", err)
	}
	var got detector.Alert
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Source != a.Source || got.Attempts != a.Attempts {
		t.Errorf("round-tripped alert = %+v, want match for input %+v", got, a)
	}
}

func TestToJSON_RoundTrips(t *testing.T) {
	alerts := []detector.Alert{
		{
			Source:    "10.0.0.1",
			Attempts:  5,
			FirstSeen: time.Date(0, time.June, 14, 15, 16, 1, 0, time.UTC),
			LastSeen:  time.Date(0, time.June, 14, 15, 16, 20, 0, time.UTC),
			Users:     []string{"root"},
		},
	}

	data, err := ToJSON(alerts)
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}

	var got []detector.Alert
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got) != 1 || got[0].Source != "10.0.0.1" || got[0].Attempts != 5 {
		t.Errorf("round-tripped alerts = %+v, want match for input %+v", got, alerts)
	}
}
