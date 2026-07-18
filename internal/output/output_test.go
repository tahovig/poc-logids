package output

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tahovig/poc-logids/internal/detector"
)

func TestToTable_Empty(t *testing.T) {
	got := ToTable(nil)
	want := "No brute-force activity detected.\n"
	if got != want {
		t.Errorf("ToTable(nil) = %q, want %q", got, want)
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
	for _, want := range []string{"SOURCE", "ATTEMPTS", "10.0.0.1", "7", "root, admin"} {
		if !strings.Contains(got, want) {
			t.Errorf("ToTable output missing %q; got:\n%s", want, got)
		}
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
