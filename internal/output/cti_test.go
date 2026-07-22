package output

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tahovig/poc-logids/internal/counterintel"
)

func TestToCTILine_IncludesPopulatedFieldsOnly(t *testing.T) {
	intel := counterintel.Intel{IP: "1.2.3.4", Org: "EXAMPLE-NET", Country: "Netherlands", City: "Amsterdam"}
	line := ToCTILine(intel, counterintel.ReasonRepeat)

	for _, want := range []string{"source=1.2.3.4", `org="EXAMPLE-NET"`, `location="Amsterdam, Netherlands"`, "trigger=repeat_offender"} {
		if !strings.Contains(line, want) {
			t.Errorf("ToCTILine() = %q, missing %q", line, want)
		}
	}
	if strings.Contains(line, "asn=") || strings.Contains(line, "network=") {
		t.Errorf("ToCTILine() = %q, unexpected fields for unset data", line)
	}
}

func TestToCTIJSONLine_TaggedAsCTI(t *testing.T) {
	data, err := ToCTIJSONLine(counterintel.Intel{IP: "1.2.3.4"}, counterintel.ReasonSeverity)
	if err != nil {
		t.Fatalf("ToCTIJSONLine() error = %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("output isn't valid JSON: %v", err)
	}
	if parsed["type"] != "cti" {
		t.Errorf(`parsed["type"] = %v, want "cti"`, parsed["type"])
	}
	if parsed["trigger"] != "critical_severity" {
		t.Errorf(`parsed["trigger"] = %v, want "critical_severity"`, parsed["trigger"])
	}
	if parsed["ip"] != "1.2.3.4" {
		t.Errorf(`parsed["ip"] = %v, want "1.2.3.4"`, parsed["ip"])
	}
}
