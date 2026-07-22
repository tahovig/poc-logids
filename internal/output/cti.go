package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tahovig/poc-logids/internal/counterintel"
)

// ToCTILine renders a passive-intel enrichment result as a one-line
// human-readable note, mirroring ToLine's shape for alerts. Fields
// with no data (a registry that didn't answer) are simply omitted
// rather than shown empty.
func ToCTILine(intel counterintel.Intel, reason counterintel.Reason) string {
	parts := []string{fmt.Sprintf("[CTI] source=%s", intel.IP)}
	if intel.Org != "" {
		parts = append(parts, fmt.Sprintf("org=%q", intel.Org))
	}
	if loc := ctiLocation(intel); loc != "" {
		parts = append(parts, fmt.Sprintf("location=%q", loc))
	}
	if intel.ASN != "" {
		parts = append(parts, fmt.Sprintf("asn=%q", intel.ASN))
	}
	if intel.Network != "" {
		parts = append(parts, fmt.Sprintf("network=%q", intel.Network))
	}
	parts = append(parts, fmt.Sprintf("trigger=%s", reason))
	return strings.Join(parts, " ")
}

func ctiLocation(intel counterintel.Intel) string {
	switch {
	case intel.City != "" && intel.Country != "":
		return intel.City + ", " + intel.Country
	case intel.Country != "":
		return intel.Country
	default:
		return ""
	}
}

// ctiJSONLine tags a CTI result with its trigger reason and a type
// discriminator, so a consumer piping -follow -json through jq can
// tell CTI lines apart from alert lines in the same stream (e.g.
// `select(.type == "cti")`).
type ctiJSONLine struct {
	Type   string              `json:"type"`
	Reason counterintel.Reason `json:"trigger"`
	counterintel.Intel
}

// ToCTIJSONLine renders a CTI result as a single compact JSON object.
func ToCTIJSONLine(intel counterintel.Intel, reason counterintel.Reason) ([]byte, error) {
	return json.Marshal(ctiJSONLine{Type: "cti", Reason: reason, Intel: intel})
}
