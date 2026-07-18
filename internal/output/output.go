// Package output renders detected alerts as JSON or a human-readable
// ASCII table.
package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tahovig/poc-logids/internal/detector"
)

// ToJSON renders alerts as indented JSON. A nil/empty slice renders
// as "[]", not "null", so consumers don't need to special-case it.
func ToJSON(alerts []detector.Alert) ([]byte, error) {
	if alerts == nil {
		alerts = []detector.Alert{}
	}
	return json.MarshalIndent(alerts, "", "  ")
}

// ToJSONLine renders a single alert as compact JSON, suited to
// live-tail mode where alerts arrive one at a time and each line of
// output should be independently valid JSON (composable with tools
// like jq, one alert per line).
func ToJSONLine(a detector.Alert) ([]byte, error) {
	return json.Marshal(a)
}

// ToLine renders a single alert as a one-line human-readable summary,
// suited to live-tail mode where alerts arrive one at a time rather
// than as a batch table.
func ToLine(a detector.Alert) string {
	users := "-"
	if len(a.Users) > 0 {
		users = strings.Join(a.Users, ",")
	}
	return fmt.Sprintf("[ALERT] %s  source=%s  attempts=%d  users=%s",
		a.LastSeen.Format(tableTimeLayout), a.Source, a.Attempts, users)
}

const tableTimeLayout = "Jan _2 15:04:05"

// ToTable renders alerts as a column-aligned ASCII table, sized to
// the widest value in each column.
func ToTable(alerts []detector.Alert) string {
	if len(alerts) == 0 {
		return "No brute-force activity detected.\n"
	}

	headers := []string{"SOURCE", "ATTEMPTS", "FIRST SEEN", "LAST SEEN", "USERS TRIED"}
	rows := make([][]string, 0, len(alerts))
	for _, a := range alerts {
		rows = append(rows, []string{
			a.Source,
			fmt.Sprintf("%d", a.Attempts),
			a.FirstSeen.Format(tableTimeLayout),
			a.LastSeen.Format(tableTimeLayout),
			strings.Join(a.Users, ", "),
		})
	}

	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	var b strings.Builder
	writeRow := func(cells []string) {
		for i, cell := range cells {
			fmt.Fprintf(&b, "%-*s", widths[i]+2, cell)
		}
		b.WriteByte('\n')
	}
	writeRow(headers)
	for _, row := range rows {
		writeRow(row)
	}
	return b.String()
}
