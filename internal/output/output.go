// Package output renders detected alerts as JSON or a human-readable
// ASCII table.
package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tahovig/poc-logids/internal/detector"
)

// ToJSON renders alerts as indented JSON.
func ToJSON(alerts []detector.Alert) ([]byte, error) {
	return json.MarshalIndent(alerts, "", "  ")
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
