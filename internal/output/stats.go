package output

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tahovig/poc-logids/internal/detector"
)

// statsTargetBuckets bounds how many rows the activity histogram
// renders, regardless of how long a dataset's time span is -- a
// 6-week pull and a 264-day pull (the full loghub dataset) both stay
// readable on one screen.
const statsTargetBuckets = 20

// statsBucketUnits are tried finest-first; pickBucketDuration returns
// the first one whose bucket count fits under statsTargetBuckets.
var statsBucketUnits = []time.Duration{
	time.Hour,
	24 * time.Hour,
	7 * 24 * time.Hour,
	30 * 24 * time.Hour,
}

// pickBucketDuration chooses the finest bucket granularity that keeps
// the histogram under statsTargetBuckets rows. If even the coarsest
// unit doesn't fit (a dataset spanning years), it scales that unit up
// further rather than rendering an unbounded number of rows.
func pickBucketDuration(span time.Duration) time.Duration {
	if span <= 0 {
		return time.Hour
	}
	for _, unit := range statsBucketUnits {
		if int64(span/unit) <= statsTargetBuckets {
			return unit
		}
	}
	coarsest := statsBucketUnits[len(statsBucketUnits)-1]
	factor := int64(span / (coarsest * statsTargetBuckets))
	return coarsest * time.Duration(factor+1)
}

// statsBucket is one row of the activity-over-time histogram.
type statsBucket struct {
	start time.Time
	label string
	count int
}

// bucketLabel renders a bucket's start time; sub-day granularities
// include the time of day, day-or-coarser granularities don't, since
// the date alone is the meaningful unit at that resolution.
func bucketLabel(t time.Time, unit time.Duration) string {
	if unit < 24*time.Hour {
		return t.Format("Jan _2 15:04")
	}
	return t.Format("Jan _2")
}

// histogramBuckets groups alerts by FirstSeen into buckets sized by
// pickBucketDuration, so the number of rows stays bounded regardless
// of how long a dataset's time span is. Returned in chronological
// order.
func histogramBuckets(alerts []detector.Alert) []statsBucket {
	first, last := seenRange(alerts)
	unit := pickBucketDuration(last.Sub(first))

	counts := make(map[time.Time]int)
	for _, a := range alerts {
		counts[a.FirstSeen.Truncate(unit)]++
	}

	keys := make([]time.Time, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Before(keys[j]) })

	buckets := make([]statsBucket, len(keys))
	for i, k := range keys {
		buckets[i] = statsBucket{start: k, label: bucketLabel(k, unit), count: counts[k]}
	}
	return buckets
}

// bar renders a block-character bar scaled to width, proportional to
// count/max. A nonzero count always renders at least one character,
// even if the proportional length would round down to zero -- a
// present-but-tiny bar should still be visible, not indistinguishable
// from zero.
func bar(count, max, width int) string {
	if count <= 0 || max <= 0 {
		return ""
	}
	length := count * width / max
	if length < 1 {
		length = 1
	}
	return strings.Repeat("█", length)
}

// statsTopN bounds how many sources get a detailed row in the top
// offenders section before the rest collapse into a single "...and N
// more sources" line -- same rollup discipline as tableUsersCap and
// summaryDetailCap elsewhere in this package.
const statsTopN = 10

// topOffenders returns the top n alerts worst-first (same ordering as
// ToTable) plus a count of how many were left out.
func topOffenders(alerts []detector.Alert, n int) (top []detector.Alert, remaining int) {
	sorted := sortedForDisplay(alerts)
	if len(sorted) <= n {
		return sorted, 0
	}
	return sorted[:n], len(sorted) - n
}

// severityCounts tallies alerts per severity tier.
func severityCounts(alerts []detector.Alert) map[detector.Severity]int {
	counts := make(map[detector.Severity]int, len(summaryTierOrder))
	for _, a := range alerts {
		counts[a.Severity]++
	}
	return counts
}

// ToStats renders alerts as a fixed-size aggregate view (severity
// distribution, activity-over-time histogram, top offenders) rather
// than enumerating every alert -- so a 5-alert pull and a 500-alert
// pull both render as a single glanceable screen.
func ToStats(alerts []detector.Alert) string {
	return renderStats(alerts, isTerminal(os.Stdout))
}

// statsBarWidth is the max rendered width of a bar in the severity
// and activity sections.
const statsBarWidth = 40

func renderStats(alerts []detector.Alert, color bool) string {
	if len(alerts) == 0 {
		return "No brute-force activity detected.\n"
	}

	var b strings.Builder
	writeStatsHeader(&b, alerts)
	writeStatsSeverity(&b, alerts, color)
	writeStatsActivity(&b, alerts)
	writeStatsTopOffenders(&b, alerts, color)
	return b.String()
}

func writeStatsHeader(b *strings.Builder, alerts []detector.Alert) {
	sources := make(map[string]struct{}, len(alerts))
	totalAttempts := 0
	for _, a := range alerts {
		sources[a.Source] = struct{}{}
		totalAttempts += a.Attempts
	}
	first, last := seenRange(alerts)
	fmt.Fprintf(b, "=== %d alerts, %d sources, %d attempts | %s - %s ===\n\n",
		len(alerts), len(sources), totalAttempts, first.Format(tableTimeLayout), last.Format(tableTimeLayout))
}

func writeStatsSeverity(b *strings.Builder, alerts []detector.Alert, color bool) {
	counts := severityCounts(alerts)
	max := 0
	for _, tier := range summaryTierOrder {
		if counts[tier] > max {
			max = counts[tier]
		}
	}

	b.WriteString("SEVERITY\n")
	for _, tier := range summaryTierOrder {
		count := counts[tier]
		pct := 0
		if len(alerts) > 0 {
			pct = count * 100 / len(alerts)
		}
		line := fmt.Sprintf("  %-8s %-*s %4d (%3d%%)\n", string(tier), statsBarWidth, bar(count, max, statsBarWidth), count, pct)
		if c := severityColor(tier, color); c != "" && count > 0 {
			b.WriteString(c)
			b.WriteString(strings.TrimSuffix(line, "\n"))
			b.WriteString(ansiReset)
			b.WriteByte('\n')
		} else {
			b.WriteString(line)
		}
	}
	b.WriteByte('\n')
}

func writeStatsActivity(b *strings.Builder, alerts []detector.Alert) {
	buckets := histogramBuckets(alerts)
	max := 0
	for _, bkt := range buckets {
		if bkt.count > max {
			max = bkt.count
		}
	}

	unit := "hour"
	if len(buckets) > 1 {
		unit = unitLabel(buckets[1].start.Sub(buckets[0].start))
	} else if len(alerts) > 0 {
		first, last := seenRange(alerts)
		unit = unitLabel(pickBucketDuration(last.Sub(first)))
	}

	fmt.Fprintf(b, "ACTIVITY (by %s)\n", unit)
	for _, bkt := range buckets {
		fmt.Fprintf(b, "  %-14s %-*s %d\n", bkt.label, statsBarWidth, bar(bkt.count, max, statsBarWidth), bkt.count)
	}
	b.WriteByte('\n')
}

func writeStatsTopOffenders(b *strings.Builder, alerts []detector.Alert, color bool) {
	top, remaining := topOffenders(alerts, statsTopN)

	b.WriteString("TOP OFFENDERS\n")
	for i, a := range top {
		users := "-"
		if len(a.Users) > 0 {
			users = capUsers(a.Users, ", ")
		}
		line := fmt.Sprintf("  %2d. %-15s %5d attempts  %-8s %s\n", i+1, a.Source, a.Attempts, string(a.Severity), users)
		if c := severityColor(a.Severity, color); c != "" {
			b.WriteString(c)
			b.WriteString(strings.TrimSuffix(line, "\n"))
			b.WriteString(ansiReset)
			b.WriteByte('\n')
		} else {
			b.WriteString(line)
		}
	}
	if remaining > 0 {
		fmt.Fprintf(b, "  ...and %d more sources\n", remaining)
	}
}

// unitLabel names a bucket duration for the ACTIVITY section header.
func unitLabel(unit time.Duration) string {
	switch {
	case unit < 24*time.Hour:
		return "hour"
	case unit < 7*24*time.Hour:
		return "day"
	case unit < 30*24*time.Hour:
		return "week"
	default:
		return "month"
	}
}
