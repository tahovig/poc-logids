// Command poc-logids scans an auth-log-style file for SSH
// brute-force activity, optionally following it for new activity
// like tail -f.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/tahovig/poc-logids/internal/counterintel"
	"github.com/tahovig/poc-logids/internal/detector"
	"github.com/tahovig/poc-logids/internal/output"
	"github.com/tahovig/poc-logids/internal/parser"
	"github.com/tahovig/poc-logids/internal/tail"
)

func main() {
	filePath := flag.String("file", "", "path to an auth-log-style file to scan (required)")
	jsonOut := flag.Bool("json", false, "output alerts as JSON instead of a table")
	summary := flag.Bool("summary", false, "output alerts as a plain-English outline instead of a table -- for a reader who isn't a security analyst")
	threshold := flag.Int("threshold", detector.DefaultConfig.Threshold, "minimum failed attempts from one source to flag as brute-force")
	window := flag.Duration("window", detector.DefaultConfig.Window, "time window attempts must fall within (e.g. 60s, 5m)")
	follow := flag.Bool("follow", false, "keep watching the file for new activity after the initial scan, like tail -f")
	quietStartup := flag.Bool("quiet-startup", false, "with -follow, skip printing the initial batch scan's alerts and only report new activity going forward -- for a long-running service that may restart (crash, reboot) and shouldn't re-report the whole file's history each time")
	ctiEnabled := flag.Bool("cti", false, "enable passive threat-intel enrichment (RDAP + GeoIP) for repeat or critical-severity sources -- makes outbound HTTP calls to public registries; off by default")
	ctiThreshold := flag.Int("cti-threshold", counterintel.DefaultConfig.RepeatThreshold, "failed-auth events from the same source within -cti-window that trigger enrichment")
	ctiWindow := flag.Duration("cti-window", counterintel.DefaultConfig.RepeatWindow, "time window -cti-threshold repeats are counted within")
	ctiCooldown := flag.Duration("cti-cooldown", counterintel.DefaultConfig.Cooldown, "minimum time between repeat enrichments of the same source")
	flag.Parse()

	if *filePath == "" {
		fmt.Fprintln(os.Stderr, "error: -file is required")
		flag.Usage()
		os.Exit(1)
	}
	if *jsonOut && *summary {
		fmt.Fprintln(os.Stderr, "error: -json and -summary are mutually exclusive")
		flag.Usage()
		os.Exit(1)
	}

	cfg := detector.Config{Threshold: *threshold, Window: *window}
	ctiCfg := counterintel.Config{RepeatThreshold: *ctiThreshold, RepeatWindow: *ctiWindow, Cooldown: *ctiCooldown}
	var cti *counterintel.Tracker
	if *ctiEnabled {
		cti = counterintel.NewTracker(ctiCfg)
	}

	p := parser.NewParser()
	events, offset, err := scanFile(*filePath, p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	alerts := detector.Detect(events, cfg)
	if !*quietStartup {
		if err := printAlerts(alerts, *jsonOut, *summary); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		// Gated the same as printAlerts, and for the same reason
		// -quiet-startup exists: a restarted long-running service
		// shouldn't re-spend enrichment lookups (or reset repeat
		// history) on the same historical alerts every time it comes
		// back up. Skipping here means the Tracker's history starts
		// fresh too, consistent with -quiet-startup only caring about
		// new activity going forward.
		if cti != nil {
			runEnrichment(context.Background(), events, alerts, cti, *jsonOut)
		}
	}

	if !*follow {
		return
	}

	// Reuse the same parser (not a fresh one) so year inference
	// carries over: it depends on having seen every line since the
	// start of the file in order, and -follow continues that same
	// chronological stream rather than starting a new one.
	if err := runFollow(*filePath, offset, p, cfg, cti, *jsonOut, *summary); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// scanFile parses every failed-auth event in path using p and
// reports the byte offset it stopped at, so a subsequent live-tail
// (if any) can resume from exactly that point with no gap or overlap.
func scanFile(path string, p *parser.Parser) (events []parser.AuthFailureEvent, offset int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if evs, ok := p.ParseLine(scanner.Text()); ok {
			events = append(events, evs...)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, fmt.Errorf("reading %s: %w", path, err)
	}

	offset, err = f.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, 0, fmt.Errorf("seeking %s: %w", path, err)
	}
	return events, offset, nil
}

// runFollow watches path for new activity starting at startOffset,
// printing each alert as soon as it's detected, until interrupted.
func runFollow(path string, startOffset int64, p *parser.Parser, cfg detector.Config, cti *counterintel.Tracker, jsonOut, summary bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	lines, err := tail.Follow(ctx, path, startOffset)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Watching %s for new activity (threshold=%d, window=%s)... press Ctrl+C to stop\n",
		path, cfg.Threshold, cfg.Window)

	live := detector.NewLive(cfg)
	for line := range lines {
		if line.Err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", line.Err)
			continue
		}
		evs, ok := p.ParseLine(line.Text)
		if !ok {
			continue
		}
		for _, event := range evs {
			// Checked for every event, not just ones that end up part
			// of an alerted burst -- this is what catches a source
			// too patient to ever trip live's own Threshold.
			if cti != nil {
				if reason, ok := cti.ObserveEvent(event); ok {
					printCTI(ctx, event.Source, reason, jsonOut)
				}
			}
			alert, ok := live.Feed(event)
			if !ok {
				continue
			}
			if err := printLiveAlert(alert, jsonOut, summary); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
			}
			if cti != nil {
				if reason, ok := cti.ObserveAlert(alert); ok {
					printCTI(ctx, alert.Source, reason, jsonOut)
				}
			}
		}
	}

	fmt.Fprintln(os.Stderr, "Stopped watching.")
	return nil
}

// runEnrichment feeds events and alerts through cti in true
// chronological order (merged, not events-then-alerts), enriching
// each source that crosses the bar. The merge matters: cti's cooldown
// math is timestamp-based, not call-order-based, so processing an
// early event after a later alert (e.g. all events first, then all
// alerts) could let that alert's cooldown wrongly suppress an event
// that actually happened first. Used by the batch scan path;
// -follow's live path calls cti.ObserveEvent/ObserveAlert inline
// instead, since there events and alerts already arrive in real
// chronological order one at a time.
func runEnrichment(ctx context.Context, events []parser.AuthFailureEvent, alerts []detector.Alert, cti *counterintel.Tracker, jsonOut bool) {
	type observation struct {
		ts      time.Time
		source  string
		observe func() (counterintel.Reason, bool)
	}

	obs := make([]observation, 0, len(events)+len(alerts))
	for _, e := range events {
		obs = append(obs, observation{ts: e.Timestamp, source: e.Source, observe: func() (counterintel.Reason, bool) { return cti.ObserveEvent(e) }})
	}
	for _, a := range alerts {
		obs = append(obs, observation{ts: a.LastSeen, source: a.Source, observe: func() (counterintel.Reason, bool) { return cti.ObserveAlert(a) }})
	}
	sort.SliceStable(obs, func(i, j int) bool { return obs[i].ts.Before(obs[j].ts) })

	for _, o := range obs {
		if reason, ok := o.observe(); ok {
			printCTI(ctx, o.source, reason, jsonOut)
		}
	}
}

// printCTI enriches source and prints the result. CTI output always
// goes to stderr, never stdout: stdout is reserved for the alert
// output itself (table/JSON/summary), and enrichment is supplementary
// context about it, not part of the detection artifact.
func printCTI(ctx context.Context, source string, reason counterintel.Reason, jsonOut bool) {
	intel := counterintel.Enrich(ctx, source)
	if jsonOut {
		data, err := output.ToCTIJSONLine(intel, reason)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: cti: %v\n", err)
			return
		}
		fmt.Fprintln(os.Stderr, string(data))
		return
	}
	fmt.Fprintln(os.Stderr, output.ToCTILine(intel, reason))
}

func printAlerts(alerts []detector.Alert, jsonOut, summary bool) error {
	switch {
	case jsonOut:
		out, err := output.ToJSON(alerts)
		if err != nil {
			return err
		}
		fmt.Println(string(out))
	case summary:
		fmt.Print(output.ToSummary(alerts))
	default:
		fmt.Print(output.ToTable(alerts))
	}
	return nil
}

func printLiveAlert(a detector.Alert, jsonOut, summary bool) error {
	switch {
	case jsonOut:
		data, err := output.ToJSONLine(a)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	case summary:
		fmt.Println(output.ToSummaryLine(a))
	default:
		fmt.Println(output.ToLine(a))
	}
	return nil
}
