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
	"syscall"

	"github.com/tahovig/poc-logids/internal/detector"
	"github.com/tahovig/poc-logids/internal/output"
	"github.com/tahovig/poc-logids/internal/parser"
	"github.com/tahovig/poc-logids/internal/tail"
)

func main() {
	filePath := flag.String("file", "", "path to an auth-log-style file to scan (required)")
	jsonOut := flag.Bool("json", false, "output alerts as JSON instead of a table")
	threshold := flag.Int("threshold", detector.DefaultConfig.Threshold, "minimum failed attempts from one source to flag as brute-force")
	window := flag.Duration("window", detector.DefaultConfig.Window, "time window attempts must fall within (e.g. 60s, 5m)")
	follow := flag.Bool("follow", false, "keep watching the file for new activity after the initial scan, like tail -f")
	flag.Parse()

	if *filePath == "" {
		fmt.Fprintln(os.Stderr, "error: -file is required")
		flag.Usage()
		os.Exit(1)
	}

	cfg := detector.Config{Threshold: *threshold, Window: *window}

	events, offset, err := scanFile(*filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := printAlerts(detector.Detect(events, cfg), *jsonOut); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if !*follow {
		return
	}

	if err := runFollow(*filePath, offset, cfg, *jsonOut); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// scanFile parses every failed-auth event in path and reports the
// byte offset it stopped at, so a subsequent live-tail (if any) can
// resume from exactly that point with no gap or overlap.
func scanFile(path string) (events []parser.AuthFailureEvent, offset int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if event, ok := parser.ParseLine(scanner.Text()); ok {
			events = append(events, event)
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
func runFollow(path string, startOffset int64, cfg detector.Config, jsonOut bool) error {
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
		event, ok := parser.ParseLine(line.Text)
		if !ok {
			continue
		}
		if alert, ok := live.Feed(event); ok {
			if err := printLiveAlert(alert, jsonOut); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
			}
		}
	}

	fmt.Fprintln(os.Stderr, "Stopped watching.")
	return nil
}

func printAlerts(alerts []detector.Alert, jsonOut bool) error {
	if jsonOut {
		out, err := output.ToJSON(alerts)
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}
	fmt.Print(output.ToTable(alerts))
	return nil
}

func printLiveAlert(a detector.Alert, jsonOut bool) error {
	if jsonOut {
		data, err := output.ToJSONLine(a)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}
	fmt.Println(output.ToLine(a))
	return nil
}
