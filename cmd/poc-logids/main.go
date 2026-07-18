// Command poc-logids scans an auth-log-style file for SSH
// brute-force activity.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	"github.com/tahovig/poc-logids/internal/detector"
	"github.com/tahovig/poc-logids/internal/output"
	"github.com/tahovig/poc-logids/internal/parser"
)

func main() {
	filePath := flag.String("file", "", "path to an auth-log-style file to scan (required)")
	jsonOut := flag.Bool("json", false, "output alerts as JSON instead of a table")
	threshold := flag.Int("threshold", detector.DefaultConfig.Threshold, "minimum failed attempts from one source to flag as brute-force")
	window := flag.Duration("window", detector.DefaultConfig.Window, "time window attempts must fall within (e.g. 60s, 5m)")
	flag.Parse()

	if *filePath == "" {
		fmt.Fprintln(os.Stderr, "error: -file is required")
		flag.Usage()
		os.Exit(1)
	}

	events, err := scanFile(*filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	alerts := detector.Detect(events, detector.Config{Threshold: *threshold, Window: *window})

	if *jsonOut {
		out, err := output.ToJSON(alerts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(out))
		return
	}
	fmt.Print(output.ToTable(alerts))
}

func scanFile(path string) ([]parser.AuthFailureEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	var events []parser.AuthFailureEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if event, ok := parser.ParseLine(scanner.Text()); ok {
			events = append(events, event)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return events, nil
}
