package parser

import (
	"testing"
	"time"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		wantOK     bool
		wantSource string
		wantUser   string
		wantTS     string // parsed with syslogTimeLayout, empty if wantOK is false
	}{
		{
			name:       "pam_unix, rhost only, real loghub sample",
			line:       "Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4 ",
			wantOK:     true,
			wantSource: "218.188.2.4",
			wantUser:   "",
			wantTS:     "Jun 14 15:16:01",
		},
		{
			name:       "pam_unix, hostname rhost with user=, real loghub sample",
			line:       "Jun 15 02:04:59 combo sshd(pam_unix)[20882]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root",
			wantOK:     true,
			wantSource: "220-135-151-1.hinet-ip.hinet.net",
			wantUser:   "root",
			wantTS:     "Jun 15 02:04:59",
		},
		{
			name:       "openssh, invalid user, single-digit day",
			line:       "Jan  2 03:04:05 host sshd[1234]: Failed password for invalid user bob from 10.0.0.5 port 51234 ssh2",
			wantOK:     true,
			wantSource: "10.0.0.5",
			wantUser:   "bob",
			wantTS:     "Jan  2 03:04:05",
		},
		{
			name:       "openssh, known user",
			line:       "Jun 20 11:22:33 host sshd[5678]: Failed password for root from 10.0.0.6 port 51235 ssh2",
			wantOK:     true,
			wantSource: "10.0.0.6",
			wantUser:   "root",
			wantTS:     "Jun 20 11:22:33",
		},
		{
			name:   "pam_unix precursor line has no rhost, correctly ignored to avoid double counting",
			line:   "Jun 15 12:12:34 combo sshd(pam_unix)[23397]: check pass; user unknown",
			wantOK: false,
		},
		{
			name:   "unrelated session line",
			line:   "Jun 15 04:06:18 combo su(pam_unix)[21416]: session opened for user cyrus by (uid=0)",
			wantOK: false,
		},
		{
			name:   "unrelated logrotate line",
			line:   "Jun 15 04:06:20 combo logrotate: ALERT exited abnormally with [1]",
			wantOK: false,
		},
		{
			name:   "empty line",
			line:   "",
			wantOK: false,
		},
		{
			// sshd logs whatever username a client sends, unsanitized
			// -- constructed here to demonstrate a hostile client
			// appending an ANSI cursor-down escape sequence (ESC [ 8
			// B) to a "username" specifically to corrupt a
			// terminal-based log viewer (real usernames never contain
			// control bytes). Only the ESC byte itself is a control
			// character -- sanitizeField strips it, which neutralizes
			// the escape sequence (a terminal only recognizes CSI
			// sequences by their leading ESC), but the remaining
			// printable "[8B" is left behind as inert text; the goal
			// is preventing execution, not full cosmetic cleanup.
			// Raw (checked below) still keeps the original bytes
			// intact.
			name:       "openssh, control bytes in username stripped",
			line:       "Jun 20 11:22:33 host sshd[5678]: Failed password for invalid user root\x1b[8B from 10.0.0.6 port 51235 ssh2",
			wantOK:     true,
			wantSource: "10.0.0.6",
			wantUser:   "root[8B",
			wantTS:     "Jun 20 11:22:33",
		},
		{
			// A more directly disruptive payload: repeated vertical-
			// tab bytes (each moves the cursor down a line in most
			// terminals), no CSI structure needed -- this is the
			// shape that would produce exactly the large blank
			// vertical gaps seen against real honeypot data. Every
			// byte here is a control byte, so sanitizeField removes
			// the whole thing, leaving a clean username.
			name:       "openssh, repeated vertical-tab bytes fully stripped",
			line:       "Jun 20 11:22:34 host sshd[5679]: Failed password for root\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b from 10.0.0.7 port 51236 ssh2",
			wantOK:     true,
			wantSource: "10.0.0.7",
			wantUser:   "root",
			wantTS:     "Jun 20 11:22:34",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events, ok := NewParser().ParseLine(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("ParseLine(%q) ok = %v, want %v", tt.line, ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if len(events) != 1 {
				t.Fatalf("ParseLine(%q) = %d events, want 1", tt.line, len(events))
			}
			event := events[0]
			if event.Source != tt.wantSource {
				t.Errorf("Source = %q, want %q", event.Source, tt.wantSource)
			}
			if event.User != tt.wantUser {
				t.Errorf("User = %q, want %q", event.User, tt.wantUser)
			}
			wantTS, err := time.Parse(syslogTimeLayout, tt.wantTS)
			if err != nil {
				t.Fatalf("test setup: bad wantTS %q: %v", tt.wantTS, err)
			}
			if !event.Timestamp.Equal(wantTS) {
				t.Errorf("Timestamp = %v, want %v", event.Timestamp, wantTS)
			}
			if event.Raw != tt.line {
				t.Errorf("Raw = %q, want %q", event.Raw, tt.line)
			}
		})
	}
}

func TestParseLine_MessageRepeated_ExpandsToNEvents(t *testing.T) {
	// Real line captured from the honeypot droplet, 2026-07-20: rsyslog
	// collapsed 4 of 5 real "Failed password" attempts in one
	// connection into this single summary line.
	line := "Jul 20 23:13:59 poc-logids-honeypot sshd[31120]: message repeated 4 times: [ Failed password for root from 45.148.10.152 port 40498 ssh2]"

	events, ok := NewParser().ParseLine(line)
	if !ok {
		t.Fatalf("ParseLine(%q) ok = false, want true", line)
	}
	if len(events) != 4 {
		t.Fatalf("ParseLine(%q) = %d events, want 4", line, len(events))
	}
	wantTS, _ := time.Parse(syslogTimeLayout, "Jul 20 23:13:59")
	for i, e := range events {
		if e.Source != "45.148.10.152" {
			t.Errorf("events[%d].Source = %q, want %q", i, e.Source, "45.148.10.152")
		}
		if e.User != "root" {
			t.Errorf("events[%d].User = %q, want %q", i, e.User, "root")
		}
		if !e.Timestamp.Equal(wantTS) {
			t.Errorf("events[%d].Timestamp = %v, want %v", i, e.Timestamp, wantTS)
		}
		if e.Raw != line {
			t.Errorf("events[%d].Raw = %q, want %q", i, e.Raw, line)
		}
	}
}

func TestParseLine_MessageRepeated_PamUnixBody(t *testing.T) {
	line := "Jun 15 02:04:59 combo sshd(pam_unix)[20882]: message repeated 2 times: [ authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4  user=root]"

	events, ok := NewParser().ParseLine(line)
	if !ok {
		t.Fatalf("ParseLine(%q) ok = false, want true", line)
	}
	if len(events) != 2 {
		t.Fatalf("ParseLine(%q) = %d events, want 2", line, len(events))
	}
	for i, e := range events {
		if e.Source != "218.188.2.4" || e.User != "root" {
			t.Errorf("events[%d] = {Source: %q, User: %q}, want {%q, %q}", i, e.Source, e.User, "218.188.2.4", "root")
		}
	}
}

func TestParseLine_MessageRepeated_UnrecognizedInnerBody(t *testing.T) {
	// A repeated line wrapping a message this parser doesn't otherwise
	// recognize must be ignored, not guessed at.
	line := "Jul 20 23:10:00 host sshd[1]: message repeated 3 times: [ Invalid user admin from 1.2.3.4 port 22 ]"
	if events, ok := NewParser().ParseLine(line); ok {
		t.Errorf("ParseLine(%q) = %v, true; want ok=false for an unrecognized inner message", line, events)
	}
}

func TestParseLine_MessageRepeated_ZeroCountIgnored(t *testing.T) {
	line := "Jul 20 23:10:00 host sshd[1]: message repeated 0 times: [ Failed password for root from 1.2.3.4 port 22 ssh2]"
	if events, ok := NewParser().ParseLine(line); ok {
		t.Errorf("ParseLine(%q) = %v, true; want ok=false for a zero repeat count", line, events)
	}
}

func TestParser_YearIncrementsOnDecToJanWrap(t *testing.T) {
	p := NewParser()
	lines := []string{
		"Dec 30 23:58:00 combo sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
		"Dec 31 23:59:58 combo sshd[2]: Failed password for root from 1.2.3.4 port 22 ssh2",
		"Jan  1 00:00:02 combo sshd[3]: Failed password for root from 1.2.3.4 port 22 ssh2",
		"Jan  2 08:00:00 combo sshd[4]: Failed password for root from 1.2.3.4 port 22 ssh2",
	}

	var events []AuthFailureEvent
	for _, line := range lines {
		es, ok := p.ParseLine(line)
		if !ok {
			t.Fatalf("ParseLine(%q) unexpectedly failed to match", line)
		}
		events = append(events, es[0])
	}

	if events[0].Timestamp.Year() != events[1].Timestamp.Year() {
		t.Errorf("Dec 30 and Dec 31 should share a year, got %d and %d",
			events[0].Timestamp.Year(), events[1].Timestamp.Year())
	}
	if events[2].Timestamp.Year() != events[0].Timestamp.Year()+1 {
		t.Errorf("Jan 1 should be one year after Dec 30/31, got Dec=%d Jan=%d",
			events[0].Timestamp.Year(), events[2].Timestamp.Year())
	}
	if events[3].Timestamp.Year() != events[2].Timestamp.Year() {
		t.Errorf("Jan 1 and Jan 2 should share a year, got %d and %d",
			events[2].Timestamp.Year(), events[3].Timestamp.Year())
	}

	// The real point of year inference: the gap across the wrap must
	// come out as ~4 seconds (23:59:58 -> 00:00:02), not ~-364 days.
	gap := events[2].Timestamp.Sub(events[1].Timestamp)
	if gap != 4*time.Second {
		t.Errorf("gap across the year wrap = %v, want 4s", gap)
	}

	// And the full sequence must be strictly increasing, so sorting
	// and windowed chaining work correctly across the boundary.
	for i := 1; i < len(events); i++ {
		if !events[i].Timestamp.After(events[i-1].Timestamp) {
			t.Errorf("events[%d] (%v) not after events[%d] (%v)",
				i, events[i].Timestamp, i-1, events[i-1].Timestamp)
		}
	}
}

func TestParser_NoWrapWithinSameYear(t *testing.T) {
	p := NewParser()
	lines := []string{
		"Jan  5 00:00:00 combo sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
		"Jun 15 00:00:00 combo sshd[2]: Failed password for root from 1.2.3.4 port 22 ssh2",
		"Dec 31 00:00:00 combo sshd[3]: Failed password for root from 1.2.3.4 port 22 ssh2",
	}

	var years []int
	for _, line := range lines {
		es, ok := p.ParseLine(line)
		if !ok {
			t.Fatalf("ParseLine(%q) unexpectedly failed to match", line)
		}
		years = append(years, es[0].Timestamp.Year())
	}

	if years[0] != years[1] || years[1] != years[2] {
		t.Errorf("months increasing within one calendar year should not increment the year, got %v", years)
	}
}

func TestParser_MultipleWraps(t *testing.T) {
	p := NewParser()
	lines := []string{
		"Dec 31 00:00:00 combo sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
		"Jan  1 00:00:00 combo sshd[2]: Failed password for root from 1.2.3.4 port 22 ssh2",
		"Dec 31 00:00:00 combo sshd[3]: Failed password for root from 1.2.3.4 port 22 ssh2",
		"Jan  1 00:00:00 combo sshd[4]: Failed password for root from 1.2.3.4 port 22 ssh2",
	}

	var years []int
	for _, line := range lines {
		es, ok := p.ParseLine(line)
		if !ok {
			t.Fatalf("ParseLine(%q) unexpectedly failed to match", line)
		}
		years = append(years, es[0].Timestamp.Year())
	}

	want := []int{years[0], years[0] + 1, years[0] + 1, years[0] + 2}
	for i := range years {
		if years[i] != want[i] {
			t.Errorf("years = %v, want %v", years, want)
			break
		}
	}
}
