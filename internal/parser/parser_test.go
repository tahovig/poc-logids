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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, ok := ParseLine(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("ParseLine(%q) ok = %v, want %v", tt.line, ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
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
