// Package parser extracts failed SSH authentication attempts from
// syslog-style auth log lines.
package parser

import (
	"regexp"
	"time"
)

// AuthFailureEvent is a single failed SSH authentication attempt
// extracted from a log line.
type AuthFailureEvent struct {
	Timestamp time.Time
	Source    string // remote host or IP that attempted the connection
	User      string // username that was attempted, if the log line reported one
	Raw       string // original log line
}

// syslogTimeLayout has no year field, matching real syslog/auth.log
// output. Parser.resolveYear infers a consistent year across a
// Dec 31 -> Jan 1 boundary; see its doc comment.
const syslogTimeLayout = "Jan _2 15:04:05"

var (
	// pamUnixRe matches the older PAM-style syslog format found in
	// real-world datasets like loghub's Linux sample:
	//   Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; ... rhost=218.188.2.4
	// rhost may be a raw IP or a reverse-DNS hostname; user= is only
	// present on some lines.
	pamUnixRe = regexp.MustCompile(
		`^(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\(pam_unix\)\[\d+\]:\s+authentication failure;.*?\brhost=(?P<source>\S+?)(?:\s+user=(?P<user>\S+))?\s*$`,
	)

	// openSSHRe matches the modern OpenSSH format:
	//   Jan  2 03:04:05 host sshd[1234]: Failed password for invalid user bob from 10.0.0.5 port 51234 ssh2
	//   Jan  2 03:04:05 host sshd[1234]: Failed password for root from 10.0.0.5 port 51234 ssh2
	openSSHRe = regexp.MustCompile(
		`^(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user\s+)?(?P<user>\S+) from (?P<source>\S+) port \d+ ssh2\s*$`,
	)

	formats = []*regexp.Regexp{pamUnixRe, openSSHRe}
)

// Parser extracts failed-auth events from a sequence of log lines,
// inferring a consistent year across a Dec 31 -> Jan 1 boundary as it
// goes (see resolveYear). Because that inference depends on seeing
// lines in chronological order, a single Parser must be used across
// an entire file or stream — not recreated per line — and lines must
// be fed to it in the order they appear in the log (true of any
// real, append-only log file).
type Parser struct {
	year      int
	lastMonth time.Month
	started   bool
}

// NewParser creates a Parser ready to process a new file or stream.
func NewParser() *Parser {
	return &Parser{}
}

// ParseLine attempts to extract a failed-auth event from a single log
// line. Most lines in a real auth log are unrelated to SSH auth
// failures (session open/close, cron, logrotate, ...) — ok is false
// for those, which is the normal case, not an error.
func (p *Parser) ParseLine(line string) (event AuthFailureEvent, ok bool) {
	for _, re := range formats {
		match := re.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		groups := namedGroups(re, match)

		raw, err := time.Parse(syslogTimeLayout, groups["ts"])
		if err != nil {
			continue
		}

		return AuthFailureEvent{
			Timestamp: p.resolveYear(raw),
			Source:    groups["source"],
			User:      groups["user"],
			Raw:       line,
		}, true
	}
	return AuthFailureEvent{}, false
}

// resolveYear assigns a consistent, monotonically increasing year to
// an otherwise year-less syslog timestamp. The first line seen
// anchors year 0 (a placeholder, not a real calendar year -- classic
// syslog format simply doesn't carry that information, and display
// formatting never shows it); each later line whose month is earlier
// than the previous line's month is assumed to have crossed a
// Dec -> Jan boundary and gets the next year. A spurious one-off
// out-of-order line (e.g. two processes' entries interleaved within
// the same second) can't trigger this by accident -- that would take
// an entire month's difference, not ordinary jitter.
func (p *Parser) resolveYear(raw time.Time) time.Time {
	month := raw.Month()
	if p.started && month < p.lastMonth {
		p.year++
	}
	p.started = true
	p.lastMonth = month
	return time.Date(p.year, month, raw.Day(), raw.Hour(), raw.Minute(), raw.Second(), 0, time.UTC)
}

func namedGroups(re *regexp.Regexp, match []string) map[string]string {
	groups := make(map[string]string, len(match))
	for i, name := range re.SubexpNames() {
		if i == 0 || name == "" {
			continue
		}
		groups[name] = match[i]
	}
	return groups
}
