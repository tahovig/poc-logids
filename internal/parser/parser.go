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
// output. Parsed timestamps land in year 0, so ordering and duration
// math are only valid within a single log that doesn't cross a
// Dec 31 -> Jan 1 boundary — an accepted limitation given brute-force
// detection windows operate on a seconds-to-minutes scale, far
// shorter than a year.
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

// ParseLine attempts to extract a failed-auth event from a single log
// line. Most lines in a real auth log are unrelated to SSH auth
// failures (session open/close, cron, logrotate, ...) — ok is false
// for those, which is the normal case, not an error.
func ParseLine(line string) (event AuthFailureEvent, ok bool) {
	for _, re := range formats {
		match := re.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		groups := namedGroups(re, match)

		ts, err := time.Parse(syslogTimeLayout, groups["ts"])
		if err != nil {
			continue
		}

		return AuthFailureEvent{
			Timestamp: ts,
			Source:    groups["source"],
			User:      groups["user"],
			Raw:       line,
		}, true
	}
	return AuthFailureEvent{}, false
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
