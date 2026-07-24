// Package parser extracts failed SSH authentication attempts from
// syslog-style auth log lines.
package parser

import (
	"regexp"
	"strconv"
	"strings"
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

	// pamUnixBodyRe and openSSHBodyRe match just the message body (no
	// timestamp/host/process prefix) of the two formats above, used to
	// re-parse the message rsyslog wraps inside a "message repeated"
	// line (see repeatedRe). Kept as separate patterns rather than
	// factored out of pamUnixRe/openSSHRe so those two -- already
	// covered by real-data tests -- are untouched by this addition.
	pamUnixBodyRe = regexp.MustCompile(
		`^authentication failure;.*?\brhost=(?P<source>\S+?)(?:\s+user=(?P<user>\S+))?\s*$`,
	)
	openSSHBodyRe = regexp.MustCompile(
		`^Failed password for (?:invalid user\s+)?(?P<user>\S+) from (?P<source>\S+) port \d+ ssh2\s*$`,
	)
	bodyFormats = []*regexp.Regexp{pamUnixBodyRe, openSSHBodyRe}

	// repeatedRe matches rsyslog's own repeated-message collapsing
	// (Ubuntu's default $RepeatedMsgReduction on): rather than logging
	// the same line twice in a row, rsyslog logs it once, then a
	// summary line once the repeats stop or a different message
	// arrives:
	//   Jul 20 23:13:59 host sshd[31120]: message repeated 4 times: [ Failed password for root from 45.148.10.152 port 40498 ssh2]
	// Confirmed on the real honeypot droplet: a single SSH connection
	// making several password attempts logs an identical "Failed
	// password for ..." line each time, so this collapsing hits
	// exactly the burst shape this tool exists to detect -- without
	// expanding it, those attempts are invisible to the parser, not
	// just miscounted (a real 5-attempt burst was observed showing
	// only 1 parsed event, which at the default -threshold 5 means
	// the burst wouldn't be flagged at all).
	repeatedRe = regexp.MustCompile(
		`^(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd(?:\(pam_unix\))?\[\d+\]:\s+message repeated (?P<count>\d+) times:\s+\[\s*(?P<inner>.+?)\s*\]\s*$`,
	)
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

// ParseLine attempts to extract failed-auth events from a single log
// line. Most lines in a real auth log are unrelated to SSH auth
// failures (session open/close, cron, logrotate, ...) — ok is false
// for those, which is the normal case, not an error. A line usually
// yields exactly one event, but a "message repeated N times: [...]"
// line (see repeatedRe) yields N -- rsyslog's own collapsing of
// consecutive identical lines represents N real attempts, not one.
func (p *Parser) ParseLine(line string) (events []AuthFailureEvent, ok bool) {
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

		return []AuthFailureEvent{{
			Timestamp: p.resolveYear(raw),
			Source:    sanitizeField(groups["source"]),
			User:      sanitizeField(groups["user"]),
			Raw:       line,
		}}, true
	}
	return p.parseRepeated(line)
}

// parseRepeated expands an rsyslog repeated-message summary line into
// the N real events it stands in for, by re-parsing the message body
// rsyslog wrapped inside it against the same formats ParseLine
// otherwise matches. rsyslog only keeps the timestamp of the summary
// line itself, not each individual occurrence's real time, so all N
// synthetic events share that one timestamp -- a documented precision
// loss, not a bug: the alternative (not expanding at all) silently
// drops the attempts entirely, which is strictly worse for detection.
func (p *Parser) parseRepeated(line string) (events []AuthFailureEvent, ok bool) {
	match := repeatedRe.FindStringSubmatch(line)
	if match == nil {
		return nil, false
	}
	groups := namedGroups(repeatedRe, match)

	count, err := strconv.Atoi(groups["count"])
	if err != nil || count <= 0 {
		return nil, false
	}

	var source, user string
	matched := false
	for _, re := range bodyFormats {
		bodyMatch := re.FindStringSubmatch(groups["inner"])
		if bodyMatch == nil {
			continue
		}
		bodyGroups := namedGroups(re, bodyMatch)
		source, user = sanitizeField(bodyGroups["source"]), sanitizeField(bodyGroups["user"])
		matched = true
		break
	}
	if !matched {
		return nil, false
	}

	raw, err := time.Parse(syslogTimeLayout, groups["ts"])
	if err != nil {
		return nil, false
	}
	ts := p.resolveYear(raw)

	events = make([]AuthFailureEvent, count)
	for i := range events {
		events[i] = AuthFailureEvent{Timestamp: ts, Source: source, User: user, Raw: line}
	}
	return events, true
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

// sanitizeField strips ASCII control bytes (0x00-0x1F, 0x7F) from a
// captured source/user field. sshd logs whatever a client sends
// completely unsanitized, and \S+ in the regexes above happily
// captures raw control bytes along with everything else -- a
// legitimate username or rhost never contains one, but a hostile
// client can send one deliberately (e.g. ANSI/CSI escape sequences
// appended to a "username") specifically to corrupt a naive
// terminal-based log viewer: printed as-is, the escape bytes get
// interpreted by the terminal (cursor moves, screen clears) rather
// than displayed, which is exactly the kind of thing a security tool
// must not forward untouched. Raw keeps the original, unsanitized
// line for forensic purposes; only the parsed-out fields are cleaned.
func sanitizeField(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
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
