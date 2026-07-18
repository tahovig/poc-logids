// Package tail follows a growing log file (tail -f semantics),
// transparently handling log rotation.
package tail

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Line is a single new line observed while following a file, or a
// non-fatal error encountered while watching. Follow keeps running
// after an error where it can (e.g. a transient stat failure); the
// caller decides whether an error is worth acting on.
type Line struct {
	Text string
	Err  error
}

// Follow watches path for appended content, sending each new
// complete line on the returned channel as it appears, starting from
// startOffset bytes into the file (callers that already read the
// file once, e.g. an initial full scan, should pass the offset they
// stopped at so nothing is skipped or double-read).
//
// Rotation is handled transparently: a rename+recreate (the common
// logrotate strategy) or an in-place truncation (copytruncate) both
// cause Follow to pick up the new/reset file rather than blocking
// forever on a stale handle. Follow runs until ctx is canceled,
// closing the channel when it returns.
func Follow(ctx context.Context, path string, startOffset int64) (<-chan Line, error) {
	dir := filepath.Dir(path)
	name := filepath.Base(path)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("creating watcher: %w", err)
	}
	if err := watcher.Add(dir); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("watching %s: %w", dir, err)
	}

	fl, err := openFollower(path)
	if err != nil {
		watcher.Close()
		return nil, err
	}
	fl.pos = startOffset
	if err := fl.seedTail(); err != nil {
		watcher.Close()
		fl.f.Close()
		return nil, err
	}

	out := make(chan Line)

	go func() {
		defer close(out)
		defer watcher.Close()
		defer fl.f.Close()

		// Catch up on anything written between startOffset being
		// determined and the watch actually starting.
		if err := fl.readNew(ctx, out); err != nil {
			sendLine(ctx, out, Line{Err: err})
		}

		for {
			select {
			case <-ctx.Done():
				return

			case event, okw := <-watcher.Events:
				if !okw {
					return
				}
				if filepath.Base(event.Name) != name {
					continue
				}
				if event.Op&(fsnotify.Rename|fsnotify.Remove) != 0 {
					fl.f.Close()
					newFl, err := waitForReopen(ctx, path)
					if err != nil {
						if err != context.Canceled {
							sendLine(ctx, out, Line{Err: err})
						}
						return
					}
					fl = newFl
				}
				if err := fl.readNew(ctx, out); err != nil {
					sendLine(ctx, out, Line{Err: err})
				}

			case werr, okw := <-watcher.Errors:
				if !okw {
					return
				}
				sendLine(ctx, out, Line{Err: werr})
			}
		}
	}()

	return out, nil
}

func sendLine(ctx context.Context, out chan<- Line, l Line) {
	select {
	case out <- l:
	case <-ctx.Done():
	}
}

// tailVerifyBytes bounds how much trailing content readNew keeps
// around to detect an in-place truncation that a size check alone
// can miss (see contentChanged).
const tailVerifyBytes = 4096

// follower tracks read progress through one open file handle.
type follower struct {
	f       *os.File
	pos     int64  // bytes of f already delivered as complete lines
	pending []byte // bytes read past the last full line, awaiting its terminator
	tail    []byte // last up to tailVerifyBytes bytes already consumed, for contentChanged
}

func openFollower(path string) (*follower, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	return &follower{f: f}, nil
}

// seedTail populates tail from disk to match fl.pos, needed when pos
// starts nonzero (a caller-supplied startOffset skipping content this
// follower never read itself) so contentChanged has something valid
// to verify against from the very first check.
func (fl *follower) seedTail() error {
	if fl.pos == 0 {
		return nil
	}
	n := fl.pos
	if n > tailVerifyBytes {
		n = tailVerifyBytes
	}
	if _, err := fl.f.Seek(fl.pos-n, io.SeekStart); err != nil {
		return fmt.Errorf("seek: %w", err)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(fl.f, buf); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	fl.tail = buf
	return nil
}

// readNew reads any bytes appended since the last call and emits
// each complete newline-terminated line. A trailing partial line (no
// newline yet) is held in pending until more data completes it.
func (fl *follower) readNew(ctx context.Context, out chan<- Line) error {
	info, err := fl.f.Stat()
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}
	size := info.Size()

	truncated := size < fl.pos
	if !truncated && fl.pos > 0 {
		truncated, err = fl.contentChanged(size)
		if err != nil {
			return err
		}
	}
	if truncated {
		// An in-place (copytruncate-style) truncation, possibly
		// already followed by a rewrite. Restart from the top.
		fl.pos = 0
		fl.pending = fl.pending[:0]
		fl.tail = fl.tail[:0]
	}
	if size == fl.pos {
		return nil
	}

	if _, err := fl.f.Seek(fl.pos, io.SeekStart); err != nil {
		return fmt.Errorf("seek: %w", err)
	}
	buf := make([]byte, size-fl.pos)
	n, err := io.ReadFull(fl.f, buf)
	if err != nil && err != io.ErrUnexpectedEOF {
		return fmt.Errorf("read: %w", err)
	}
	buf = buf[:n]
	fl.pos += int64(n)
	fl.pending = append(fl.pending, buf...)
	fl.appendTail(buf)

	for {
		idx := bytes.IndexByte(fl.pending, '\n')
		if idx < 0 {
			break
		}
		line := strings.TrimSuffix(string(fl.pending[:idx]), "\r")
		fl.pending = fl.pending[idx+1:]
		select {
		case out <- Line{Text: line}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// contentChanged reports whether the bytes on disk just before our
// current position still match what we last read there. A bare size
// check (size < pos) misses the case where a truncation is
// immediately followed by a rewrite that grows the file past its old
// size before the next check runs -- the file never appears smaller
// than pos even though everything at and before pos is now different
// content. Re-verifying a bounded trailing window catches that case
// without re-reading the whole file on every check.
func (fl *follower) contentChanged(size int64) (bool, error) {
	n := int64(len(fl.tail))
	if n == 0 {
		return false, nil
	}
	start := fl.pos - n
	if start < 0 || start+n > size {
		return true, nil
	}
	if _, err := fl.f.Seek(start, io.SeekStart); err != nil {
		return false, fmt.Errorf("seek: %w", err)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(fl.f, buf); err != nil {
		return false, fmt.Errorf("read: %w", err)
	}
	return !bytes.Equal(buf, fl.tail), nil
}

func (fl *follower) appendTail(buf []byte) {
	fl.tail = append(fl.tail, buf...)
	if len(fl.tail) > tailVerifyBytes {
		fl.tail = fl.tail[len(fl.tail)-tailVerifyBytes:]
	}
}

// waitForReopen retries opening path until it exists again (or ctx
// is canceled), covering the brief window between logrotate removing
// the old file and creating its replacement.
func waitForReopen(ctx context.Context, path string) (*follower, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if fl, err := openFollower(path); err == nil {
			return fl, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}
