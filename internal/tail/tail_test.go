package tail

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testTimeout = 5 * time.Second

func recvLine(t *testing.T, ch <-chan Line) Line {
	t.Helper()
	select {
	case l, ok := <-ch:
		if !ok {
			t.Fatal("channel closed while waiting for a line")
		}
		return l
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for a line")
		return Line{}
	}
}

func expectNoLineSoon(t *testing.T, ch <-chan Line) {
	t.Helper()
	select {
	case l, ok := <-ch:
		if !ok {
			return
		}
		t.Fatalf("expected no line yet, got %+v", l)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestFollow_AppendedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path, []byte("existing line\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start from the end of the existing content, like main.go does
	// after its initial one-shot scan.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := Follow(ctx, path, info.Size())
	if err != nil {
		t.Fatalf("Follow: %v", err)
	}

	expectNoLineSoon(t, lines)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("first new line\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	got := recvLine(t, lines)
	if got.Err != nil {
		t.Fatalf("unexpected error: %v", got.Err)
	}
	if got.Text != "first new line" {
		t.Errorf("got %q, want %q", got.Text, "first new line")
	}
}

func TestFollow_PartialLineHeldUntilComplete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	lines, err := Follow(ctx, path, 0)
	if err != nil {
		t.Fatalf("Follow: %v", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("half a line, no newline yet"); err != nil {
		t.Fatal(err)
	}

	expectNoLineSoon(t, lines)

	if _, err := f.WriteString(" -- now complete\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	got := recvLine(t, lines)
	want := "half a line, no newline yet -- now complete"
	if got.Text != want {
		t.Errorf("got %q, want %q", got.Text, want)
	}
}

func TestFollow_RotationByRenameAndRecreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path, []byte("before rotation\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := Follow(ctx, path, info.Size())
	if err != nil {
		t.Fatalf("Follow: %v", err)
	}

	// Simulate logrotate: move the current file aside, create a fresh
	// one at the same path, write to the new one.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("after rotation\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	got := recvLine(t, lines)
	if got.Err != nil {
		t.Fatalf("unexpected error: %v", got.Err)
	}
	if got.Text != "after rotation" {
		t.Errorf("got %q, want %q", got.Text, "after rotation")
	}
}

func TestFollow_InPlaceTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path, []byte("line one\nline two\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := Follow(ctx, path, info.Size())
	if err != nil {
		t.Fatalf("Follow: %v", err)
	}

	// copytruncate: truncate the same inode, then write fresh
	// (shorter) content.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("post-truncate line\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	got := recvLine(t, lines)
	if got.Err != nil {
		t.Fatalf("unexpected error: %v", got.Err)
	}
	if got.Text != "post-truncate line" {
		t.Errorf("got %q, want %q", got.Text, "post-truncate line")
	}
}

func TestFollow_ContextCancelClosesChannel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	lines, err := Follow(ctx, path, 0)
	if err != nil {
		t.Fatalf("Follow: %v", err)
	}

	cancel()

	select {
	case _, ok := <-lines:
		if ok {
			t.Fatal("expected channel to close after cancel, got a value instead")
		}
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for channel to close after cancel")
	}
}
