package file

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bitnami/sealed-secrets/pkg/keybackup"
)

const fp = "SHA256:" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestPutThenExists(t *testing.T) {
	dir := t.TempDir()
	s, err := keybackup.Open(context.Background(), "file://"+dir)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := s.Exists(context.Background(), fp)
	if err != nil || ok {
		t.Fatalf("Exists before Put = %v, %v; want false, nil", ok, err)
	}
	if err := s.Put(context.Background(), keybackup.Backup{Fingerprint: fp, SecretName: "k1", Manifest: []byte(`{"a":1}`)}); err != nil {
		t.Fatal(err)
	}
	ok, err = s.Exists(context.Background(), fp)
	if err != nil || !ok {
		t.Fatalf("Exists after Put = %v, %v; want true, nil", ok, err)
	}
	got, err := os.ReadFile(filepath.Join(dir, strings.Repeat("0", 64)+".json"))
	if err != nil || string(got) != `{"a":1}` {
		t.Fatalf("file content = %q, %v", got, err)
	}
}

func TestPutTwiceReplaces(t *testing.T) {
	dir := t.TempDir()
	s, _ := New(dir)
	ctx := context.Background()
	_ = s.Put(ctx, keybackup.Backup{Fingerprint: fp, Manifest: []byte("one")})
	if err := s.Put(ctx, keybackup.Backup{Fingerprint: fp, Manifest: []byte("two")}); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("want 1 file, got %d", len(entries))
	}
	got, _ := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if string(got) != "two" {
		t.Errorf("content = %q, want two", got)
	}
}

func TestNoPartialFileOnFailure(t *testing.T) {
	dir := t.TempDir()
	s, _ := New(dir)
	// Make the directory read-only so the temp file cannot be created.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skip("cannot chmod:", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := s.Put(context.Background(), keybackup.Backup{Fingerprint: fp, Manifest: []byte("x")}); err == nil {
		t.Skip("Put succeeded despite read-only dir (running as root?)")
	}
	_ = os.Chmod(dir, 0o700)
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("expected no files, got %v", entries)
	}
}

func TestOpenRejectsRelativeAndMissing(t *testing.T) {
	if _, err := keybackup.Open(context.Background(), "file://relative/dir"); err == nil {
		t.Error("relative path should be rejected")
	}
	if _, err := keybackup.Open(context.Background(), "file:///definitely/not/here"); err == nil {
		t.Error("missing dir should be rejected")
	}
}

func TestBadFingerprint(t *testing.T) {
	s, _ := New(t.TempDir())
	if err := s.Put(context.Background(), keybackup.Backup{Fingerprint: "bad"}); err == nil {
		t.Error("Put with bad fingerprint should fail")
	}
	if _, err := s.Exists(context.Background(), "bad"); err == nil {
		t.Error("Exists with bad fingerprint should fail")
	}
}
