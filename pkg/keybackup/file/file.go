// Package file is a keybackup provider that writes one JSON file per sealing key
// into a local directory. URL form: file:///absolute/path.
package file

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/bitnami/sealed-secrets/pkg/keybackup"
)

// Scheme is the URL scheme this provider registers.
const Scheme = "file"

func init() {
	keybackup.Register(Scheme, func(_ context.Context, u *url.URL) (keybackup.Store, error) {
		// file:///abs/dir parses to Host "" and Path "/abs/dir"; file://rel/dir parses to Host "rel".
		if u.Host != "" {
			return nil, fmt.Errorf("file backup: path must be absolute (file:///dir), got %q", u.String())
		}
		return New(u.Path)
	})
}

// Store writes entries into dir.
type Store struct {
	dir string
}

// New returns a Store for an existing absolute directory.
func New(dir string) (*Store, error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("file backup: %q is not an absolute path", dir)
	}
	st, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("file backup: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("file backup: %q is not a directory", dir)
	}
	return &Store{dir: dir}, nil
}

func (s *Store) path(fingerprint string) (string, error) {
	id, err := keybackup.SafeID(fingerprint)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.dir, id+".json"), nil
}

// Put writes the manifest to a temporary file and renames it into place.
func (s *Store) Put(_ context.Context, b keybackup.Backup) error {
	dst, err := s.path(b.Fingerprint)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".put-*")
	if err != nil {
		return fmt.Errorf("file backup: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(b.Manifest); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("file backup: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("file backup: close: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		cleanup()
		return fmt.Errorf("file backup: chmod: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		cleanup()
		return fmt.Errorf("file backup: rename: %w", err)
	}
	return nil
}

// Exists reports whether the entry file is present.
func (s *Store) Exists(_ context.Context, fingerprint string) (bool, error) {
	p, err := s.path(fingerprint)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(p)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("file backup: %w", err)
	}
}
