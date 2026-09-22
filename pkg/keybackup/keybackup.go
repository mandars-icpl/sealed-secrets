// Package keybackup stores copies of sealing keys outside the cluster.
//
// The controller core only knows the Store interface and a URL. The scheme
// of the URL selects a provider that was registered by a provider package
// from its init function, in the same style as database/sql drivers.
package keybackup

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrUnknownScheme is returned by Open when no provider is registered for the URL scheme.
var ErrUnknownScheme = errors.New("keybackup: unknown scheme")

// Backup is one sealing key, ready to be applied back into a cluster.
type Backup struct {
	// Fingerprint is the public key fingerprint (crypto.PublicKeyFingerprint) and the stable identity of the entry.
	Fingerprint string
	// SecretName is metadata.name of the Secret in Manifest.
	SecretName string
	// Manifest is the Secret as JSON with server-populated fields stripped. Never log it.
	Manifest []byte
	// CreatedAt is the certificate NotBefore time.
	CreatedAt time.Time
}

// Store is implemented by every backend.
type Store interface {
	// Put stores b, creating the entry for b.Fingerprint or replacing its content if it
	// already exists. A second Put with the same fingerprint never creates a second entry.
	Put(ctx context.Context, b Backup) error
	// Exists reports whether an entry with this fingerprint is already stored.
	Exists(ctx context.Context, fingerprint string) (bool, error)
}

// OpenFunc constructs a Store from an already parsed URL.
type OpenFunc func(ctx context.Context, u *url.URL) (Store, error)

var (
	providersMu sync.RWMutex
	providers   = map[string]OpenFunc{}
)

// Register makes a provider available under scheme. It panics if the scheme is already taken.
func Register(scheme string, open OpenFunc) {
	providersMu.Lock()
	defer providersMu.Unlock()
	if _, dup := providers[scheme]; dup {
		panic("keybackup: Register called twice for scheme " + scheme)
	}
	providers[scheme] = open
}

// Open parses rawURL and returns the Store for its scheme.
func Open(ctx context.Context, rawURL string) (Store, error) {
	if rawURL == "" {
		return nil, errors.New("keybackup: empty URL")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("keybackup: parse URL: %w", err)
	}
	if u.Scheme == "" {
		return nil, fmt.Errorf("keybackup: URL %q has no scheme", rawURL)
	}
	providersMu.RLock()
	open, ok := providers[u.Scheme]
	names := make([]string, 0, len(providers))
	for s := range providers {
		names = append(names, s)
	}
	providersMu.RUnlock()
	if !ok {
		sort.Strings(names)
		return nil, fmt.Errorf("%w %q (registered: %s)", ErrUnknownScheme, u.Scheme, strings.Join(names, ", "))
	}
	return open(ctx, u)
}

// SafeID turns a fingerprint of the form "SHA256:<base64>" into 64 lowercase hex
// characters, safe for use in object names on any backend.
func SafeID(fingerprint string) (string, error) {
	const prefix = "SHA256:"
	if !strings.HasPrefix(fingerprint, prefix) {
		return "", fmt.Errorf("keybackup: unsupported fingerprint format %q", fingerprint)
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(fingerprint, prefix))
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("keybackup: malformed fingerprint %q", fingerprint)
	}
	return hex.EncodeToString(raw), nil
}
