package keybackup

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
)

type nopStore struct{ u *url.URL }

func (nopStore) Put(context.Context, Backup) error            { return nil }
func (nopStore) Exists(context.Context, string) (bool, error) { return false, nil }

func TestOpenKnownScheme(t *testing.T) {
	Register("testscheme", func(_ context.Context, u *url.URL) (Store, error) { return nopStore{u: u}, nil })
	s, err := Open(context.Background(), "testscheme://host/path?x=1")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ns, ok := s.(nopStore)
	if !ok {
		t.Fatalf("got %T, want nopStore", s)
	}
	if ns.u.Host != "host" || ns.u.Path != "/path" || ns.u.Query().Get("x") != "1" {
		t.Errorf("provider got wrong url: %s", ns.u)
	}
}

func TestOpenUnknownScheme(t *testing.T) {
	Register("known", func(context.Context, *url.URL) (Store, error) { return nopStore{}, nil })
	_, err := Open(context.Background(), "nope://x")
	if !errors.Is(err, ErrUnknownScheme) {
		t.Fatalf("got %v, want ErrUnknownScheme", err)
	}
	if !strings.Contains(err.Error(), "known") {
		t.Errorf("error should list registered schemes, got %q", err)
	}
}

func TestOpenEmptyOrMalformed(t *testing.T) {
	for _, raw := range []string{"", "no-scheme", "://x"} {
		if _, err := Open(context.Background(), raw); err == nil {
			t.Errorf("Open(%q) should fail", raw)
		}
	}
}

func TestRegisterPanicsOnDuplicate(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("second Register of same scheme should panic")
		}
	}()
	Register("dup", func(context.Context, *url.URL) (Store, error) { return nopStore{}, nil })
	Register("dup", func(context.Context, *url.URL) (Store, error) { return nopStore{}, nil })
}

func TestSafeID(t *testing.T) {
	// 32 zero bytes, base64 raw std = 43 'A's.
	got, err := SafeID("SHA256:" + strings.Repeat("A", 43))
	if err != nil {
		t.Fatal(err)
	}
	if got != strings.Repeat("0", 64) {
		t.Errorf("got %q", got)
	}
	for _, bad := range []string{"", "MD5:abc", "SHA256:", "SHA256:!!!"} {
		if _, err := SafeID(bad); err == nil {
			t.Errorf("SafeID(%q) should fail", bad)
		}
	}
}
