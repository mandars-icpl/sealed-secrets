# Sealing Key Backup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The controller backs up every sealing key to an external store before the key exists in the cluster, through a cloud-agnostic `Store` interface with an AWS Secrets Manager provider and a file provider.

**Architecture:** A new `pkg/keybackup` package defines `Backup`, `Store`, `Register` and `Open` (scheme-keyed provider registry) plus two providers in sub-packages. `pkg/controller` gains a backup-aware key generation path (controller-chosen Secret name, `Put` before `Create`), a best-effort reconcile of pre-existing keys, an informer hook for externally added keys, and three metrics. One flag, `--key-backup-url`, enables it; empty keeps today's behaviour byte for byte.

**Tech Stack:** Go 1.26 (repo `go.mod`), `k8s.io/client-go` fake clientset for tests, `github.com/aws/aws-sdk-go-v2` (`config`, `service/secretsmanager`), `prometheus/client_golang`, Helm chart in `helm/sealed-secrets`.

**Spec:** `docs/superpowers/specs/2026-09-22-sealing-key-backup-design.md`

## Global Constraints

- Backup is off when `--key-backup-url` is empty; with it empty, key creation must still use `GenerateName` and touch no new code path.
- Fail closed for new keys: the Kubernetes Secret is created only after `Store.Put` returns nil.
- Best effort for existing keys: reconcile and informer failures are logged and counted, never fatal.
- Store entries are keyed by public key fingerprint (`crypto.PublicKeyFingerprint`, form `SHA256:<base64>`), sanitized to hex by `keybackup.SafeID`.
- Stored payload is the Secret manifest as JSON with `resourceVersion`, `uid`, `creationTimestamp`, `managedFields`, `selfLink` cleared and `apiVersion: v1`, `kind: Secret` set.
- Controller-chosen names are `prefix + rand.String(5)` using `k8s.io/apimachinery/pkg/util/rand`.
- `Put` calls get a 30 second timeout from the controller.
- No log line and no error message ever contains key material or manifest bytes.
- Metric names live in namespace `sealed_secrets_controller`: `key_backup_total{result}`, `key_backup_last_success_timestamp_seconds`, `key_backup_unbacked_keys`.
- Commit messages: one short line, conventional prefix (`feat:`, `test:`, `docs:`, `chore:`), no trailers, no co-author line.
- Lint rules that bite here: `godot` (every comment ends with a period), `errname` (sentinel errors start with `Err`), `promlinter`, `goimports`.
- Run `go build ./... && go vet ./pkg/keybackup/... ./pkg/controller/...` before every commit.
- The integration Ginkgo suite runs against a pre-installed in-cluster controller, so the spec's "file provider integration test" is delivered as the manual kind verification in Task 10 instead. Task 9 records this in the spec.

---

## File map

| File | Responsibility |
|---|---|
| `pkg/keybackup/keybackup.go` | `Backup`, `Store`, `Register`, `Open`, `SafeID`, `ErrUnknownScheme` |
| `pkg/keybackup/keybackup_test.go` | registry and `SafeID` tests |
| `pkg/keybackup/file/file.go` | `file://` provider |
| `pkg/keybackup/file/file_test.go` | file provider tests |
| `pkg/keybackup/awssm/awssm.go` | `awssm://` provider, `api` interface over the SDK client |
| `pkg/keybackup/awssm/awssm_test.go` | fake-client tests |
| `pkg/controller/keys.go` | `buildKeySecret` extracted from `writeKey`; `keySecretManifest` |
| `pkg/controller/keys_test.go` | manifest tests |
| `pkg/controller/keybackup_metrics.go` | the three metrics and `registerKeyBackupMetrics` |
| `pkg/controller/keyregistry.go` | `backup` field, `generateKey` backup path, `unbacked` tracking |
| `pkg/controller/keyregistry_backup_test.go` | `fakeStore`, generation tests |
| `pkg/controller/keybackup.go` | `reconcileKeyBackups`, `backupKeySecret` helpers |
| `pkg/controller/keybackup_test.go` | reconcile and informer tests |
| `pkg/controller/main.go` | `Flags.KeyBackupURL`, open store, reconcile call |
| `pkg/controller/controller.go` | informer `AddFunc` hook |
| `cmd/controller/main.go` | flag binding, provider imports |
| `helm/sealed-secrets/values.yaml`, `templates/deployment.yaml`, `README.md` | `keyBackup.url` |
| `docs/key-backup.md`, `README.md` | user docs |

---

### Task 1: `pkg/keybackup` core (types, registry, SafeID)

**Files:**
- Create: `pkg/keybackup/keybackup.go`
- Test: `pkg/keybackup/keybackup_test.go`

**Interfaces:**
- Produces:
  ```go
  type Backup struct { Fingerprint, SecretName string; Manifest []byte; CreatedAt time.Time }
  type Store interface { Put(ctx context.Context, b Backup) error; Exists(ctx context.Context, fingerprint string) (bool, error) }
  type OpenFunc func(ctx context.Context, u *url.URL) (Store, error)
  func Register(scheme string, open OpenFunc)
  func Open(ctx context.Context, rawURL string) (Store, error)
  func SafeID(fingerprint string) (string, error)
  var ErrUnknownScheme error
  ```

- [x] **Step 1: Write the failing tests**

```go
// pkg/keybackup/keybackup_test.go
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
```

- [x] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/keybackup/ 2>&1 | head -5`
Expected: build failure, `undefined: Register` (package does not exist yet).

- [x] **Step 3: Write the implementation**

```go
// pkg/keybackup/keybackup.go

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
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/keybackup/ -v 2>&1 | tail -8`
Expected: all five tests PASS.

- [x] **Step 5: Commit**

```bash
git add pkg/keybackup/keybackup.go pkg/keybackup/keybackup_test.go
git commit -m "feat: add keybackup store interface and provider registry"
```

---

### Task 2: file provider

**Files:**
- Create: `pkg/keybackup/file/file.go`
- Test: `pkg/keybackup/file/file_test.go`

**Interfaces:**
- Consumes: `keybackup.Register`, `keybackup.Store`, `keybackup.Backup`, `keybackup.SafeID`
- Produces: scheme `file`, URL `file:///abs/dir`; entries at `<dir>/<SafeID>.json`. Exported `New(dir string) (*Store, error)` for tests.

- [x] **Step 1: Write the failing tests**

```go
// pkg/keybackup/file/file_test.go
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
```

- [x] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/keybackup/file/ 2>&1 | head -5`
Expected: build failure, `undefined: New`.

- [x] **Step 3: Write the implementation**

```go
// pkg/keybackup/file/file.go

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
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./pkg/keybackup/... -v 2>&1 | grep -E "^(--- |ok|FAIL)"`
Expected: every test PASS or SKIP (the read-only test skips under root); package lines `ok`.

- [x] **Step 5: Commit**

```bash
git add pkg/keybackup/file/
git commit -m "feat: add file keybackup provider"
```

---

### Task 3: AWS Secrets Manager provider

**Files:**
- Create: `pkg/keybackup/awssm/awssm.go`
- Test: `pkg/keybackup/awssm/awssm_test.go`
- Modify: `go.mod`, `go.sum` (via `go get`)

**Interfaces:**
- Consumes: `keybackup.Register`, `keybackup.Backup`, `keybackup.SafeID`
- Produces: scheme `awssm`, URL `awssm://<prefix>[/<more>]?region=<r>&kms-key-id=<k>`. Exported `NewWithClient(api, prefix, kmsKeyID string) *Store` for tests. Unexported `api` interface with `CreateSecret`, `PutSecretValue`, `DescribeSecret`, `TagResource`.

- [x] **Step 1: Add the SDK modules**

Run:
```bash
go get github.com/aws/aws-sdk-go-v2/config@latest github.com/aws/aws-sdk-go-v2/service/secretsmanager@latest
go mod tidy
go build ./...
```
Expected: build succeeds. Note that `go mod tidy` removes the three modules again at this point,
because no file imports them until step 4; that is normal. They come back as direct requirements in
`go.mod` when `go mod tidy` is re-run after the implementation exists, which step 4 does.

- [x] **Step 2: Write the failing tests**

```go
// pkg/keybackup/awssm/awssm_test.go
package awssm

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/bitnami/sealed-secrets/pkg/keybackup"
)

const fp = "SHA256:" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

var wantName = "ss/prod/" + strings.Repeat("0", 64)

type fakeAPI struct {
	existing    map[string][]byte
	createErr   error
	putErr      error
	describeErr error
	created     []*secretsmanager.CreateSecretInput
	puts        []*secretsmanager.PutSecretValueInput
	tags        []*secretsmanager.TagResourceInput
}

func (f *fakeAPI) CreateSecret(_ context.Context, in *secretsmanager.CreateSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	if _, ok := f.existing[*in.Name]; ok {
		return nil, &types.ResourceExistsException{Message: aws.String("exists")}
	}
	f.created = append(f.created, in)
	f.existing[*in.Name] = in.SecretBinary
	return &secretsmanager.CreateSecretOutput{}, nil
}

func (f *fakeAPI) PutSecretValue(_ context.Context, in *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	if f.putErr != nil {
		return nil, f.putErr
	}
	f.puts = append(f.puts, in)
	f.existing[*in.SecretId] = in.SecretBinary
	return &secretsmanager.PutSecretValueOutput{}, nil
}

func (f *fakeAPI) DescribeSecret(_ context.Context, in *secretsmanager.DescribeSecretInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error) {
	if f.describeErr != nil {
		return nil, f.describeErr
	}
	if _, ok := f.existing[*in.SecretId]; !ok {
		return nil, &types.ResourceNotFoundException{Message: aws.String("nope")}
	}
	return &secretsmanager.DescribeSecretOutput{}, nil
}

func (f *fakeAPI) TagResource(_ context.Context, in *secretsmanager.TagResourceInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.TagResourceOutput, error) {
	f.tags = append(f.tags, in)
	return &secretsmanager.TagResourceOutput{}, nil
}

func newFake() *fakeAPI { return &fakeAPI{existing: map[string][]byte{}} }

func tagValue(tags []types.Tag, key string) string {
	for _, t := range tags {
		if *t.Key == key {
			return *t.Value
		}
	}
	return ""
}

func TestPutCreatesWhenMissing(t *testing.T) {
	f := newFake()
	s := NewWithClient(f, "ss/prod", "alias/k")
	err := s.Put(context.Background(), keybackup.Backup{Fingerprint: fp, SecretName: "sealed-secrets-keyabcde", Manifest: []byte("m")})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.created) != 1 || len(f.puts) != 0 {
		t.Fatalf("created=%d puts=%d, want 1/0", len(f.created), len(f.puts))
	}
	in := f.created[0]
	if *in.Name != wantName {
		t.Errorf("name = %q, want %q", *in.Name, wantName)
	}
	if *in.KmsKeyId != "alias/k" {
		t.Errorf("kms = %q", *in.KmsKeyId)
	}
	if string(in.SecretBinary) != "m" {
		t.Errorf("binary = %q", in.SecretBinary)
	}
	if tagValue(in.Tags, tagSecretName) != "sealed-secrets-keyabcde" || tagValue(in.Tags, tagFingerprint) != fp || tagValue(in.Tags, tagManagedBy) != "sealed-secrets-controller" {
		t.Errorf("tags = %v", in.Tags)
	}
}

func TestPutNoKMSKeyOmitsField(t *testing.T) {
	f := newFake()
	s := NewWithClient(f, "ss", "")
	_ = s.Put(context.Background(), keybackup.Backup{Fingerprint: fp, Manifest: []byte("m")})
	if f.created[0].KmsKeyId != nil {
		t.Errorf("KmsKeyId should be nil when not configured")
	}
}

func TestPutReplacesWhenExists(t *testing.T) {
	f := newFake()
	f.existing[wantName] = []byte("old")
	s := NewWithClient(f, "ss/prod", "")
	err := s.Put(context.Background(), keybackup.Backup{Fingerprint: fp, SecretName: "newname", Manifest: []byte("new")})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.created) != 0 || len(f.puts) != 1 || len(f.tags) != 1 {
		t.Fatalf("created=%d puts=%d tags=%d, want 0/1/1", len(f.created), len(f.puts), len(f.tags))
	}
	if string(f.existing[wantName]) != "new" {
		t.Errorf("content not replaced")
	}
	if tagValue(f.tags[0].Tags, tagSecretName) != "newname" {
		t.Errorf("secret-name tag not refreshed: %v", f.tags[0].Tags)
	}
}

func TestPutPropagatesCreateError(t *testing.T) {
	f := newFake()
	f.createErr = errors.New("boom")
	s := NewWithClient(f, "ss", "")
	if err := s.Put(context.Background(), keybackup.Backup{Fingerprint: fp}); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
}

func TestExists(t *testing.T) {
	f := newFake()
	s := NewWithClient(f, "ss/prod", "")
	ok, err := s.Exists(context.Background(), fp)
	if err != nil || ok {
		t.Fatalf("missing: got %v, %v", ok, err)
	}
	f.existing[wantName] = []byte("x")
	ok, err = s.Exists(context.Background(), fp)
	if err != nil || !ok {
		t.Fatalf("present: got %v, %v", ok, err)
	}
	f.describeErr = errors.New("net down")
	if _, err := s.Exists(context.Background(), fp); err == nil {
		t.Fatal("transport error should propagate")
	}
}

func TestParseURL(t *testing.T) {
	u, _ := url.Parse("awssm://sealed-secrets/prod-cluster/?region=ap-south-1&kms-key-id=alias/x")
	prefix, region, kms, err := parseURL(u)
	if err != nil {
		t.Fatal(err)
	}
	if prefix != "sealed-secrets/prod-cluster" || region != "ap-south-1" || kms != "alias/x" {
		t.Errorf("got %q %q %q", prefix, region, kms)
	}
	u, _ = url.Parse("awssm://?region=x")
	if _, _, _, err := parseURL(u); err == nil {
		t.Error("empty prefix should fail")
	}
	u, _ = url.Parse("awssm://p?bogus=1")
	if _, _, _, err := parseURL(u); err == nil {
		t.Error("unknown query parameter should fail")
	}
}

func TestOpenRegistersScheme(t *testing.T) {
	// Open constructs a real client from the default config; that must not call AWS.
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "x")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "y")
	if _, err := keybackup.Open(context.Background(), "awssm://p/q"); err != nil {
		t.Fatalf("Open: %v", err)
	}
}
```

- [x] **Step 3: Run tests to verify they fail**

Run: `go test ./pkg/keybackup/awssm/ 2>&1 | head -5`
Expected: build failure. The message is `no required module provides package
github.com/aws/aws-sdk-go-v2/aws`, not `undefined: NewWithClient`, because step 1's `go mod tidy`
dropped the still-unimported SDK modules. Either way the test does not compile, which is the point.

- [x] **Step 4: Write the implementation**

```go
// pkg/keybackup/awssm/awssm.go

// Package awssm is a keybackup provider that stores one AWS Secrets Manager
// secret per sealing key. URL form:
//
//	awssm://<prefix>[/<more prefix>]?region=<region>&kms-key-id=<key id or alias>
//
// Credentials come from the AWS default chain (IRSA, Pod Identity, env, profile).
package awssm

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/bitnami/sealed-secrets/pkg/keybackup"
)

// Scheme is the URL scheme this provider registers.
const Scheme = "awssm"

const (
	tagSecretName  = "sealed-secrets/secret-name"
	tagFingerprint = "sealed-secrets/fingerprint"
	tagManagedBy   = "sealed-secrets/managed-by"
	managedByValue = "sealed-secrets-controller"
)

// api is the subset of the Secrets Manager client the provider uses.
type api interface {
	CreateSecret(ctx context.Context, in *secretsmanager.CreateSecretInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	PutSecretValue(ctx context.Context, in *secretsmanager.PutSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
	DescribeSecret(ctx context.Context, in *secretsmanager.DescribeSecretInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error)
	TagResource(ctx context.Context, in *secretsmanager.TagResourceInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.TagResourceOutput, error)
}

// Store writes sealing keys to Secrets Manager under a name prefix.
type Store struct {
	client   api
	prefix   string
	kmsKeyID string
}

func init() {
	keybackup.Register(Scheme, open)
}

func open(ctx context.Context, u *url.URL) (keybackup.Store, error) {
	prefix, region, kmsKeyID, err := parseURL(u)
	if err != nil {
		return nil, err
	}
	var loadOpts []func(*config.LoadOptions) error
	if region != "" {
		loadOpts = append(loadOpts, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("awssm backup: load AWS config: %w", err)
	}
	return NewWithClient(secretsmanager.NewFromConfig(cfg), prefix, kmsKeyID), nil
}

// parseURL extracts prefix, region and kms key id. Unknown query keys are an error
// so that typos fail at startup rather than silently using defaults.
func parseURL(u *url.URL) (prefix, region, kmsKeyID string, err error) {
	prefix = strings.Trim(u.Host+u.Path, "/")
	if prefix == "" {
		return "", "", "", fmt.Errorf("awssm backup: URL %q has no name prefix", u.String())
	}
	for k := range u.Query() {
		switch k {
		case "region", "kms-key-id":
		default:
			return "", "", "", fmt.Errorf("awssm backup: unknown query parameter %q", k)
		}
	}
	return prefix, u.Query().Get("region"), u.Query().Get("kms-key-id"), nil
}

// NewWithClient returns a Store over an existing client. Tests use it with a fake.
func NewWithClient(client api, prefix, kmsKeyID string) *Store {
	return &Store{client: client, prefix: strings.Trim(prefix, "/"), kmsKeyID: kmsKeyID}
}

func (s *Store) name(fingerprint string) (string, error) {
	id, err := keybackup.SafeID(fingerprint)
	if err != nil {
		return "", err
	}
	return s.prefix + "/" + id, nil
}

func tags(b keybackup.Backup) []types.Tag {
	return []types.Tag{
		{Key: aws.String(tagSecretName), Value: aws.String(b.SecretName)},
		{Key: aws.String(tagFingerprint), Value: aws.String(b.Fingerprint)},
		{Key: aws.String(tagManagedBy), Value: aws.String(managedByValue)},
	}
}

// Put creates the secret, or replaces its value and refreshes tags if it already exists.
func (s *Store) Put(ctx context.Context, b keybackup.Backup) error {
	name, err := s.name(b.Fingerprint)
	if err != nil {
		return err
	}
	in := &secretsmanager.CreateSecretInput{
		Name:         aws.String(name),
		SecretBinary: b.Manifest,
		Description:  aws.String("sealed-secrets sealing key " + b.SecretName),
		Tags:         tags(b),
	}
	if s.kmsKeyID != "" {
		in.KmsKeyId = aws.String(s.kmsKeyID)
	}
	_, err = s.client.CreateSecret(ctx, in)
	var exists *types.ResourceExistsException
	switch {
	case err == nil:
		return nil
	case errors.As(err, &exists):
		if _, err := s.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{SecretId: aws.String(name), SecretBinary: b.Manifest}); err != nil {
			return fmt.Errorf("awssm backup: replace %s: %w", name, err)
		}
		if _, err := s.client.TagResource(ctx, &secretsmanager.TagResourceInput{SecretId: aws.String(name), Tags: tags(b)}); err != nil {
			return fmt.Errorf("awssm backup: tag %s: %w", name, err)
		}
		return nil
	default:
		return fmt.Errorf("awssm backup: create %s: %w", name, err)
	}
}

// Exists maps ResourceNotFoundException to false and any other error to an error.
func (s *Store) Exists(ctx context.Context, fingerprint string) (bool, error) {
	name, err := s.name(fingerprint)
	if err != nil {
		return false, err
	}
	_, err = s.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{SecretId: aws.String(name)})
	var notFound *types.ResourceNotFoundException
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &notFound):
		return false, nil
	default:
		return false, fmt.Errorf("awssm backup: describe %s: %w", name, err)
	}
}
```

Then run `go mod tidy` again. Now that the code imports them, it restores
`github.com/aws/aws-sdk-go-v2`, `.../config` and `.../service/secretsmanager` as direct
requirements in `go.mod`, which is the state step 1 described.

- [x] **Step 5: Run tests to verify they pass**

Run: `go test ./pkg/keybackup/... -v 2>&1 | grep -E "^(--- |ok|FAIL)"`
Expected: all PASS, three `ok` package lines.

- [x] **Step 6: Commit**

```bash
git add go.mod go.sum pkg/keybackup/awssm/
git commit -m "feat: add AWS Secrets Manager keybackup provider"
```

---

### Task 4: Secret manifest helpers in the controller

**Files:**
- Modify: `pkg/controller/keys.go:56-107` (`writeKey`)
- Test: `pkg/controller/keys_test.go`

**Interfaces:**
- Produces:
  ```go
  func buildKeySecret(key *rsa.PrivateKey, certs []*x509.Certificate, namespace, krLabel, prefix, additionalAnnotations, additionalLabels string, optSetters ...writeKeyOpt) *v1.Secret
  func keySecretManifest(s *v1.Secret) ([]byte, error)
  ```
  `writeKey` keeps its signature and now calls `buildKeySecret` then `Create`.

- [x] **Step 1: Write the failing tests** (append to `pkg/controller/keys_test.go`)

```go
func TestBuildKeySecretMatchesWriteKey(t *testing.T) {
	rand := testRand()
	key, _ := rsa.GenerateKey(rand, 2048)
	cert, _ := signKey(rand, key)
	s := buildKeySecret(key, []*x509.Certificate{cert}, "ns", SealedSecretsKeyLabel, "prefix", "a=1", "b=2")
	if s.GenerateName != "prefix" || s.Name != "" || s.Namespace != "ns" {
		t.Errorf("metadata = %+v", s.ObjectMeta)
	}
	if s.Labels[SealedSecretsKeyLabel] != "active" || s.Labels["b"] != "2" || s.Annotations["a"] != "1" {
		t.Errorf("labels/annotations = %v %v", s.Labels, s.Annotations)
	}
	if s.Type != v1.SecretTypeTLS || len(s.Data[v1.TLSPrivateKeyKey]) == 0 || len(s.Data[v1.TLSCertKey]) == 0 {
		t.Errorf("data/type wrong")
	}
	gotKey, gotCerts, err := readKey(s)
	if err != nil || gotKey.N.Cmp(key.N) != 0 || len(gotCerts) != 1 {
		t.Errorf("round trip failed: %v", err)
	}
}

func TestKeySecretManifestStripsServerFields(t *testing.T) {
	rand := testRand()
	key, _ := rsa.GenerateKey(rand, 2048)
	cert, _ := signKey(rand, key)
	s := buildKeySecret(key, []*x509.Certificate{cert}, "ns", SealedSecretsKeyLabel, "prefix", "", "")
	s.Name = "prefixabcde"
	s.GenerateName = ""
	s.ResourceVersion = "123"
	s.UID = "uid-1"
	s.SelfLink = "/x"
	s.CreationTimestamp = metav1.Now()
	s.ManagedFields = []metav1.ManagedFieldsEntry{{Manager: "m"}}

	raw, err := keySecretManifest(s)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["apiVersion"] != "v1" || m["kind"] != "Secret" {
		t.Errorf("type meta missing: %v %v", m["apiVersion"], m["kind"])
	}
	md := m["metadata"].(map[string]interface{})
	if md["name"] != "prefixabcde" || md["namespace"] != "ns" {
		t.Errorf("metadata = %v", md)
	}
	for _, f := range []string{"resourceVersion", "uid", "selfLink", "managedFields"} {
		if _, present := md[f]; present {
			t.Errorf("%s should be stripped", f)
		}
	}
	if ts, present := md["creationTimestamp"]; present && ts != nil {
		t.Errorf("creationTimestamp should be cleared, got %v", ts)
	}
	// The original object must not be mutated.
	if s.ResourceVersion != "123" {
		t.Error("keySecretManifest mutated its input")
	}
	// And the manifest must decode back to a Secret holding the same key.
	var back v1.Secret
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	gotKey, _, err := readKey(&back)
	if err != nil || gotKey.N.Cmp(key.N) != 0 {
		t.Errorf("manifest does not round trip the key: %v", err)
	}
}
```

Add `"encoding/json"` to the test file imports.

- [x] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/controller/ -run 'TestBuildKeySecret|TestKeySecretManifest' 2>&1 | head -5`
Expected: build failure, `undefined: buildKeySecret`.

- [x] **Step 3: Refactor `writeKey` and add `keySecretManifest`**

Replace the body of `writeKey` in `pkg/controller/keys.go` (lines 56 to 107) with:

```go
// buildKeySecret assembles the Secret that holds a sealing key pair, without creating it.
func buildKeySecret(key *rsa.PrivateKey, certs []*x509.Certificate, namespace, krLabel, prefix string, additionalAnnotations string, additionalLabels string, optSetters ...writeKeyOpt) *v1.Secret {
	var opts writeKeyOpts
	for _, o := range optSetters {
		o(&opts)
	}

	certbytes := []byte{}
	for _, cert := range certs {
		certbytes = append(certbytes, pem.EncodeToMemory(&pem.Block{Type: certUtil.CertificateBlockType, Bytes: cert.Raw})...)
	}

	labels := map[string]string{
		krLabel: "active",
	}

	annotations := map[string]string{}

	if additionalLabels != "" {
		for _, label := range removeDuplicates(strings.Split(additionalLabels, ",")) {
			key := strings.Split(label, "=")[0]
			value := strings.Split(label, "=")[1]
			if key != krLabel {
				labels[key] = value
			}
		}
	}

	if additionalAnnotations != "" {
		for _, label := range removeDuplicates(strings.Split(additionalAnnotations, ",")) {
			key := strings.Split(label, "=")[0]
			value := strings.Split(label, "=")[1]
			annotations[key] = value
		}
	}

	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         namespace,
			GenerateName:      prefix,
			Labels:            labels,
			Annotations:       annotations,
			CreationTimestamp: opts.creationTime,
		},
		Data: map[string][]byte{
			v1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{Type: keyutil.RSAPrivateKeyBlockType, Bytes: x509.MarshalPKCS1PrivateKey(key)}),
			v1.TLSCertKey:       certbytes,
		},
		Type: v1.SecretTypeTLS,
	}
}

func writeKey(ctx context.Context, client kubernetes.Interface, key *rsa.PrivateKey, certs []*x509.Certificate, namespace, krLabel, prefix string, additionalAnnotations string, additionalLabels string, optSetters ...writeKeyOpt) (string, error) {
	secret := buildKeySecret(key, certs, namespace, krLabel, prefix, additionalAnnotations, additionalLabels, optSetters...)
	createdSecret, err := client.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}
	return createdSecret.Name, nil
}

// keySecretManifest serializes a copy of s as a Secret manifest that can be applied
// into a fresh cluster: type meta set, server-populated fields cleared. The returned
// bytes contain the private key and must never be logged.
func keySecretManifest(s *v1.Secret) ([]byte, error) {
	c := s.DeepCopy()
	c.APIVersion = "v1"
	c.Kind = "Secret"
	c.ResourceVersion = ""
	c.UID = ""
	c.SelfLink = ""
	c.CreationTimestamp = metav1.Time{}
	c.ManagedFields = nil
	c.Generation = 0
	return json.Marshal(c)
}
```

Add `"encoding/json"` to the imports of `pkg/controller/keys.go`.

- [x] **Step 4: Run the whole controller package**

Run: `go test ./pkg/controller/ 2>&1 | tail -3`
Expected: `ok`. `TestWriteKey` still passes because `writeKey` behaviour is unchanged.

- [x] **Step 5: Commit**

```bash
git add pkg/controller/keys.go pkg/controller/keys_test.go
git commit -m "feat: extract key secret builder and manifest serializer"
```

---

### Task 5: metrics and the backup-aware key generation path

**Files:**
- Create: `pkg/controller/keybackup_metrics.go`
- Modify: `pkg/controller/keyregistry.go:26-67`
- Test: `pkg/controller/keyregistry_backup_test.go`

**Interfaces:**
- Consumes: `keybackup.Store`, `buildKeySecret`, `keySecretManifest`
- Produces:
  ```go
  // keyregistry.go
  type KeyRegistry struct { ...; backup keybackup.Store; unbacked map[string]struct{} }
  func (kr *KeyRegistry) SetBackupStore(s keybackup.Store)
  const keyBackupTimeout = 30 * time.Second
  const keyNameAttempts = 5
  // keybackup_metrics.go
  var keyBackupTotal *prometheus.CounterVec           // label "result"
  var keyBackupLastSuccess prometheus.Gauge
  var keyBackupUnbackedKeys prometheus.Gauge
  func registerKeyBackupMetrics()
  func (kr *KeyRegistry) markUnbacked(fingerprint string)
  func (kr *KeyRegistry) markBacked(fingerprint string)
  ```

- [x] **Step 1: Write the metrics file**

```go
// pkg/controller/keybackup_metrics.go
package controller

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	keyBackupResultSuccess = "success"
	keyBackupResultFailure = "failure"
	keyBackupResultSkipped = "skipped"
)

var (
	keyBackupTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricNamespace,
			Name:      "key_backup_total",
			Help:      "Sealing key backup attempts by result (success, failure, skipped).",
		},
		[]string{"result"},
	)
	keyBackupLastSuccess = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Name:      "key_backup_last_success_timestamp_seconds",
			Help:      "Unix time of the last successful sealing key backup.",
		},
	)
	keyBackupUnbackedKeys = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricNamespace,
			Name:      "key_backup_unbacked_keys",
			Help:      "Registered sealing keys with no confirmed backup. Zero is healthy.",
		},
	)
)

// registerKeyBackupMetrics is called once from Main, only when backup is enabled.
func registerKeyBackupMetrics() {
	prometheus.MustRegister(keyBackupTotal, keyBackupLastSuccess, keyBackupUnbackedKeys)
}

func observeKeyBackupSuccess() {
	keyBackupTotal.WithLabelValues(keyBackupResultSuccess).Inc()
	keyBackupLastSuccess.Set(float64(time.Now().Unix()))
}
```

- [x] **Step 2: Write the failing tests**

```go
// pkg/controller/keyregistry_backup_test.go
package controller

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/bitnami/sealed-secrets/pkg/keybackup"
)

// fakeStore records Puts and can be told to fail or to report entries as existing.
type fakeStore struct {
	mu        sync.Mutex
	puts      []keybackup.Backup
	putErr    error
	existing  map[string]bool
	existsErr error
	onPut     func(b keybackup.Backup) // called before recording, used to inspect state at Put time
}

func newFakeStore() *fakeStore { return &fakeStore{existing: map[string]bool{}} }

func (f *fakeStore) Put(_ context.Context, b keybackup.Backup) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.onPut != nil {
		f.onPut(b)
	}
	if f.putErr != nil {
		return f.putErr
	}
	f.puts = append(f.puts, b)
	f.existing[b.Fingerprint] = true
	return nil
}

func (f *fakeStore) Exists(_ context.Context, fp string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.existsErr != nil {
		return false, f.existsErr
	}
	return f.existing[fp], nil
}

func (f *fakeStore) putCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.puts)
}

func newTestRegistry(t *testing.T, client *fake.Clientset, store keybackup.Store) *KeyRegistry {
	t.Helper()
	kr := NewKeyRegistry(client, "ns", "prefix", SealedSecretsKeyLabel, 1024)
	if store != nil {
		kr.SetBackupStore(store)
	}
	return kr
}

func createdSecrets(client *fake.Clientset) []*v1.Secret {
	var out []*v1.Secret
	for _, a := range client.Actions() {
		if a.Matches("create", "secrets") {
			out = append(out, a.(ktesting.CreateAction).GetObject().(*v1.Secret))
		}
	}
	return out
}

func TestGenerateKeyBackupDisabledUsesGenerateName(t *testing.T) {
	client := fake.NewClientset()
	client.PrependReactor("create", "secrets", generateNameReactor)
	kr := newTestRegistry(t, client, nil)
	if _, err := kr.generateKey(context.Background(), time.Hour, "cn", "", ""); err != nil {
		t.Fatal(err)
	}
	cs := createdSecrets(client)
	if len(cs) != 1 || cs[0].GenerateName != "prefix" {
		t.Fatalf("expected one create with GenerateName, got %+v", cs)
	}
}

func TestGenerateKeyBackupPutBeforeCreate(t *testing.T) {
	client := fake.NewClientset()
	store := newFakeStore()
	var createsAtPut int
	store.onPut = func(keybackup.Backup) { createsAtPut = len(createdSecrets(client)) }
	kr := newTestRegistry(t, client, store)

	name, err := kr.generateKey(context.Background(), time.Hour, "cn", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if createsAtPut != 0 {
		t.Error("Secret was created before Put")
	}
	if store.putCount() != 1 {
		t.Fatalf("puts = %d, want 1", store.putCount())
	}
	b := store.puts[0]
	if b.SecretName != name || len(name) != len("prefix")+5 || name[:6] != "prefix" {
		t.Errorf("SecretName = %q, generated name = %q", b.SecretName, name)
	}
	cs := createdSecrets(client)
	if len(cs) != 1 || cs[0].Name != name || cs[0].GenerateName != "" {
		t.Errorf("created secret metadata = %+v", cs[0].ObjectMeta)
	}
	var m v1.Secret
	if err := json.Unmarshal(b.Manifest, &m); err != nil || m.Name != name || m.Kind != "Secret" {
		t.Errorf("manifest does not carry the created name: %v %q", err, m.Name)
	}
	if kr.keyLen() != 1 {
		t.Errorf("registry has %d keys, want 1", kr.keyLen())
	}
	if b.Fingerprint == "" || b.CreatedAt.IsZero() {
		t.Errorf("fingerprint/createdAt not set: %+v", b)
	}
	if got := testutil.ToFloat64(keyBackupTotal.WithLabelValues(keyBackupResultSuccess)); got < 1 {
		t.Errorf("success counter = %v", got)
	}
}

func TestGenerateKeyBackupFailureCreatesNothing(t *testing.T) {
	client := fake.NewClientset()
	store := newFakeStore()
	store.putErr = errors.New("store down")
	kr := newTestRegistry(t, client, store)
	before := testutil.ToFloat64(keyBackupTotal.WithLabelValues(keyBackupResultFailure))
	keyBackupUnbackedKeys.Set(0) // shared gauge; other tests may have left it nonzero

	_, err := kr.generateKey(context.Background(), time.Hour, "cn", "", "")
	if err == nil || !errors.Is(err, store.putErr) {
		t.Fatalf("err = %v, want wrapped store error", err)
	}
	if len(createdSecrets(client)) != 0 {
		t.Error("Secret must not be created when backup fails")
	}
	if kr.keyLen() != 0 {
		t.Error("registry must stay empty when backup fails")
	}
	if got := testutil.ToFloat64(keyBackupTotal.WithLabelValues(keyBackupResultFailure)); got != before+1 {
		t.Errorf("failure counter = %v, want %v", got, before+1)
	}
	if got := testutil.ToFloat64(keyBackupUnbackedKeys); got != 0 {
		t.Errorf("unbacked gauge = %v, want 0 (key never existed)", got)
	}
}

func TestGenerateKeyNameCollisionRetries(t *testing.T) {
	client := fake.NewClientset()
	first := true
	client.PrependReactor("create", "secrets", func(action ktesting.Action) (bool, runtime.Object, error) {
		if first {
			first = false
			name := action.(ktesting.CreateAction).GetObject().(*v1.Secret).Name
			return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, name)
		}
		return false, nil, nil
	})
	store := newFakeStore()
	kr := newTestRegistry(t, client, store)

	name, err := kr.generateKey(context.Background(), time.Hour, "cn", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if store.putCount() != 2 {
		t.Fatalf("puts = %d, want 2 (one per name attempt)", store.putCount())
	}
	if store.puts[0].SecretName == store.puts[1].SecretName {
		t.Error("second attempt must use a different name")
	}
	if store.puts[1].SecretName != name {
		t.Errorf("last Put name %q != created name %q", store.puts[1].SecretName, name)
	}
	if store.puts[0].Fingerprint != store.puts[1].Fingerprint {
		t.Error("both attempts must share the fingerprint so the entry is replaced, not duplicated")
	}
}

func TestGenerateKeyGivesUpAfterMaxAttempts(t *testing.T) {
	client := fake.NewClientset()
	client.PrependReactor("create", "secrets", func(action ktesting.Action) (bool, runtime.Object, error) {
		name := action.(ktesting.CreateAction).GetObject().(*v1.Secret).Name
		return true, nil, apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, name)
	})
	kr := newTestRegistry(t, client, newFakeStore())
	if _, err := kr.generateKey(context.Background(), time.Hour, "cn", "", ""); !apierrors.IsAlreadyExists(err) {
		t.Fatalf("err = %v, want AlreadyExists after %d attempts", err, keyNameAttempts)
	}
	if kr.keyLen() != 0 {
		t.Error("registry must stay empty")
	}
}
```

- [x] **Step 3: Run tests to verify they fail**

Run: `go test ./pkg/controller/ -run 'TestGenerateKey' 2>&1 | head -5`
Expected: build failure, `kr.SetBackupStore undefined`.

- [x] **Step 4: Implement in `keyregistry.go`**

Add to the imports: `"errors"` is not needed; add `"github.com/bitnami/sealed-secrets/pkg/keybackup"`, `apierrors "k8s.io/apimachinery/pkg/api/errors"`, `krand "k8s.io/apimachinery/pkg/util/rand"`.

Add constants after the imports:

```go
const (
	// keyBackupTimeout bounds a single Store.Put or Exists call.
	keyBackupTimeout = 30 * time.Second
	// keyNameAttempts bounds retries when a controller-chosen Secret name already exists.
	keyNameAttempts = 5
	// keyNameSuffixLen matches the API server's GenerateName suffix length.
	keyNameSuffixLen = 5
)
```

Extend the struct and constructor:

```go
type KeyRegistry struct {
	mu            sync.RWMutex
	client        kubernetes.Interface
	namespace     string
	keyPrefix     string
	keyLabel      string
	keysize       int
	keys          map[string]*Key
	mostRecentKey *Key
	backup        keybackup.Store     // nil when backup is disabled.
	unbacked      map[string]struct{} // fingerprints of live keys with no confirmed backup.
}
```

In `NewKeyRegistry` add `unbacked: map[string]struct{}{},` to the literal.

Add after `NewKeyRegistry`:

```go
// SetBackupStore enables fail-closed backup of newly generated keys.
func (kr *KeyRegistry) SetBackupStore(s keybackup.Store) {
	kr.backup = s
}

func (kr *KeyRegistry) markUnbacked(fingerprint string) {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	kr.unbacked[fingerprint] = struct{}{}
	keyBackupUnbackedKeys.Set(float64(len(kr.unbacked)))
}

func (kr *KeyRegistry) markBacked(fingerprint string) {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	delete(kr.unbacked, fingerprint)
	keyBackupUnbackedKeys.Set(float64(len(kr.unbacked)))
}
```

Replace `generateKey` with:

```go
func (kr *KeyRegistry) generateKey(ctx context.Context, validFor time.Duration, cn string, privateKeyAnnotations string, privateKeyLabels string) (string, error) {
	key, cert, err := generatePrivateKeyAndCert(kr.keysize, validFor, cn)
	if err != nil {
		return "", err
	}
	certs := []*x509.Certificate{cert}

	var generatedName string
	if kr.backup == nil {
		generatedName, err = writeKey(ctx, kr.client, key, certs, kr.namespace, kr.keyLabel, kr.keyPrefix, privateKeyAnnotations, privateKeyLabels)
	} else {
		generatedName, err = kr.writeKeyWithBackup(ctx, key, certs, privateKeyAnnotations, privateKeyLabels)
	}
	if err != nil {
		return "", err
	}
	// Only store key to local store if write to k8s worked
	if err := kr.registerNewKey(generatedName, key, cert, time.Now()); err != nil {
		return "", err
	}
	slog.Info("New key written", "namespace", kr.namespace, "name", generatedName)
	slog.Info("Certificate generated", "certificate", pem.EncodeToMemory(&pem.Block{Type: certUtil.CertificateBlockType, Bytes: cert.Raw}))
	return generatedName, nil
}

// writeKeyWithBackup chooses the Secret name itself, stores the backup, and only then
// creates the Secret. A failed backup means no Secret is created.
func (kr *KeyRegistry) writeKeyWithBackup(ctx context.Context, key *rsa.PrivateKey, certs []*x509.Certificate, privateKeyAnnotations, privateKeyLabels string) (string, error) {
	fingerprint, err := crypto.PublicKeyFingerprint(&key.PublicKey)
	if err != nil {
		return "", err
	}
	secret := buildKeySecret(key, certs, kr.namespace, kr.keyLabel, kr.keyPrefix, privateKeyAnnotations, privateKeyLabels)
	secret.GenerateName = ""

	var lastErr error
	for attempt := 0; attempt < keyNameAttempts; attempt++ {
		secret.Name = kr.keyPrefix + krand.String(keyNameSuffixLen)
		manifest, err := keySecretManifest(secret)
		if err != nil {
			return "", err
		}
		b := keybackup.Backup{Fingerprint: fingerprint, SecretName: secret.Name, Manifest: manifest, CreatedAt: certs[0].NotBefore}
		putCtx, cancel := context.WithTimeout(ctx, keyBackupTimeout)
		err = kr.backup.Put(putCtx, b)
		cancel()
		if err != nil {
			keyBackupTotal.WithLabelValues(keyBackupResultFailure).Inc()
			slog.Error("Sealing key backup failed; key not created", "name", secret.Name, "fingerprint", fingerprint, "error", err)
			return "", fmt.Errorf("backup of new sealing key: %w", err)
		}
		observeKeyBackupSuccess()

		created, err := kr.client.CoreV1().Secrets(kr.namespace).Create(ctx, secret, metav1.CreateOptions{})
		if err == nil {
			slog.Info("Sealing key backed up", "name", created.Name, "fingerprint", fingerprint)
			return created.Name, nil
		}
		if !apierrors.IsAlreadyExists(err) {
			return "", err
		}
		lastErr = err
		slog.Warn("Sealing key name already exists, retrying with a new name", "name", secret.Name)
	}
	return "", lastErr
}
```

Add `metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"` to imports.

- [x] **Step 5: Run the tests**

Run: `go test ./pkg/controller/ 2>&1 | tail -3`
Expected: `ok`. All five new tests and every pre-existing test pass.

- [x] **Step 6: Vet and commit**

Run: `go vet ./pkg/controller/ && gofmt -l pkg/controller/` (expect no output from gofmt).

```bash
git add pkg/controller/keybackup_metrics.go pkg/controller/keyregistry.go pkg/controller/keyregistry_backup_test.go
git commit -m "feat: back up new sealing keys before creating them"
```

---

### Task 6: reconcile existing keys and hook the key informer

**Files:**
- Create: `pkg/controller/keybackup.go`
- Modify: `pkg/controller/controller.go:135-148` (`watchKeySecrets` AddFunc)
- Test: `pkg/controller/keybackup_test.go`

**Interfaces:**
- Consumes: `KeyRegistry.backup`, `markUnbacked`, `markBacked`, `keySecretManifest`, `readKey`, `crypto.PublicKeyFingerprint`
- Produces:
  ```go
  // backupKeySecret ensures one live key Secret has a store entry. Best effort: returns the error but callers only log it.
  func (kr *KeyRegistry) backupKeySecret(ctx context.Context, secret *v1.Secret) error
  // reconcileKeyBackups runs backupKeySecret over every labeled key Secret in the namespace.
  func (kr *KeyRegistry) reconcileKeyBackups(ctx context.Context)
  ```

- [ ] **Step 1: Write the failing tests**

```go
// pkg/controller/keybackup_test.go
package controller

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/bitnami/sealed-secrets/pkg/crypto"
)

// keySecretFixture creates a labeled key Secret in the fake cluster and returns it with its fingerprint.
func keySecretFixture(t *testing.T, client *fake.Clientset, name string) (*v1.Secret, string) {
	t.Helper()
	rand := testRand()
	key, err := rsa.GenerateKey(rand, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := signKey(rand, key)
	if err != nil {
		t.Fatal(err)
	}
	s := buildKeySecret(key, []*x509.Certificate{cert}, "ns", SealedSecretsKeyLabel, "prefix", "", "")
	s.GenerateName = ""
	s.Name = name
	created, err := client.CoreV1().Secrets("ns").Create(context.Background(), s, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fp, _ := crypto.PublicKeyFingerprint(&key.PublicKey)
	return created, fp
}

func TestBackupKeySecretPutsWhenMissing(t *testing.T) {
	client := fake.NewClientset()
	store := newFakeStore()
	kr := newTestRegistry(t, client, store)
	s, fp := keySecretFixture(t, client, "prefixaaaaa")

	if err := kr.backupKeySecret(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if store.putCount() != 1 || store.puts[0].Fingerprint != fp || store.puts[0].SecretName != "prefixaaaaa" {
		t.Fatalf("puts = %+v", store.puts)
	}
	if got := testutil.ToFloat64(keyBackupUnbackedKeys); got != 0 {
		t.Errorf("unbacked = %v, want 0", got)
	}
}

func TestBackupKeySecretSkipsWhenPresent(t *testing.T) {
	client := fake.NewClientset()
	store := newFakeStore()
	kr := newTestRegistry(t, client, store)
	s, fp := keySecretFixture(t, client, "prefixbbbbb")
	store.existing[fp] = true
	before := testutil.ToFloat64(keyBackupTotal.WithLabelValues(keyBackupResultSkipped))

	if err := kr.backupKeySecret(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if store.putCount() != 0 {
		t.Error("must not Put when Exists is true")
	}
	if got := testutil.ToFloat64(keyBackupTotal.WithLabelValues(keyBackupResultSkipped)); got != before+1 {
		t.Errorf("skipped counter = %v, want %v", got, before+1)
	}
}

func TestBackupKeySecretFailureMarksUnbacked(t *testing.T) {
	client := fake.NewClientset()
	store := newFakeStore()
	store.putErr = errors.New("down")
	kr := newTestRegistry(t, client, store)
	s, fp := keySecretFixture(t, client, "prefixccccc")

	if err := kr.backupKeySecret(context.Background(), s); err == nil {
		t.Fatal("expected error")
	}
	if got := testutil.ToFloat64(keyBackupUnbackedKeys); got != 1 {
		t.Errorf("unbacked = %v, want 1", got)
	}
	// Recovery: the next successful backup clears it.
	store.putErr = nil
	if err := kr.backupKeySecret(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(keyBackupUnbackedKeys); got != 0 {
		t.Errorf("unbacked after recovery = %v, want 0", got)
	}
	if _, still := kr.unbacked[fp]; still {
		t.Error("fingerprint still marked unbacked")
	}
}

func TestBackupKeySecretNoopWhenDisabled(t *testing.T) {
	client := fake.NewClientset()
	kr := newTestRegistry(t, client, nil)
	s, _ := keySecretFixture(t, client, "prefixddddd")
	if err := kr.backupKeySecret(context.Background(), s); err != nil {
		t.Fatalf("disabled backup must be a no-op, got %v", err)
	}
}

func TestReconcileKeyBackups(t *testing.T) {
	client := fake.NewClientset()
	store := newFakeStore()
	kr := newTestRegistry(t, client, store)
	_, fp1 := keySecretFixture(t, client, "prefix11111")
	_, _ = keySecretFixture(t, client, "prefix22222")
	store.existing[fp1] = true

	kr.reconcileKeyBackups(context.Background())

	if store.putCount() != 1 || store.puts[0].SecretName != "prefix22222" {
		t.Fatalf("expected exactly one Put for the missing key, got %+v", store.puts)
	}
	if got := testutil.ToFloat64(keyBackupUnbackedKeys); got != 0 {
		t.Errorf("unbacked = %v, want 0", got)
	}
}

func TestReconcileKeyBackupsContinuesAfterFailure(t *testing.T) {
	client := fake.NewClientset()
	store := newFakeStore()
	store.existsErr = errors.New("describe failed")
	kr := newTestRegistry(t, client, store)
	_, _ = keySecretFixture(t, client, "prefix33333")
	_, _ = keySecretFixture(t, client, "prefix44444")

	kr.reconcileKeyBackups(context.Background()) // must not panic or return early

	if got := testutil.ToFloat64(keyBackupUnbackedKeys); got != 2 {
		t.Errorf("unbacked = %v, want 2", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./pkg/controller/ -run 'TestBackupKeySecret|TestReconcile' 2>&1 | head -5`
Expected: build failure, `kr.backupKeySecret undefined`.

- [ ] **Step 3: Write `pkg/controller/keybackup.go`**

```go
package controller

import (
	"context"
	"fmt"
	"log/slog"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/bitnami/sealed-secrets/pkg/crypto"
	"github.com/bitnami/sealed-secrets/pkg/keybackup"
)

// backupKeySecret ensures a key Secret that already exists in the cluster has an
// entry in the backup store. It is best effort: the caller logs the returned error
// and carries on, because the key is already live.
func (kr *KeyRegistry) backupKeySecret(ctx context.Context, secret *v1.Secret) error {
	if kr.backup == nil {
		return nil
	}
	key, certs, err := readKey(secret)
	if err != nil {
		return fmt.Errorf("read key %s: %w", secret.Name, err)
	}
	fingerprint, err := crypto.PublicKeyFingerprint(&key.PublicKey)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, keyBackupTimeout)
	defer cancel()

	exists, err := kr.backup.Exists(ctx, fingerprint)
	if err != nil {
		kr.markUnbacked(fingerprint)
		keyBackupTotal.WithLabelValues(keyBackupResultFailure).Inc()
		return fmt.Errorf("check backup of %s: %w", secret.Name, err)
	}
	if exists {
		kr.markBacked(fingerprint)
		keyBackupTotal.WithLabelValues(keyBackupResultSkipped).Inc()
		return nil
	}

	manifest, err := keySecretManifest(secret)
	if err != nil {
		return err
	}
	b := keybackup.Backup{Fingerprint: fingerprint, SecretName: secret.Name, Manifest: manifest}
	if len(certs) > 0 {
		b.CreatedAt = certs[0].NotBefore
	}
	if err := kr.backup.Put(ctx, b); err != nil {
		kr.markUnbacked(fingerprint)
		keyBackupTotal.WithLabelValues(keyBackupResultFailure).Inc()
		return fmt.Errorf("backup of %s: %w", secret.Name, err)
	}
	kr.markBacked(fingerprint)
	observeKeyBackupSuccess()
	slog.Info("Existing sealing key backed up", "name", secret.Name, "fingerprint", fingerprint)
	return nil
}

// reconcileKeyBackups backs up every labeled key Secret in the registry's namespace
// that has no store entry yet. Failures are logged and skipped.
func (kr *KeyRegistry) reconcileKeyBackups(ctx context.Context) {
	if kr.backup == nil {
		return
	}
	list, err := kr.client.CoreV1().Secrets(kr.namespace).List(ctx, metav1.ListOptions{LabelSelector: keySelector.String()})
	if err != nil {
		slog.Error("Failed to list sealing keys for backup reconcile", "error", err)
		return
	}
	for i := range list.Items {
		if err := kr.backupKeySecret(ctx, &list.Items[i]); err != nil {
			slog.Error("Sealing key backup reconcile failed", "name", list.Items[i].Name, "error", err)
		}
	}
}
```

- [ ] **Step 4: Hook the informer** in `pkg/controller/controller.go`, inside `watchKeySecrets`, `AddFunc` (line 138 to 148). After the successful `registryNewKeyWithSecret` call, add:

```go
			if err := registry.backupKeySecret(context.Background(), secret); err != nil {
				slog.Error("Backup of externally added sealing key failed", "secret", secret.Name, "error", err)
			}
```

so the handler reads:

```go
		AddFunc: func(obj interface{}) {
			secret, ok := obj.(*corev1.Secret)
			if !ok {
				return
			}
			err := registryNewKeyWithSecret(secret, registry, keyOrderPriority)
			if err != nil {
				slog.Error("failed to register key", "secret", secret.Name, "error", err)
				return
			}
			if err := registry.backupKeySecret(context.Background(), secret); err != nil {
				slog.Error("Backup of externally added sealing key failed", "secret", secret.Name, "error", err)
			}
		},
```

Confirm `"context"` is already imported in `controller.go` (it is, for `AttemptUnseal`); if not, add it.

- [ ] **Step 5: Run the tests**

Run: `go test ./pkg/controller/ 2>&1 | tail -3`
Expected: `ok`.

- [ ] **Step 6: Commit**

```bash
git add pkg/controller/keybackup.go pkg/controller/keybackup_test.go pkg/controller/controller.go
git commit -m "feat: reconcile existing sealing keys into the backup store"
```

---

### Task 7: wire the flag, open the store, register providers

**Files:**
- Modify: `pkg/controller/main.go:44-72` (`Flags`), `pkg/controller/main.go:189-238` (`Main`)
- Modify: `cmd/controller/main.go:1-20` (imports), `cmd/controller/main.go:32-70` (`bindControllerFlags`)
- Test: `cmd/controller/main_test.go`

**Interfaces:**
- Consumes: `keybackup.Open`, `KeyRegistry.SetBackupStore`, `reconcileKeyBackups`, `registerKeyBackupMetrics`
- Produces: `Flags.KeyBackupURL string`, flag `--key-backup-url`, env `SEALED_SECRETS_KEY_BACKUP_URL`

- [ ] **Step 1: Write the failing test** (append to `cmd/controller/main_test.go`; keep the existing imports and add `"github.com/bitnami/sealed-secrets/pkg/controller"` and `flag "github.com/spf13/pflag"` if not present)

```go
func TestKeyBackupURLFlagAndEnv(t *testing.T) {
	var f controller.Flags
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	bindControllerFlags(&f, fs)
	if err := fs.Parse([]string{"--key-backup-url=file:///tmp/x"}); err != nil {
		t.Fatal(err)
	}
	if f.KeyBackupURL != "file:///tmp/x" {
		t.Errorf("flag not bound: %q", f.KeyBackupURL)
	}

	var g controller.Flags
	fs2 := flag.NewFlagSet("test2", flag.ContinueOnError)
	gofs := goflag.NewFlagSet("gotest2", goflag.ContinueOnError)
	t.Setenv("SEALED_SECRETS_KEY_BACKUP_URL", "awssm://p?region=r")
	bindFlags(&g, fs2, gofs)
	if err := fs2.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if g.KeyBackupURL != "awssm://p?region=r" {
		t.Errorf("env not bound: %q", g.KeyBackupURL)
	}
}
```

Add `goflag "flag"` to the test imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/controller/ -run TestKeyBackupURLFlagAndEnv 2>&1 | head -5`
Expected: build failure, `f.KeyBackupURL undefined`.

- [ ] **Step 3: Add the field and flag**

In `pkg/controller/main.go`, add to `Flags` after `KubeClientBurst int`:

```go
	KeyBackupURL            string
```

In `cmd/controller/main.go`, in `bindControllerFlags` after the `watch-for-secrets` line:

```go
	fs.StringVar(&f.KeyBackupURL, "key-backup-url", "", "URL of an external store that receives a copy of every sealing key before it is created (for example awssm://prefix?region=ap-south-1&kms-key-id=alias/x, or file:///dir). Empty disables backup.")
```

In `cmd/controller/main.go` imports, add the providers for their registration side effect:

```go
	_ "github.com/bitnami/sealed-secrets/pkg/keybackup/awssm"
	_ "github.com/bitnami/sealed-secrets/pkg/keybackup/file"
```

- [ ] **Step 4: Open the store in `Main`**

In `pkg/controller/main.go`, `Main`, replace the block from `keyRegistry, err := initKeyRegistry(...)` through its `if err != nil { return err }` with:

```go
	var backupStore keybackup.Store
	if f.KeyBackupURL != "" {
		backupStore, err = keybackup.Open(ctx, f.KeyBackupURL)
		if err != nil {
			return fmt.Errorf("key backup: %w", err)
		}
		registerKeyBackupMetrics()
		slog.Info("Sealing key backup enabled", "url", redactURL(f.KeyBackupURL))
	}

	keyRegistry, err := initKeyRegistry(ctx, clientset, rand.Reader, myNs, prefix, SealedSecretsKeyLabel, f.KeySize, f.KeyOrderPriority)
	if err != nil {
		return err
	}
	if backupStore != nil {
		keyRegistry.SetBackupStore(backupStore)
		keyRegistry.reconcileKeyBackups(ctx)
	}
```

Add `"github.com/bitnami/sealed-secrets/pkg/keybackup"` and `"net/url"` to the imports, and add this helper at the bottom of `main.go`:

```go
// redactURL strips query values from a backup URL before logging, so a future
// provider that accepts credentials in the query never leaks them.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<unparseable>"
	}
	q := u.Query()
	for k := range q {
		q.Set(k, "…")
	}
	u.RawQuery = q.Encode()
	return u.String()
}
```

Order matters: `Open` happens before `initKeyRegistry` so a bad URL fails before any key work; `SetBackupStore` happens before `initKeyRenewal` (which may generate the first key) so that first key is backed up.

- [ ] **Step 5: Build and test everything**

Run: `go build ./... && go test ./cmd/controller/ ./pkg/controller/ ./pkg/keybackup/... 2>&1 | tail -6`
Expected: all `ok`.

- [ ] **Step 6: Commit**

```bash
git add cmd/controller/main.go cmd/controller/main_test.go pkg/controller/main.go
git commit -m "feat: add --key-backup-url flag and wire the backup store"
```

---

### Task 8: Helm chart

**Files:**
- Modify: `helm/sealed-secrets/values.yaml:90` (after `keycutofftime`)
- Modify: `helm/sealed-secrets/templates/deployment.yaml:95` (after the `keycutofftime` block)
- Modify: `helm/sealed-secrets/README.md:101` (after the `keycutofftime` row)

- [ ] **Step 1: Add the value**

In `values.yaml`, directly after the `keycutofftime: ""` line:

```yaml
## @param keyBackup.url URL of an external store that receives a copy of every sealing key before it is created. Empty disables backup.
## e.g. awssm://sealed-secrets/prod?region=ap-south-1&kms-key-id=alias/sealed-secrets
## Cloud credentials bind through serviceAccount.annotations (IRSA on EKS). See docs/key-backup.md.
##
keyBackup:
  url: ""
```

- [ ] **Step 2: Render the flag**

In `templates/deployment.yaml`, directly after the `{{- end }}` that closes the `keycutofftime` block:

```yaml
            {{- if .Values.keyBackup.url }}
            - --key-backup-url
            - {{ .Values.keyBackup.url | quote }}
            {{- end }}
```

- [ ] **Step 3: Document the parameter**

In `helm/sealed-secrets/README.md`, add a row after `keycutofftime` in the same table, aligned with the existing columns:

```
| `keyBackup.url`                                   | URL of an external store that receives a copy of every sealing key before it is created. Empty disables backup.   | `""`                                |
```

- [ ] **Step 4: Verify rendering**

Run:
```bash
helm template t helm/sealed-secrets | grep -c "key-backup-url" ; \
helm template t helm/sealed-secrets --set keyBackup.url='awssm://p?region=r' | grep -A1 "key-backup-url"
```
Expected: first command prints `0`; second prints the flag line followed by `- "awssm://p?region=r"`.

- [ ] **Step 5: Commit**

```bash
git add helm/sealed-secrets/values.yaml helm/sealed-secrets/templates/deployment.yaml helm/sealed-secrets/README.md
git commit -m "feat(helm): add keyBackup.url value"
```

---

### Task 9: user documentation and spec note

**Files:**
- Create: `docs/key-backup.md`
- Modify: `README.md:763-793` (backup FAQ)
- Modify: `docs/superpowers/specs/2026-09-22-sealing-key-backup-design.md` (Integration test section)

- [ ] **Step 1: Write `docs/key-backup.md`**

```markdown
# Sealing key backup

The controller can copy every sealing key to a store outside the cluster **before**
the key is created in Kubernetes. If a key cannot be backed up, it is not created;
the existing key keeps working and the controller retries on the next renewal.
This guarantees no sealing key is ever in use without an external copy.

Backup is off by default. Restore is a manual procedure described below.

## Enabling it

Set one flag (or its environment variable):

| Flag | Env var |
|---|---|
| `--key-backup-url=<url>` | `SEALED_SECRETS_KEY_BACKUP_URL` |

With the Helm chart:

```yaml
keyBackup:
  url: "awssm://sealed-secrets/prod?region=ap-south-1&kms-key-id=alias/sealed-secrets"
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/sealed-secrets-backup
```

The scheme of the URL selects the provider. An unknown scheme stops the controller
at startup with a message listing the schemes that are compiled in.

## Providers

### `awssm://` AWS Secrets Manager

```
awssm://<prefix>[/<more>]?region=<region>&kms-key-id=<key id or alias>
```

- One Secrets Manager secret per sealing key, named `<prefix>/<hex fingerprint>`,
  tagged with `sealed-secrets/secret-name` and `sealed-secrets/fingerprint`.
- `region` is optional (SDK default resolution applies).
- `kms-key-id` is optional (account default key applies). Set it so the key policy can be scoped.
- Credentials come from the AWS default chain: IRSA or Pod Identity on EKS, environment or profile elsewhere. Nothing goes in the URL.

Minimum IAM policy for the controller's role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["secretsmanager:CreateSecret", "secretsmanager:DescribeSecret", "secretsmanager:PutSecretValue", "secretsmanager:TagResource"],
      "Resource": "arn:aws:secretsmanager:<region>:<account>:secret:<prefix>/*"
    },
    {
      "Effect": "Allow",
      "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
      "Resource": "<kms key arn>"
    }
  ]
}
```

The controller never reads secret values back. Restore uses a human's credentials.

### `file://` local directory

```
file:///absolute/path
```

One JSON file per key. Meant for tests and for air-gapped clusters with a mounted,
externally replicated volume.

## What is stored

The Secret manifest as JSON, exactly what `kubectl get secret -o json` shows minus
server-populated fields. It contains the private key. Protect the store accordingly.

## Behaviour

| Situation | Behaviour |
|---|---|
| New key, backup succeeds | Secret created, key registered. |
| New key, backup fails | Nothing created. Error logged, `key_backup_total{result="failure"}` incremented. Retried on the next renewal period. |
| Key already in the cluster when backup is turned on | Backed up at startup (best effort). |
| Key added by hand with `--watch-for-secrets` | Backed up when the controller sees it (best effort). |
| Store misconfigured (bad URL, unknown scheme) | Controller exits at startup. |
| Key deleted from the cluster | Store entry is kept. Old SealedSecrets may still need it. |

## Metrics

| Metric | Meaning |
|---|---|
| `sealed_secrets_controller_key_backup_total{result}` | Attempts by `success`, `failure`, `skipped`. |
| `sealed_secrets_controller_key_backup_last_success_timestamp_seconds` | Last successful backup. |
| `sealed_secrets_controller_key_backup_unbacked_keys` | Live keys with no confirmed backup. **Alert when nonzero.** |

## Restore

1. Fetch every entry under your prefix and decode it:

   ```bash
   PREFIX=sealed-secrets/prod
   mkdir -p restore
   for n in $(aws secretsmanager list-secrets --filters Key=name,Values="$PREFIX/" --query 'SecretList[].Name' --output text); do
     aws secretsmanager get-secret-value --secret-id "$n" --query SecretBinary --output text | base64 -d > "restore/$(basename "$n").json"
   done
   ```

2. Apply them into the controller's namespace **before** installing the controller:

   ```bash
   kubectl apply -n kube-system -f restore/
   ```

3. Install or start the controller. It logs `registered private key` for each restored
   key and does not generate a new one if the newest is younger than the renewal period.

4. Check an old SealedSecret decrypts.

To decrypt offline without a cluster:

```bash
kubeseal --recovery-unseal --recovery-private-key restore/<file>.json --format yaml < sealed.yaml
```

## Adding a provider

Implement `keybackup.Store` (`Put`, `Exists`) in a new package under `pkg/keybackup/`,
call `keybackup.Register("<scheme>", open)` from `init`, and import the package for
side effect in `cmd/controller/main.go`. The controller core needs no change.
```

- [ ] **Step 2: Point the README FAQ at it**

In `README.md`, inside the section `### How can I do a backup of my SealedSecrets?`, add as the first paragraph after the heading:

```markdown
> The controller can do this for you automatically, storing every key in AWS Secrets Manager or another external store before it is created. See [docs/key-backup.md](docs/key-backup.md). The manual procedure below still works.
```

- [ ] **Step 3: Update the spec's integration test section**

In the spec, replace the `### Integration test` section body with:

```markdown
The existing Ginkgo suite runs against a controller already installed in a cluster, and
`controller.Main` requires in-cluster configuration, so a file-provider integration test
cannot run in that suite. The file provider is verified manually in kind with an
`emptyDir` volume (implementation plan, Task 10) and by its unit tests.
```

- [ ] **Step 4: Commit**

```bash
git add docs/key-backup.md README.md docs/superpowers/specs/2026-09-22-sealing-key-backup-design.md
git commit -m "docs: document sealing key backup"
```

---

### Task 10: manual verification in kind (file provider, then AWS)

**Files:** none changed. This task produces a verification note appended to `docs/superpowers/plans/2026-09-22-sealing-key-backup.md` under a `## Verification log` heading.

Prerequisites: `kind`, `helm`, `kubectl`, `kubeseal`, `docker`, and for part B the AWS profile `ss-feas` in region `ap-south-1` with the policy from `feasibility/iam-policy.json` plus `secretsmanager:PutSecretValue`. Build the image from the branch and load it into kind.

- [ ] **Step 1: Build and load the controller image**

The repo Dockerfile expects a goreleaser `dist/` layout, so build the image from a
two-line Dockerfile in the scratchpad instead:

```bash
cd /home/ms/code/Others/SealedSecret-Proj/sealed-secrets
mkdir -p /tmp/kb-image
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/kb-image/controller ./cmd/controller
cat > /tmp/kb-image/Dockerfile <<'DF'
FROM gcr.io/distroless/static:nonroot
USER 1001
COPY controller /usr/local/bin/
EXPOSE 8080 8081
ENTRYPOINT ["controller"]
DF
docker build -t sealed-secrets-controller:kb /tmp/kb-image
kind create cluster --name ss-kb --wait 120s
kind load docker-image sealed-secrets-controller:kb --name ss-kb
```

Every `helm install`/`upgrade` below passes the same image values; define them once:

```bash
IMG="--set image.registry=docker.io --set image.repository=library/sealed-secrets-controller --set image.tag=kb --set image.pullPolicy=Never"
```

- [ ] **Step 2: Part A, file provider through an emptyDir**

```bash
helm install sealed-secrets ./helm/sealed-secrets -n kube-system \
  --set fullnameOverride=sealed-secrets-controller \
  $IMG \
  --set keyBackup.url=file:///backup \
  --set-json 'additionalVolumes=[{"name":"backup","emptyDir":{}}]' \
  --set-json 'additionalVolumeMounts=[{"name":"backup","mountPath":"/backup"}]' \
  --wait --timeout 180s
kubectl -n kube-system logs deploy/sealed-secrets-controller | grep -iE "backup|key"
POD=$(kubectl -n kube-system get pod -l app.kubernetes.io/name=sealed-secrets -o name | head -1)
kubectl -n kube-system exec $POD -- ls -la /backup
```

Expected: log shows `Sealing key backup enabled`, `Sealing key backed up`, `New key written`; `/backup` holds one `<64 hex>.json` file. 

Then prove the file restores:

```bash
kubectl -n kube-system exec $POD -- cat /backup/*.json > /tmp/kb-restore.json
kubectl -n kube-system get secret -l sealedsecrets.bitnami.com/sealed-secrets-key -o name
kubeseal --fetch-cert --controller-name sealed-secrets-controller --controller-namespace kube-system > /tmp/kb-cert.pem
kubectl create secret generic kb-test --dry-run=client -o yaml --from-literal=t=hello | kubeseal --cert /tmp/kb-cert.pem --format yaml > /tmp/kb-sealed.yaml
kind delete cluster --name ss-kb
kind create cluster --name ss-kb --wait 120s
kind load docker-image sealed-secrets-controller:kb --name ss-kb
kubectl apply -n kube-system -f /tmp/kb-restore.json
helm install sealed-secrets ./helm/sealed-secrets -n kube-system --set fullnameOverride=sealed-secrets-controller \
  $IMG \
  --wait --timeout 180s
kubectl -n kube-system logs deploy/sealed-secrets-controller | grep -E "registered private key|New key written"
kubectl apply -f /tmp/kb-sealed.yaml && sleep 5 && kubectl get secret kb-test -o jsonpath='{.data.t}' | base64 -d; echo
```

Expected: `registered private key` present, `New key written` absent, output `hello`. Record PASS/FAIL. Then `shred -u /tmp/kb-restore.json`.

- [ ] **Step 3: Part B, AWS Secrets Manager**

Create a scoped KMS key and put AWS credentials into the pod via env (kind has no IRSA):

```bash
export AWS_PROFILE=ss-feas AWS_REGION=ap-south-1
SUFFIX=kb-$(date +%m%d)
KEY=$(aws kms create-key --description "sealed-secrets $SUFFIX" --query KeyMetadata.KeyId --output text)
aws kms create-alias --alias-name alias/ss-feas-$SUFFIX --target-key-id $KEY
kubectl -n kube-system create secret generic aws-creds \
  --from-literal=AWS_ACCESS_KEY_ID=$(aws configure get aws_access_key_id) \
  --from-literal=AWS_SECRET_ACCESS_KEY=$(aws configure get aws_secret_access_key)
helm upgrade sealed-secrets ./helm/sealed-secrets -n kube-system --set fullnameOverride=sealed-secrets-controller $IMG \
  --set keyBackup.url="awssm://ss-feas-$SUFFIX/keys?region=ap-south-1&kms-key-id=alias/ss-feas-$SUFFIX" \
  --wait --timeout 180s || true   # first rollout may crash-loop until creds are injected below
kubectl -n kube-system set env deploy/sealed-secrets-controller --from=secret/aws-creds
kubectl -n kube-system rollout status deploy/sealed-secrets-controller --timeout=120s
kubectl -n kube-system logs deploy/sealed-secrets-controller | grep -iE "backup"
aws secretsmanager list-secrets --filters Key=name,Values="ss-feas-$SUFFIX/keys/" --query 'SecretList[].[Name,Tags[?Key==`sealed-secrets/secret-name`].Value|[0]]' --output table
```

The chart has no value for extra container env, so `kubectl set env` patches the Deployment
directly. Later `helm upgrade --reuse-values` calls keep that patch only if Helm does not
own the `env` field; if the AWS log line disappears after an upgrade, re-run the `set env`.

Expected: one entry per key Secret in the cluster (the reconcile pass backed up the restored key), tag matches the Secret name. Now force a renewal and confirm a second entry:

```bash
helm upgrade sealed-secrets ./helm/sealed-secrets -n kube-system --reuse-values --set keycutofftime="$(date -R | sed 's/,/\\,/g')" --wait
sleep 5
aws secretsmanager list-secrets --filters Key=name,Values="ss-feas-$SUFFIX/keys/" --query 'length(SecretList)'
kubectl -n kube-system get secret -l sealedsecrets.bitnami.com/sealed-secrets-key -o name | wc -l
```

Expected: both counts equal 2. Then restore from AWS into a fresh cluster using the procedure in `docs/key-backup.md` and confirm `kb-test` decrypts to `hello`. Record PASS/FAIL.

- [ ] **Step 4: Fail-closed check**

Break the store and force a renewal:

```bash
helm upgrade sealed-secrets ./helm/sealed-secrets -n kube-system --reuse-values \
  --set keyBackup.url="awssm://ss-feas-$SUFFIX/keys?region=ap-south-1&kms-key-id=alias/does-not-exist" \
  --set keycutofftime="$(date -R | sed 's/,/\\,/g')" --wait
sleep 5
kubectl -n kube-system logs deploy/sealed-secrets-controller | grep -E "backup failed|Failed to generate"
kubectl -n kube-system get secret -l sealedsecrets.bitnami.com/sealed-secrets-key -o name | wc -l
kubectl -n kube-system port-forward deploy/sealed-secrets-controller 8081:8081 & sleep 2
curl -s localhost:8081/metrics | grep key_backup_; kill %1
```

Expected: an error log line, key count unchanged, `key_backup_total{result="failure"}` at least 1, `key_backup_unbacked_keys 0`. The controller pod is still Running.

- [ ] **Step 5: Clean up**

```bash
kind delete cluster --name ss-kb
for s in $(aws secretsmanager list-secrets --filters Key=name,Values="ss-feas-$SUFFIX" --query 'SecretList[].Name' --output text); do aws secretsmanager delete-secret --secret-id "$s" --force-delete-without-recovery; done
aws kms delete-alias --alias-name alias/ss-feas-$SUFFIX
aws kms schedule-key-deletion --key-id $KEY --pending-window-in-days 7
rm -f /tmp/kb-cert.pem /tmp/kb-sealed.yaml
```

- [ ] **Step 6: Record and commit the verification log**

Append to this plan file:

```markdown
## Verification log

- Date:
- Image build command that worked:
- Part A (file provider): PASS/FAIL, notes
- Part B (AWS): PASS/FAIL, entry names seen, notes
- Fail-closed: PASS/FAIL, metric values
- Deviations from the plan:
```

```bash
git add docs/superpowers/plans/2026-09-22-sealing-key-backup.md
git commit -m "docs: record key backup verification"
```

---

## Self-review notes

- Spec coverage: interface and registry (T1), file provider (T2), awssm provider with create-or-replace and IAM (T3), manifest with stripped fields (T4), controller-chosen name, fail-closed ordering, collision retry, 30 s timeout, metrics (T5), reconcile at startup and informer hook, unbacked gauge (T6), flag, env var, fatal startup on bad URL, conditional metric registration (T7), Helm (T8), docs and README pointer (T9), manual AWS verification (T10). The spec's Ginkgo integration test is replaced by T10 Part A and the spec is amended in T9.
- Type consistency: `keybackup.Backup{Fingerprint, SecretName, Manifest, CreatedAt}` used identically in T1, T2, T3, T5, T6. `SetBackupStore`, `backupKeySecret`, `reconcileKeyBackups`, `markUnbacked`, `markBacked`, `keyBackupTotal`, `keyBackupUnbackedKeys`, `observeKeyBackupSuccess`, `keyBackupTimeout`, `keyNameAttempts` defined in T5/T6 and consumed in T6/T7 with the same names.
- `generateNameReactor` in existing tests appends `-<16 chars>`; the backup path never uses GenerateName so that reactor is irrelevant there.
