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

func TestInitKeyRenewalCutoffBackupFailureKeepsExistingKeys(t *testing.T) {
	ctx := context.Background()
	client := fake.NewClientset()
	client.PrependReactor("create", "secrets", generateNameReactor)
	kr := newTestRegistry(t, client, nil)
	if _, err := kr.generateKey(ctx, time.Hour, "cn", "", ""); err != nil {
		t.Fatal(err)
	}
	client.ClearActions()

	store := newFakeStore()
	store.putErr = errors.New("store down")
	kr.SetBackupStore(store)

	// A cutoff in the future forces a renewal at startup, which the failing store blocks.
	trigger, err := initKeyRenewal(ctx, kr, 0, time.Hour, time.Now().Add(time.Minute), "cn", "", "")
	if err != nil {
		t.Fatalf("startup must not fail when keys already exist, got %v", err)
	}
	if trigger == nil {
		t.Fatal("expected a trigger function")
	}
	if len(createdSecrets(client)) != 0 {
		t.Error("no Secret may be created when backup fails")
	}
	if kr.keyLen() != 1 {
		t.Errorf("registry has %d keys, want the 1 existing key", kr.keyLen())
	}
}

func TestInitKeyRenewalFirstKeyBackupFailureIsFatal(t *testing.T) {
	client := fake.NewClientset()
	store := newFakeStore()
	store.putErr = errors.New("store down")
	kr := newTestRegistry(t, client, store)

	if _, err := initKeyRenewal(context.Background(), kr, 0, time.Hour, time.Time{}, "cn", "", ""); err == nil {
		t.Fatal("first install with a failing store must fail startup")
	}
	if kr.keyLen() != 0 {
		t.Error("registry must stay empty")
	}
}
