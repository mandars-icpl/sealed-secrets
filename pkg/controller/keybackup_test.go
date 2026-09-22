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
