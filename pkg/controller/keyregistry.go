package controller

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/bitnami/sealed-secrets/pkg/crypto"
	"github.com/bitnami/sealed-secrets/pkg/keybackup"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	krand "k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/kubernetes"
	certUtil "k8s.io/client-go/util/cert"
)

const (
	// keyBackupTimeout bounds a single Store.Put or Exists call.
	keyBackupTimeout = 30 * time.Second
	// keyNameAttempts bounds retries when a controller-chosen Secret name already exists.
	keyNameAttempts = 5
	// keyNameSuffixLen matches the API server's GenerateName suffix length.
	keyNameSuffixLen = 5
)

// A Key holds the cryptographic key pair and some metadata about it.
type Key struct {
	private      *rsa.PrivateKey
	cert         *x509.Certificate
	fingerprint  string
	orderingTime time.Time
}

// A KeyRegistry manages the key pairs used to (un)seal secrets.
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

// NewKeyRegistry creates a new KeyRegistry.
func NewKeyRegistry(client kubernetes.Interface, namespace, keyPrefix, keyLabel string, keysize int) *KeyRegistry {
	return &KeyRegistry{
		client:    client,
		namespace: namespace,
		keyPrefix: keyPrefix,
		keysize:   keysize,
		keyLabel:  keyLabel,
		keys:      map[string]*Key{},
		unbacked:  map[string]struct{}{},
	}
}

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

func (kr *KeyRegistry) registerNewKey(keyName string, privKey *rsa.PrivateKey, cert *x509.Certificate, orderingTime time.Time) error {
	fingerprint, err := crypto.PublicKeyFingerprint(&privKey.PublicKey)
	if err != nil {
		return err
	}

	k := &Key{
		private:      privKey,
		cert:         cert,
		fingerprint:  fingerprint,
		orderingTime: orderingTime,
	}

	kr.mu.Lock()
	defer kr.mu.Unlock()

	kr.keys[k.fingerprint] = k

	if kr.mostRecentKey == nil || kr.mostRecentKey.orderingTime.Before(orderingTime) {
		kr.mostRecentKey = k
	}

	return nil
}

func (kr *KeyRegistry) unregisterKey(fingerprint string) {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	delete(kr.keys, fingerprint)

	if kr.mostRecentKey != nil && kr.mostRecentKey.fingerprint == fingerprint {
		kr.mostRecentKey = nil
		for _, k := range kr.keys {
			if kr.mostRecentKey == nil || kr.mostRecentKey.orderingTime.Before(k.orderingTime) {
				kr.mostRecentKey = k
			}
		}
	}
}

func (kr *KeyRegistry) latestPrivateKey() (*rsa.PrivateKey, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	if kr.mostRecentKey == nil {
		return nil, fmt.Errorf("key registry has no keys")
	}
	return kr.mostRecentKey.private, nil
}

// privateKeys returns a snapshot copy of the private keys so callers
// can iterate without holding the mutex.
func (kr *KeyRegistry) privateKeys() map[string]*rsa.PrivateKey {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	m := make(map[string]*rsa.PrivateKey, len(kr.keys))
	for k, v := range kr.keys {
		m[k] = v.private
	}
	return m
}

func (kr *KeyRegistry) keyLen() int {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	return len(kr.keys)
}

func (kr *KeyRegistry) mostRecentKeyTime() (time.Time, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	if kr.mostRecentKey == nil {
		return time.Time{}, fmt.Errorf("key registry has no keys")
	}
	return kr.mostRecentKey.orderingTime, nil
}

// getCert returns the current certificate. This method can be called by another goroutine.
func (kr *KeyRegistry) getCert() (*x509.Certificate, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	if kr.mostRecentKey == nil {
		return nil, fmt.Errorf("key registry has no keys")
	}
	return kr.mostRecentKey.cert, nil
}
