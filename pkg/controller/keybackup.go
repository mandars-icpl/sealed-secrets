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
