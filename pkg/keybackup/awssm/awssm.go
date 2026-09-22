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
