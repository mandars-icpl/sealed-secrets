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
