package controller

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	mathrand "math/rand"
	"strings"
	"testing"
	"time"

	"github.com/bitnami/sealed-secrets/pkg/crypto"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	certUtil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
)

// This is omg-not safe for real crypto use!
func testRand() io.Reader {
	return mathrand.New(mathrand.NewSource(42))
}

func signKey(r io.Reader, key *rsa.PrivateKey) (*x509.Certificate, error) {
	return crypto.SignKey(r, key, time.Hour, "testcn")
}

func signKeyWithNotBefore(r io.Reader, key *rsa.PrivateKey, notBefore time.Time) (*x509.Certificate, error) {
	return crypto.SignKeyWithNotBefore(r, key, notBefore, time.Hour, "testcn")
}

func TestReadKey(t *testing.T) {
	rand := testRand()

	key, err := rsa.GenerateKey(rand, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	cert, err := signKey(rand, key)
	if err != nil {
		t.Fatalf("Failed to self-sign key: %v", err)
	}

	secret := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mykey",
			Namespace: "myns",
		},
		Data: map[string][]byte{
			v1.TLSPrivateKeyKey: pem.EncodeToMemory(&pem.Block{Type: keyutil.RSAPrivateKeyBlockType, Bytes: x509.MarshalPKCS1PrivateKey(key)}),
			v1.TLSCertKey:       pem.EncodeToMemory(&pem.Block{Type: certUtil.CertificateBlockType, Bytes: cert.Raw}),
		},
		Type: v1.SecretTypeTLS,
	}

	key2, cert2, err := readKey(&secret)
	if err != nil {
		t.Errorf("readKey() failed with: %v", err)
	}

	// Use crypto value equality, not reflect.DeepEqual: rsa.PrivateKey embeds
	// PrecomputedValues with unexported sync/once state that differs between a
	// freshly generated key and one re-parsed from PEM, which made this test
	// flaky under CI (see #1903).
	if !key.Equal(key2) {
		t.Errorf("Extracted key != original key")
	}

	if len(cert2) == 0 || !cert.Equal(cert2[0]) {
		t.Errorf("Extracted cert != original cert")
	}
}

func TestWriteKey(t *testing.T) {
	ctx := context.Background()
	rand := testRand()
	key, err := rsa.GenerateKey(rand, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	cert, err := signKey(rand, key)
	if err != nil {
		t.Fatalf("signKey failed: %v", err)
	}

	client := fake.NewClientset()

	namespace := "myns"
	defaultLabel := "default-label"
	myKey := "mykey"
	additionalAnnotations := "testAnnotation1=additional.annotation,test.annotation.2=test/2"
	additionalLabels := "testLabel1=additional.label,test.label.2=test/2"
	_, err = writeKey(ctx, client, key, []*x509.Certificate{cert}, namespace, defaultLabel, myKey, additionalAnnotations, additionalLabels)
	if err != nil {
		t.Errorf("writeKey() failed with: %v", err)
	}

	t.Logf("actions: %v", client.Actions())

	if a := findAction(client, "create", "secrets"); a == nil {
		t.Errorf("writeKey didn't create a secret")
	} else if a.GetNamespace() != namespace {
		t.Errorf("writeKey() created key in wrong namespace!")
	}
	a := findAction(client, "create", "secrets").(ktesting.CreateActionImpl)
	secret, _ := runtime.DefaultUnstructuredConverter.ToUnstructured(a.Object)
	generateName := secret["metadata"].(map[string]interface{})["generateName"].(string)

	if generateName != myKey {
		t.Errorf("writeKey didn't set the correct name")
	}

	labels := secret["metadata"].(map[string]interface{})["labels"]
	annotations := secret["metadata"].(map[string]interface{})["annotations"]

	if labels.(map[string]interface{})[defaultLabel] != "active" {
		t.Errorf("writeKey didn't set default label")
	}

	for _, label := range strings.Split(additionalLabels, ",") {
		labelKey := strings.Split(label, "=")[0]
		labelValue := strings.Split(label, "=")[1]
		if labels.(map[string]interface{})[labelKey] != labelValue {
			t.Errorf("writeKey didn't set label %v to value '%v'", labelKey, labelValue)
		}
	}

	for _, annotation := range strings.Split(additionalAnnotations, ",") {
		annotationKey := strings.Split(annotation, "=")[0]
		annotationValue := strings.Split(annotation, "=")[1]
		if annotations.(map[string]interface{})[annotationKey] != annotationValue {
			t.Errorf("writeKey didn't set annotation '%v' to value '%v'", annotationKey, annotationValue)
		}
	}
}

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
