# Sealing key backup to an external store

Date: 2026-09-22
Status: approved design, not yet implemented

## Problem

The controller generates sealing key pairs and stores them only as Kubernetes Secrets in
its own namespace. A new key is generated every renewal period (30 days by default) and old
keys are kept, because old SealedSecrets still need them. If the cluster is lost and there is
no copy of those Secrets, every SealedSecret in git becomes undecryptable. The README
documents a manual `kubectl get secret ... > main.key` backup and warns that it must be
repeated after every renewal.

A feasibility check on 2026-09-22 (see `feasibility/RESULTS.md` outside this repo) proved
that an exported key Secret can be stored in AWS Secrets Manager or S3 with SSE-KMS, pulled
back intact, applied to a fresh cluster before the controller starts, and that the controller
then adopts it and decrypts old SealedSecrets. It also proved that AWS KMS cannot encrypt a
key file directly (files are ~7 KB, the KMS limit is 4096 bytes), so server-side encryption
by the store is the right mechanism.

## Goal

The controller backs up every sealing key to an external store as it is created, so that
no sealing key ever exists in the cluster without a copy outside it. The mechanism is cloud
agnostic: the controller core knows an interface and a URL scheme, and each backend is a
separate provider package.

## Non-goals

- Automatic restore. Restore stays a documented manual procedure in this version.
- Deleting entries from the store. Old keys may still be needed for old SealedSecrets.
- Client-side encryption. The store encrypts at rest with a customer-managed key.
- Backends other than AWS Secrets Manager and a local file store. GCP, Azure and Vault
  follow the same interface later.
- Making backup mandatory. The feature is off unless configured.

## Decisions

| Decision | Choice | Why |
|---|---|---|
| Where the mechanism lives | Inside the controller | Only the controller can guarantee a key is backed up before it is used. |
| Provider model | Own interface, scheme-keyed provider registry, direct cloud SDKs | Small dependency footprint, no client-side crypto, familiar pattern (database/sql drivers, External Secrets Operator). Go Cloud Development Kit was rejected because it drags every cloud SDK into go.mod and has no Secrets Manager writer. |
| Failure mode for new keys | Fail closed | A new key is only created in the cluster after the store confirms the backup. A store outage delays renewal; the existing key keeps working. |
| Failure mode for existing keys | Best effort, metered | Keys that already exist are live; refusing to start would make things worse. |
| Secret naming | Chosen by the controller when backup is on | Fail-closed requires the backup before the Secret exists, and the manifest needs its final name. See "Naming". |
| Store entry identity | Public key fingerprint | Stable, derived from the key itself, already computed by the registry. |
| What is stored | The full Secret manifest as JSON, server fields stripped | Restore is a plain `kubectl apply`, matching the documented manual procedure and the feasibility test. |
| First provider | AWS Secrets Manager | Purpose-built secret store, KMS encryption server-side, IAM scoping by name prefix, proven in the feasibility run. |

## Architecture

### Package `pkg/keybackup`

New package with no dependency on `pkg/controller`, so it can be unit tested alone and
reused by a future restore command.

```go
// Backup is one sealing key, ready to be applied back into a cluster.
type Backup struct {
    Fingerprint string    // public key fingerprint (crypto.PublicKeyFingerprint), the stable identity
    SecretName  string    // metadata.name of the Secret in Manifest
    Manifest    []byte    // the Secret as JSON, with server-populated fields stripped
    CreatedAt   time.Time // certificate NotBefore
}

// Store is implemented by every backend.
type Store interface {
    // Put stores b, creating the entry for b.Fingerprint or replacing its content if it
    // already exists. A second Put with the same fingerprint never creates a second entry.
    Put(ctx context.Context, b Backup) error
    // Exists reports whether an entry with this fingerprint is already stored.
    Exists(ctx context.Context, fingerprint string) (bool, error)
}

// Open parses rawURL, looks up the provider registered for its scheme and returns a Store.
// An unknown scheme returns an error listing the registered schemes.
func Open(ctx context.Context, rawURL string) (Store, error)

// Register is called by provider packages from init().
func Register(scheme string, open func(ctx context.Context, u *url.URL) (Store, error))
```

Scheme is the only thing that selects a provider. The controller never inspects the URL
beyond parsing it. The controller's `main` imports provider packages for their side effect
of registering, in the same style as database drivers.

| Scheme | Provider | In this version |
|---|---|---|
| `awssm://` | AWS Secrets Manager | yes |
| `file://` | local directory | yes |
| `gcpsm://`, `azkv://`, `vault://`, `s3://` | future | no |

A scheme identifies a provider, not a cloud. A second AWS backend later gets its own scheme.

### Provider `pkg/keybackup/awssm`

URL form:

```
awssm://<prefix>[/<more prefix>]?region=<region>&kms-key-id=<key id or alias>
```

- Host plus path, joined with `/`, is the Secrets Manager name prefix. An entry is named
  `<prefix>/<sanitized fingerprint>`. The fingerprint from `crypto.PublicKeyFingerprint` is
  `SHA256:<base64>`; the provider strips the `SHA256:` prefix and hex-encodes the raw bytes
  so the name contains only characters Secrets Manager accepts.
- `region` is optional and falls back to the SDK's own resolution.
- `kms-key-id` is optional and falls back to the account's default Secrets Manager key.
- Credentials are never in the URL. The provider uses the AWS default credential chain
  (IRSA or Pod Identity on EKS, env vars or profile elsewhere).
- `Put` calls CreateSecret with `SecretBinary` set to the manifest, `KmsKeyId` when
  given, and tags `sealed-secrets/secret-name=<SecretName>`,
  `sealed-secrets/fingerprint=<Fingerprint>`, `sealed-secrets/managed-by=controller`.
  If CreateSecret returns ResourceExistsException, it calls PutSecretValue to replace the
  content and TagResource to refresh the secret-name tag. Callers that only want to fill
  gaps (the reconcile pass) call `Exists` first and skip `Put` when true.
- `Exists` calls DescribeSecret and maps ResourceNotFoundException to false.
- The AWS client sits behind a four-method interface (DescribeSecret, CreateSecret,
  PutSecretValue, TagResource) so unit tests use a hand-written fake.
- Dependencies added: `github.com/aws/aws-sdk-go-v2`, `.../config`, `.../service/secretsmanager`.

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

The controller does not need GetSecretValue. It cannot read back what it stored; restore
uses a human's credentials.

### Provider `pkg/keybackup/file`

URL form: `file:///absolute/path/to/dir`. One file per entry named `<sanitized fingerprint>.json`.
`Put` writes to a temporary file in the same directory and renames it into place, so a crash
never leaves a partial entry. Used by unit and integration tests, and usable for air-gapped
clusters with a mounted volume.

### Controller integration

One new flag in `cmd/controller/main.go`, bound like every other flag so it also reads
from the environment:

| Flag | Env var | Default |
|---|---|---|
| `--key-backup-url` | `SEALED_SECRETS_KEY_BACKUP_URL` | empty (disabled) |

`controller.Flags` gains `KeyBackupURL string`. `KeyRegistry` gains an optional
`backup keybackup.Store` field, nil when disabled.

#### Naming

Today `writeKey` sets `GenerateName: prefix` and the API server appends five random
characters from the alphabet `bcdfghjklmnpqrstvwxz2456789`. With backup enabled the
controller generates the name itself: `prefix + rand.String(5)` from
`k8s.io/apimachinery/pkg/util/rand`, which is the same alphabet and length, and sets
`Name` instead of `GenerateName`. Names look identical to today. With backup disabled,
`GenerateName` is still used and the code path is unchanged.

#### Flow: startup

1. If `KeyBackupURL` is empty, nothing below applies.
2. `keybackup.Open` is called before the registry is loaded. Any error is fatal: the
   controller exits non-zero. Constructing the AWS client does not call AWS, so an
   unreachable endpoint is not a startup error.
3. The registry is loaded from existing key Secrets as today.
4. Reconcile pass: for every registered key, call `Exists`; if false, build the manifest
   from the live Secret and `Put`. Failures are logged, counted and skipped; the pass
   continues with the next key and startup succeeds.
5. Key renewal is scheduled as today.

#### Flow: generating a new key (`KeyRegistry.generateKey`)

1. Generate the RSA key and certificate in memory.
2. If backup is disabled: `writeKey` with `GenerateName`, register, return. Unchanged.
3. Choose `name := prefix + rand.String(5)`.
4. Build the Secret object with that name, serialize to JSON, compute the fingerprint.
5. `Put` with a 30 second timeout. On error: discard the key, log at error level with
   fingerprint and name, increment `key_backup_total{result="failure"}`, return the error.
   No Secret is created. The renewal scheduler retries on its normal period.
6. Create the Secret with that exact name. On `AlreadyExists` go to step 3 with a new
   name; the next `Put` replaces the store entry for the same fingerprint, so the stored
   manifest always carries the name that was actually created. (Bounded to 5 attempts,
   then return the error.) On any other error return it as today; the orphan entry in the
   store is harmless.
7. Register the key and log, as today. Increment `key_backup_total{result="success"}`,
   set the last-success gauge.

#### Flow: key Secret added from outside (`--watch-for-secrets`)

The informer add handler registers the key as it does now, then calls `Exists` and `Put`
if missing, with the same best-effort semantics as the reconcile pass.

#### Manifest construction

The manifest is the `v1.Secret` the controller would create, encoded as JSON with the
standard Kubernetes serializer, with `resourceVersion`, `uid`, `creationTimestamp`,
`managedFields` and `selfLink` cleared. For the reconcile and informer paths the live
Secret is copied and the same fields cleared. Labels and annotations, including the
`sealedsecrets.bitnami.com/sealed-secrets-key=active` label, are preserved so that
`kubectl apply` of the manifest recreates a Secret the controller will adopt.

### Error handling

| Class | Behaviour |
|---|---|
| Startup: bad URL, unknown scheme, provider config error | Fatal. Controller exits non-zero with a clear log line. |
| New key: `Put` fails or times out | Key discarded, no Secret created, error logged, failure counter incremented. Retry on next renewal. |
| Startup: first key ever and `Put` fails | Fatal. There is nothing to serve; the pod restart is the retry. |
| Startup: cutoff-forced key and `Put` fails, keys exist | Logged, startup continues serving the existing keys. Verified as a gap during implementation and fixed. |
| Reconcile or informer: `Exists`/`Put` fails | Logged, counted, unbacked gauge raised, processing continues. No retry loop; a restart re-runs reconcile. |

No log line contains key material. Manifest bytes are never logged at any level.

### Metrics

Registered only when backup is enabled, in the existing `sealed_secrets_controller`
namespace.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `key_backup_total` | counter | `result` = `success`, `failure`, `skipped` | Every `Put` attempt. `skipped` means `Exists` was true. |
| `key_backup_last_success_timestamp_seconds` | gauge | none | Unix time of the last successful `Put`. |
| `key_backup_unbacked_keys` | gauge | none | Registered keys with no confirmed store entry. Zero is healthy. Alert on nonzero. |

A new-key failure does not raise `key_backup_unbacked_keys`, because the key was never
created.

### Helm chart

`values.yaml` gains:

```yaml
keyBackup:
  ## @param keyBackup.url Store URL for sealing key backup (for example
  ## awssm://sealed-secrets/prod?region=ap-south-1&kms-key-id=alias/sealed-secrets).
  ## Empty disables backup.
  url: ""
```

`templates/deployment.yaml` renders `--key-backup-url <url>` when set, in the same style
as `keycutofftime`. Cloud credentials bind through the existing `serviceAccount.annotations`.
Nothing else in the chart changes.

### Documentation

- New `docs/key-backup.md`: why, the flag and URL format per provider, IAM policy, the
  restore procedure, fail-closed behaviour, metrics and alerting, how to add a provider.
- README backup FAQ gets a pointer to it.

### Restore procedure (manual, documented)

1. With human credentials, list entries under the prefix and fetch each `SecretBinary`.
2. `kubectl apply` the decoded manifests into the controller namespace.
3. Install or start the controller. It registers the keys and does not generate a new one
   if the newest is younger than the renewal period.
4. Verify an old SealedSecret decrypts.

`kubeseal --recovery-unseal --recovery-private-key <manifest> --format yaml` also works
on a fetched manifest for offline decryption.

## Testing

### `pkg/keybackup` unit tests

- `Open`: known scheme returns a store; unknown scheme errors and the message lists
  registered schemes; empty URL is rejected; provider query parsing.
- file provider: `Put` then `Exists` is true; `Put` twice leaves one file holding the
  second content; no partial file after a simulated failure mid-write.
- awssm provider (fake client): `CreateSecret` when missing; `PutSecretValue` plus tag
  refresh when `CreateSecret` reports the entry exists; `CreateSecret` error is propagated;
  `Exists` maps not-found to false; sanitized fingerprint is a valid name; `region` and
  `kms-key-id` from the URL land in the request; tags are set.

### `pkg/controller` unit tests (fake clientset)

- Backup off: Secret created with `GenerateName`, no store touched.
- Backup on: store receives the manifest before the Secret exists; Secret is created with
  the manifest's name; registry has the key.
- `Put` fails: no Secret created, registry unchanged, failure counter incremented.
- `AlreadyExists` once: second name succeeds; store holds the second name.
- Reconcile: two existing keys, one already stored, exactly one `Put`; unbacked gauge
  reads zero. A failing `Put` leaves the gauge at one and startup still succeeds.
- Informer add with `--watch-for-secrets`: externally applied key gets a `Put`.
- Manifest round trip: stored JSON decodes to a Secret whose PEM matches the generated
  key and has no `resourceVersion`, `uid`, `creationTimestamp` or `managedFields`.

### Integration test

The existing Ginkgo suite runs against a controller already installed in a cluster, and
`controller.Main` requires in-cluster configuration, so a file-provider integration test
cannot run in that suite. The file provider is verified manually in kind with an
`emptyDir` volume (implementation plan, Task 10) and by its unit tests.

### Manual verification against AWS

Once, by hand: controller in kind with an `awssm://` URL, entry appears in Secrets
Manager, cluster deleted, entry restored, old SealedSecret decrypts. This repeats the
feasibility runbook's phases 3 and 4 with the controller doing the push.

## Open questions

None. All design questions were resolved in the brainstorming session on 2026-09-22.
