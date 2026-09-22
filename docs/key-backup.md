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
| First key ever, backup fails | Controller exits; nothing to serve yet. Kubernetes restarts it, which is the retry. |
| `--key-cutoff-time` forces a key at startup, backup fails | Logged; controller keeps serving the existing keys. Retried on the next renewal. |
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
