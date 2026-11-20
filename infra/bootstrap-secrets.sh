#!/usr/bin/env bash
#
# Create the two secrets the enclave host reads at boot. Run once, after the
# `terraform apply` that creates the release's key and before the one that
# seals it: a sealed key no longer generates root keys.
#
# The root key is generated with `generate-data-key-without-plaintext`, which
# returns only ciphertext. The plaintext 32 bytes are created inside KMS and
# never exist anywhere else — not in this shell, not in terraform state, not in
# a log. The enclave is the only thing that ever sees them, and only because the
# key policy releases them to an attestation matching its measurement.

set -euo pipefail

REGION=${AWS_REGION:-us-east-1}
NAME=cavos-recovery

RELEASE=${1:?usage: bootstrap-secrets.sh <release>, for example v5}

key_arn=$(terraform output -json release_keys | jq -er --arg release "$RELEASE" '.[$release].arn')
echo "==> Using the KMS key of $RELEASE: $key_arn"

# A wrapped root key is the only way into every record sealed under it, and a
# sealed KMS key can never produce another. Never write over one.
current=$(aws ssm get-parameter --name "/$NAME/wrapped-root-key" \
  --region "$REGION" --query Parameter.Value --output text)
if [[ "$current" != "PENDING_BOOTSTRAP" ]]; then
  echo "A wrapped root key is already stored; refusing to replace it." >&2
  exit 1
fi

echo "==> Generating the wrapped root key"
wrapped=$(aws kms generate-data-key-without-plaintext \
  --key-id "$key_arn" \
  --key-spec AES_256 \
  --encryption-context "purpose=cavos-recovery-root-key-v1" \
  --region "$REGION" \
  --query CiphertextBlob --output text)

aws ssm put-parameter \
  --name "/$NAME/wrapped-root-key" \
  --type String \
  --value "$wrapped" \
  --overwrite \
  --region "$REGION" >/dev/null
echo "    stored (ciphertext only; the plaintext never left KMS)"

echo "==> Generating the relay shared secret"
# Abuse control, not a security boundary: it stops the open internet from
# queueing work onto the enclave. User data is protected end to end regardless.
secret=$(openssl rand -base64 32)
aws ssm put-parameter \
  --name "/$NAME/relay-secret" \
  --type SecureString \
  --value "$secret" \
  --overwrite \
  --region "$REGION" >/dev/null

# Deliberately not echoed. It already lives in SSM as a SecureString, and
# printing it would copy it into a terminal scrollback and shell history for no
# benefit. Read it back when you need it, with the command below.
cat <<MSG
    stored

==> Set these in the control plane (Vercel):

      CAVOS_RECOVERY_ENCLAVE_URL=$(terraform output -raw relay_url)
      CAVOS_RECOVERY_RELAY_SECRET=\$(aws ssm get-parameter \\
        --name /$NAME/relay-secret --with-decryption \\
        --region $REGION --query Parameter.Value --output text)

    Then restart the enclave host so it picks up the root key:

      aws ssm start-session --target $(terraform output -raw instance_id)
      sudo systemctl restart cavos-enclave cavos-relay
MSG
