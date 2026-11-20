#!/usr/bin/env bash
#
# Prove on a throwaway KMS key that a sealed release key cannot be reopened.
#
# Creates a key through the release-key module, seals it to a made-up
# measurement, and then tries, as whoever runs this, everything that would give
# access to the root key. Run it with the most privileged credentials the
# account has: the claim is that those are not enough.
#
# The key is left scheduled for deletion, which is itself one of the checks.
# Expect one KMS alert email per denied call.
#
# What this cannot show is what AWS Support will do for the account owner. KMS
# documents a support case as the only way back into a key whose policy locks
# everyone out; ask for it on this key before relying on a real one.

set -euo pipefail
cd "$(dirname "$0")"

REGION=us-east-1
PCR0=$(printf 'ab%.0s' {1..48})
CONTEXT="purpose=cavos-recovery-root-key-v1"
alias="cavos-recovery-disposable-$(date +%s)"
blob=$(mktemp)
trap 'rm -f "$blob"' EXIT

denied() {
  local what=$1 output
  shift
  if output=$("$@" 2>&1); then
    echo "FAIL: $what was allowed" >&2
    exit 1
  fi
  if ! grep -q AccessDenied <<<"$output"; then
    echo "FAIL: $what failed for another reason: $output" >&2
    exit 1
  fi
  echo "ok: $what is denied"
}

rm -f terraform.tfstate terraform.tfstate.backup
terraform init -input=false >/dev/null

echo "==> Creating an open key"
terraform apply -auto-approve -input=false -var "alias=$alias" >/dev/null
key_arn=$(terraform output -raw arn)
account=$(aws sts get-caller-identity --query Account --output text)
echo "    $key_arn"

aws kms generate-data-key-without-plaintext --key-id "$key_arn" --key-spec AES_256 \
  --encryption-context "$CONTEXT" --region "$REGION" \
  --query CiphertextBlob --output text | base64 --decode >"$blob"

echo "==> Sealing it"
terraform apply -auto-approve -input=false -var "alias=$alias" -var "pcr0=$PCR0" >/dev/null

echo "==> Terraform must have nothing left to change on a sealed key"
terraform plan -detailed-exitcode -input=false -var "alias=$alias" -var "pcr0=$PCR0" >/dev/null
echo "ok: the plan is empty"

../../verify-release-key.sh "$key_arn" "$PCR0"

denied "creating a grant" \
  aws kms create-grant --key-id "$key_arn" --operations Decrypt \
  --grantee-principal "arn:aws:iam::$account:root" --region "$REGION"
denied "decrypting the root key without an attestation" \
  aws kms decrypt --key-id "$key_arn" --ciphertext-blob "fileb://$blob" \
  --encryption-context "$CONTEXT" --region "$REGION"
denied "encrypting a chosen root key" \
  aws kms encrypt --key-id "$key_arn" --plaintext "AAAA" \
  --encryption-context "$CONTEXT" --region "$REGION"
denied "generating another root key" \
  aws kms generate-data-key-without-plaintext --key-id "$key_arn" --key-spec AES_256 \
  --encryption-context "$CONTEXT" --region "$REGION"
denied "re-encrypting the root key under another key" \
  aws kms re-encrypt --source-key-id "$key_arn" --destination-key-id "$key_arn" \
  --ciphertext-blob "fileb://$blob" --source-encryption-context "$CONTEXT" --region "$REGION"

echo "==> The emergency stop must still work"
aws kms disable-key --key-id "$key_arn" --region "$REGION"
aws kms enable-key --key-id "$key_arn" --region "$REGION"
aws kms schedule-key-deletion --key-id "$key_arn" --pending-window-in-days 7 \
  --region "$REGION" >/dev/null
echo "ok: the key can be disabled, enabled and scheduled for deletion"

rm -f terraform.tfstate terraform.tfstate.backup
echo "PASS: $key_arn is sealed and scheduled for deletion"
