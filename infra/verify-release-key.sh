#!/usr/bin/env bash
#
# Check that a release's KMS key is sealed: that its policy lets one enclave
# image decrypt and lets nobody change that.
#
#   ./verify-release-key.sh <key-arn> <pcr0>
#
# Three things are checked, because the policy text alone is not enough:
#
#   1. The policy allows exactly the expected actions, and Decrypt only to the
#      given measurement.
#   2. The key has no grants. A grant allows Decrypt without the measurement
#      condition and survives any policy.
#   3. Writing the policy is refused, by trying it. The write sends back the
#      policy already in place, so it changes nothing if it were to succeed.
#
# Read-only apart from that attempt. It raises the denied-KMS-call alert once.

set -euo pipefail

key_arn=${1:?usage: verify-release-key.sh <key-arn> <pcr0>}
pcr0=${2:?usage: verify-release-key.sh <key-arn> <pcr0>}
region=$(cut -d: -f4 <<<"$key_arn")

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

policy=$(aws kms get-key-policy --key-id "$key_arn" --policy-name default \
  --region "$region" --query Policy --output text)

expected_actions='[
  "kms:CancelKeyDeletion", "kms:Decrypt", "kms:DescribeKey", "kms:DisableKey",
  "kms:EnableKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus",
  "kms:ListGrants", "kms:ListKeyPolicies", "kms:ListResourceTags",
  "kms:ScheduleKeyDeletion"
]'
actions=$(jq -c '[.Statement[].Action] | flatten | sort' <<<"$policy")
[[ "$actions" == "$(jq -c 'sort' <<<"$expected_actions")" ]] ||
  fail "the policy allows other actions than a sealed key should: $actions"

jq -e '[.Statement[] | select(.Effect != "Allow" or has("NotAction") or has("NotPrincipal"))] | length == 0' \
  <<<"$policy" >/dev/null || fail "the policy has a statement that is not a plain Allow"

decrypt=$(jq -c '[.Statement[] | select([.Action] | flatten | index("kms:Decrypt"))]' <<<"$policy")
[[ $(jq 'length' <<<"$decrypt") == 1 ]] || fail "Decrypt must be allowed by exactly one statement"
jq -e --arg pcr0 "$pcr0" '.[0]
  | ([.Action] | flatten) == ["kms:Decrypt"]
    and .Condition.StringEqualsIgnoreCase["kms:RecipientAttestation:PCR0"] == $pcr0
    and .Condition.StringEquals["kms:EncryptionContext:purpose"] == "cavos-recovery-root-key-v1"
    and (.Condition | keys | sort) == ["StringEquals", "StringEqualsIgnoreCase"]' \
  <<<"$decrypt" >/dev/null || fail "Decrypt is not limited to an enclave measuring to $pcr0"
echo "ok: the policy allows Decrypt only to $pcr0, and no write to the key"

grants=$(aws kms list-grants --key-id "$key_arn" --region "$region" --query 'length(Grants)')
[[ "$grants" == 0 ]] || fail "the key has $grants grant(s); a grant bypasses the measurement condition"
echo "ok: the key has no grants"

if output=$(aws kms put-key-policy --key-id "$key_arn" --policy-name default \
  --policy "$policy" --bypass-policy-lockout-safety-check --region "$region" 2>&1); then
  fail "KMS accepted a policy write; the key is not sealed"
fi
grep -q AccessDenied <<<"$output" || fail "the policy write failed for another reason: $output"
echo "ok: KMS refuses to write the policy"

echo "sealed: $key_arn"
