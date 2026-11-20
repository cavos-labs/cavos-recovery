# The KMS key of one enclave release.
#
# The key wraps the root sealing key of exactly one image, and its policy has
# two states.
#
#   open    `pcr0` is null. The account may write the policy and create the
#           wrapped root key. Nothing can decrypt.
#   sealed  `pcr0` is set. Only an enclave measuring to it can decrypt, and no
#           statement lets anyone write the policy, create a grant or encrypt.
#           The policy is then final: KMS has no path around a key policy for
#           the account that owns the key, the root user included.
#
# A sealed key can still be read, disabled and scheduled for deletion. Those
# stop the release; none of them reveals the root key.
#
# Regaining write access to a sealed key takes an AWS Support case on the
# account. That, and the image itself, are what a sealed key still trusts.

data "aws_caller_identity" "current" {}

locals {
  account = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
  sealed  = var.pcr0 != null

  root_key_context = {
    "kms:EncryptionContext:purpose" = "cavos-recovery-root-key-v1"
  }

  observe_and_stop = {
    Sid       = "ObserveAndStop"
    Effect    = "Allow"
    Principal = { AWS = local.account }
    # Named one by one. A wildcard in a policy nobody can edit would also
    # cover every action KMS adds later.
    Action = [
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:ListGrants",
      "kms:ListKeyPolicies",
      "kms:ListResourceTags",
      "kms:DisableKey",
      "kms:EnableKey",
      "kms:ScheduleKeyDeletion",
      "kms:CancelKeyDeletion",
    ]
    Resource = "*"
  }

  open_statements = [
    {
      Sid       = "SealOnce"
      Effect    = "Allow"
      Principal = { AWS = local.account }
      Action    = ["kms:PutKeyPolicy", "kms:CreateAlias"]
      Resource  = "*"
    },
    {
      # Returns ciphertext only, so the plaintext root key never exists outside
      # KMS. There is no `kms:Encrypt`: with it an account principal could wrap
      # a root key of its own choosing.
      Sid       = "CreateTheRootKey"
      Effect    = "Allow"
      Principal = { AWS = local.account }
      Action    = "kms:GenerateDataKeyWithoutPlaintext"
      Resource  = "*"
      Condition = { StringEquals = local.root_key_context }
    },
  ]

  sealed_statements = [
    {
      # The role is what the enclave host runs as. The account stands beside it
      # so that IAM can name another role: a role that is deleted and created
      # again gets a new identity, and this policy could never be corrected to
      # follow it. Either way the measurement is the authority; credentials
      # are not.
      Sid       = "DecryptOnlyFromTheAttestedEnclave"
      Effect    = "Allow"
      Principal = { AWS = [local.account, var.enclave_role_arn] }
      Action    = "kms:Decrypt"
      Resource  = "*"
      Condition = {
        StringEqualsIgnoreCase = { "kms:RecipientAttestation:PCR0" = var.pcr0 }
        StringEquals           = local.root_key_context
      }
    },
  ]

  open_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = concat([local.observe_and_stop], local.open_statements)
  })

  sealed_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = concat([local.observe_and_stop], local.sealed_statements)
  })
}

resource "aws_kms_key" "this" {
  description             = "Cavos social recovery root sealing key"
  deletion_window_in_days = 30
  enable_key_rotation     = false

  # Sealing removes the caller's own right to write the policy, which KMS
  # refuses unless told it is intended.
  bypass_policy_lockout_safety_check = true

  policy = local.sealed ? local.sealed_policy : local.open_policy

  lifecycle {
    prevent_destroy = true
    # A sealed key cannot be retagged, so a tag change must not become a plan
    # that can never apply.
    ignore_changes = [tags, tags_all]
  }
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.alias}"
  target_key_id = aws_kms_key.this.key_id
}
