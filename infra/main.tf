data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name = "cavos-recovery"
}

# ---------------------------------------------------------------------------
# KMS: the root sealing key
# ---------------------------------------------------------------------------
# The enclave unwraps one 32-byte root key at startup and derives every record
# key from it. This is the key that wraps it.
#
# The policy below is the whole security argument for running on an untrusted
# parent. The instance role may call Decrypt, but only when the request carries
# an attestation document measuring to `enclave_pcr0`. The parent instance holds
# those same credentials and still cannot decrypt: it cannot produce an
# attestation document at all. Credentials are not authority here — the
# measurement is.
resource "aws_kms_key" "root" {
  description             = "Cavos social recovery root sealing key"
  deletion_window_in_days = 30
  enable_key_rotation     = false # The enclave's key derivation is what rotates records.

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        # `kms:CreateAlias` rather than `kms:Create*`: the wildcard also covers
        # `kms:CreateGrant`, and a grant can allow Decrypt with no attestation
        # condition at all — grant constraints are limited to encryption
        # context and source ARN.
        Action = [
          "kms:CreateAlias", "kms:Describe*", "kms:Enable*", "kms:List*",
          "kms:Put*", "kms:Update*", "kms:Revoke*", "kms:Disable*",
          "kms:Get*", "kms:Delete*", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
        ]
        Resource = "*"
      },
      {
        # Creating the wrapped root key. `GenerateDataKeyWithoutPlaintext` is
        # deliberate: it returns only ciphertext, so the plaintext root key
        # never exists outside KMS — not in a shell, not in terraform state.
        Sid       = "AllowRootKeyCreation"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        # No `kms:Encrypt`: with it, an account principal could wrap a root key
        # of its own choosing and have the enclave seal new records under it.
        Action   = ["kms:GenerateDataKeyWithoutPlaintext"]
        Resource = "*"
      },
      {
        Sid       = "AllowDecryptOnlyFromTheAttestedEnclave"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.instance.arn }
        Action    = "kms:Decrypt"
        Resource  = "*"
        Condition = {
          StringEqualsIgnoreCase = {
            "kms:RecipientAttestation:PCR0" = var.enclave_pcr0
          }
        }
      },
    ]
  })
}

resource "aws_kms_alias" "root" {
  name          = "alias/${local.name}-root"
  target_key_id = aws_kms_key.root.key_id
}

# ---------------------------------------------------------------------------
# Configuration the instance reads at boot
# ---------------------------------------------------------------------------
# Terraform creates these parameters but never holds their real values.
# `bootstrap-secrets.sh` overwrites them once, and `ignore_changes` stops
# terraform from reverting that on the next apply.
#
# The alternative — generating them in terraform — would write the plaintext
# root key into state, and state is a file that gets copied to laptops and CI.
# The placeholder below is the only value terraform ever sees.
resource "aws_ssm_parameter" "wrapped_root_key" {
  name        = "/${local.name}/wrapped-root-key"
  description = "KMS-wrapped root sealing key (ciphertext; safe at rest here)"
  type        = "String"
  value       = "PENDING_BOOTSTRAP"

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "mail_dkim_key" {
  count = var.mail_from == "" ? 0 : 1

  name        = "/${local.name}/mail-dkim-key"
  description = "PKCS#1 RSA private key (PEM) that DKIM-signs login mail"
  type        = "SecureString"
  value       = "PENDING_BOOTSTRAP"

  lifecycle {
    ignore_changes = [value]

    precondition {
      condition     = var.mail_sender != "" && var.mail_helo != "" && var.mail_dkim_selector != ""
      error_message = "mail_sender, mail_helo and mail_dkim_selector are all required when mail_from is set."
    }
  }
}

resource "aws_ssm_parameter" "relay_secret" {
  name        = "/${local.name}/relay-secret"
  description = "Shared secret the control plane presents to the relay (abuse control)"
  type        = "SecureString"
  value       = "PENDING_BOOTSTRAP"

  lifecycle {
    ignore_changes = [value]
  }
}

# ---------------------------------------------------------------------------
# The enclave image
# ---------------------------------------------------------------------------
# The EIF is built reproducibly (see scripts/build-enclave.sh) and uploaded
# here, rather than built on the instance. Building on the instance would make
# the running measurement depend on whatever the instance happened to resolve at
# boot, which defeats the point of pinning PCR0.
resource "aws_s3_bucket" "artifacts" {
  bucket = "${local.name}-artifacts-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ---------------------------------------------------------------------------
# Instance identity
# ---------------------------------------------------------------------------
resource "aws_iam_role" "instance" {
  name = "${local.name}-instance"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Session Manager, so the instance needs no inbound SSH and no key pair.
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "instance" {
  name = "${local.name}-instance"
  role = aws_iam_role.instance.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadTheEnclaveImage"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.artifacts.arn}/*"
      },
      {
        # Caddy's certificate store, kept in S3 rather than on the root volume.
        #
        # On spot the host is cattle: an interruption replaces it, and a fresh
        # /var/lib/caddy means Caddy asks Let's Encrypt for a new certificate.
        # LE allows five duplicate certificates per hostname per week, so a bad
        # afternoon would exhaust the quota and leave the relay without TLS for
        # days — an outage caused by the cost optimisation itself.
        #
        # The certificate's private key therefore lives in this bucket. That is
        # a real widening and worth stating plainly: anyone who can read the
        # bucket can impersonate `enclave.cavos.xyz` to the control plane. It
        # does not reach the enclave's secrets — the browser encrypts to an
        # attested key and KMS checks PCR0, neither of which TLS is load-bearing
        # for — but it is not nothing. The bucket blocks public access, is
        # versioned, and is encrypted at rest.
        Sid      = "PersistTheCertificateStore"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = "${aws_s3_bucket.artifacts.arn}/caddy/*"
      },
      {
        Sid      = "ListForCaddySync"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.artifacts.arn
        Condition = {
          StringLike = { "s3:prefix" = ["caddy/*", "caddy"] }
        }
      },
      {
        # Under an autoscaling group the instance is replaced without terraform
        # in the loop, so nothing outside can move the address for it. It claims
        # the address itself at boot; `--allow-reassociation` is what lets it
        # take over from the instance it is replacing.
        Sid      = "ClaimTheElasticIp"
        Effect   = "Allow"
        Action   = ["ec2:AssociateAddress", "ec2:DescribeAddresses"]
        Resource = "*"
      },
      {
        Sid    = "ReadItsOwnConfiguration"
        Effect = "Allow"
        Action = ["ssm:GetParameter", "ssm:GetParameters"]
        Resource = concat(
          [
            aws_ssm_parameter.wrapped_root_key.arn,
            aws_ssm_parameter.relay_secret.arn,
          ],
          aws_ssm_parameter.mail_dkim_key[*].arn,
        )
      },
      {
        # Note there is no kms:Decrypt here. The instance role is granted that
        # by the *key* policy, and only under the attestation condition. Adding
        # it to the identity policy would not widen access — both must allow —
        # but leaving it out keeps the grant readable in exactly one place.
        Sid      = "DecryptItsOwnSsmParameters"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "ssm.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      },
    ]
  })
}

resource "aws_iam_instance_profile" "instance" {
  name = "${local.name}-instance"
  role = aws_iam_role.instance.name
}

module "host_us_east_1" {
  source = "./host"

  name                  = local.name
  host_count            = var.host_count_us_east_1
  instance_types        = var.instance_types
  availability_zones    = var.availability_zones
  root_volume_size      = var.root_volume_size
  ssh_ingress_cidrs     = var.ssh_ingress_cidrs
  instance_profile_name = aws_iam_instance_profile.instance.name
  user_data_template    = "${path.module}/user-data.sh"
  user_data_vars = {
    region              = var.region
    hostname            = var.hostname
    artifacts_bucket    = aws_s3_bucket.artifacts.bucket
    enclave_cpu_count   = var.enclave_cpu_count
    enclave_memory_mib  = var.enclave_memory_mib
    root_key_param      = aws_ssm_parameter.wrapped_root_key.name
    relay_secret_param  = aws_ssm_parameter.relay_secret.name
    mail_from           = var.mail_from
    mail_sender         = var.mail_sender
    mail_helo           = var.mail_helo
    mail_dkim_selector  = var.mail_dkim_selector
    mail_dkim_key_param = length(aws_ssm_parameter.mail_dkim_key) == 0 ? "" : aws_ssm_parameter.mail_dkim_key[0].name
  }
}

module "host_us_east_2" {
  source = "./host"

  providers = {
    aws = aws.us_east_2
  }

  name                  = local.name
  host_count            = var.host_count_us_east_2
  instance_types        = var.instance_types_us_east_2
  availability_zones    = var.availability_zones_us_east_2
  root_volume_size      = var.root_volume_size
  ssh_ingress_cidrs     = var.ssh_ingress_cidrs
  instance_profile_name = aws_iam_instance_profile.instance.name
  user_data_template    = "${path.module}/user-data-split-region.sh"
  user_data_vars = {
    region              = "us-east-2"
    control_region      = var.region
    hostname            = var.hostname
    artifacts_bucket    = aws_s3_bucket.artifacts.bucket
    enclave_cpu_count   = var.enclave_cpu_count
    enclave_memory_mib  = var.enclave_memory_mib
    root_key_param      = aws_ssm_parameter.wrapped_root_key.name
    relay_secret_param  = aws_ssm_parameter.relay_secret.name
    mail_from           = var.mail_from
    mail_sender         = var.mail_sender
    mail_helo           = var.mail_helo
    mail_dkim_selector  = var.mail_dkim_selector
    mail_dkim_key_param = length(aws_ssm_parameter.mail_dkim_key) == 0 ? "" : aws_ssm_parameter.mail_dkim_key[0].name
  }
}
