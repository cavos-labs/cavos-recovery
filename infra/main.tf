data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Default VPC. This stack is one instance with a public address; carving out a
# dedicated VPC would add NAT gateways and cost without changing the security
# story, which rests on the enclave's attestation rather than on the network.
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

data "aws_ami" "al2023_arm64" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-kernel-6.1-arm64"]
  }
}

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
        Action = [
          "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*",
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
        Action    = ["kms:GenerateDataKeyWithoutPlaintext", "kms:Encrypt"]
        Resource  = "*"
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
        Sid      = "ReadItsOwnConfiguration"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter", "ssm:GetParameters"]
        Resource = [
          aws_ssm_parameter.wrapped_root_key.arn,
          aws_ssm_parameter.relay_secret.arn,
        ]
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

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
resource "aws_security_group" "instance" {
  name        = "${local.name}-instance"
  description = "Cavos recovery relay"
  vpc_id      = data.aws_vpc.default.id

  # 443 is open to the internet because the control plane calls it from Vercel,
  # whose egress addresses are not fixed. This is safe by design rather than by
  # network position: the body is encrypted to the enclave, the relay
  # authenticates callers with a shared secret, and a compromised relay can
  # deny service but cannot read a credential.
  ingress {
    description = "HTTPS from the control plane"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Let's Encrypt's HTTP-01 challenge.
  ingress {
    description = "ACME challenge"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  dynamic "ingress" {
    for_each = length(var.ssh_ingress_cidrs) > 0 ? [1] : []
    content {
      description = "SSH (normally closed; use SSM Session Manager)"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = var.ssh_ingress_cidrs
    }
  }

  egress {
    description = "Outbound: KMS, provider JWKS, package and image pulls"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------------------------------------------------------------------------
# The instance
# ---------------------------------------------------------------------------
resource "aws_instance" "enclave_host" {
  ami                    = data.aws_ami.al2023_arm64.id
  instance_type          = var.instance_type
  subnet_id              = data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.instance.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name

  enclave_options {
    enabled = true
  }

  metadata_options {
    http_tokens   = "required" # IMDSv2 only.
    http_endpoint = "enabled"
  }

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = templatefile("${path.module}/user-data.sh", {
    region             = var.region
    hostname           = var.hostname
    artifacts_bucket   = aws_s3_bucket.artifacts.bucket
    enclave_cpu_count  = var.enclave_cpu_count
    enclave_memory_mib = var.enclave_memory_mib
    root_key_param     = aws_ssm_parameter.wrapped_root_key.name
    relay_secret_param = aws_ssm_parameter.relay_secret.name
  })

  # Changing user_data should rebuild the host; it is the whole bootstrap.
  user_data_replace_on_change = true

  tags = { Name = "${local.name}-host" }
}

# A stable address, so the DNS record does not have to change when the instance
# is replaced. Free while it stays associated.
resource "aws_eip" "instance" {
  instance = aws_instance.enclave_host.id
  domain   = "vpc"
  tags     = { Name = "${local.name}-eip" }
}
