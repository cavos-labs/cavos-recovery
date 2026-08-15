data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Default VPC. This stack is one instance with a public address; carving out a
# dedicated VPC would add NAT gateways and cost without changing the security
# story, which rests on the enclave's attestation rather than on the network.
data "aws_vpc" "default" {
  default = true
}

# Not every availability zone offers every instance type. us-east-1e is the
# live example: it is in the default VPC and offers no Graviton at all, so an
# autoscaling group handed the full subnet list will eventually try to place
# there and fail the whole scaling activity with InvalidFleetConfiguration.
#
# Rather than hard-coding the exclusion, ask EC2 which zones offer each type in
# the fleet and keep only the zones that offer all of them. Adding an instance
# type to var.instance_types then narrows the zone list on its own.
data "aws_ec2_instance_type_offerings" "by_az" {
  for_each = toset(var.instance_types)

  location_type = "availability-zone"

  filter {
    name   = "instance-type"
    values = [each.value]
  }
}

locals {
  supported_azs = setintersection([
    for offering in data.aws_ec2_instance_type_offerings.by_az : toset(offering.locations)
  ]...)
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }

  filter {
    name   = "availability-zone"
    values = tolist(local.supported_azs)
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
# The address
# ---------------------------------------------------------------------------
# Declared before the host, and no longer attached to it. Under an autoscaling
# group there is no long-lived instance to bind to, so the address stands alone
# and each instance claims it at boot (see `ClaimTheElasticIp` above). The DNS
# record for var.hostname keeps pointing here across every replacement.
resource "aws_eip" "instance" {
  domain = "vpc"
  tags   = { Name = "${local.name}-eip" }
}

# ---------------------------------------------------------------------------
# The host
# ---------------------------------------------------------------------------
resource "aws_launch_template" "enclave_host" {
  name_prefix   = "${local.name}-"
  image_id      = data.aws_ami.al2023_arm64.id
  instance_type = var.instance_types[0]

  iam_instance_profile {
    name = aws_iam_instance_profile.instance.name
  }

  vpc_security_group_ids = [aws_security_group.instance.id]

  enclave_options {
    enabled = true
  }

  metadata_options {
    http_tokens   = "required" # IMDSv2 only.
    http_endpoint = "enabled"
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = var.root_volume_size
      volume_type = "gp3"
      encrypted   = true
    }
  }

  user_data = base64encode(templatefile("${path.module}/user-data.sh", {
    region             = var.region
    hostname           = var.hostname
    artifacts_bucket   = aws_s3_bucket.artifacts.bucket
    enclave_cpu_count  = var.enclave_cpu_count
    enclave_memory_mib = var.enclave_memory_mib
    root_key_param     = aws_ssm_parameter.wrapped_root_key.name
    relay_secret_param = aws_ssm_parameter.relay_secret.name
    eip_allocation_id  = aws_eip.instance.id
  }))

  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "${local.name}-host" }
  }

  lifecycle {
    create_before_destroy = true
  }
}

# One instance, bought on the spot market.
#
# The workload is a good fit for spot in a way that is worth being explicit
# about: the enclave holds no durable state. It re-fetches the wrapped root key
# from Parameter Store and unwraps it against KMS on every boot, so a replaced
# host rebuilds itself from scratch with no data to restore. An interruption is
# an outage, not a loss.
#
# What it costs is availability. There are no retries in `@cavos/kit`'s recovery
# client — every failure path throws — so a user who calls enrol or recover
# during a replacement sees a hard error rather than a pause. Baking a golden
# AMI (boot is currently 3-6 minutes of `dnf install`) and adding client-side
# backoff would both shrink that window substantially; neither is done yet.
resource "aws_autoscaling_group" "enclave_host" {
  name                = "${local.name}-host"
  vpc_zone_identifier = data.aws_subnets.default.ids

  min_size         = 1
  max_size         = 2 # Headroom for capacity rebalancing to start the replacement first.
  desired_capacity = 1

  # Replace the host when AWS signals it is at elevated risk of interruption,
  # rather than waiting for the two-minute termination notice. The replacement
  # claims the Elastic IP with `--allow-reassociation`, so the handover needs no
  # coordination. Sessions are the one casualty: they live in enclave memory, so
  # a session opened against the outgoing host cannot complete against the new
  # one. They are single-use and short-lived, and the client starts a fresh one.
  capacity_rebalance = true

  health_check_type         = "EC2"
  health_check_grace_period = 600 # Cold boot installs packages; see the golden-AMI note.

  mixed_instances_policy {
    instances_distribution {
      # 100% spot. At capacity 1 any on-demand base would mean paying the
      # on-demand price for the only instance, which is the whole point of this
      # change. Durability comes from breadth instead: five instance types
      # across every default subnet is roughly twenty-five capacity pools, and
      # `price-capacity-optimized` picks the one least likely to be reclaimed.
      on_demand_base_capacity                  = 0
      on_demand_percentage_above_base_capacity = 0
      spot_allocation_strategy                 = "price-capacity-optimized"
    }

    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.enclave_host.id
        version            = aws_launch_template.enclave_host.latest_version
      }

      # Every type here is arm64, has at least 2 vCPUs, and supports Nitro
      # Enclaves — verified with `describe-instance-types`. The allocator asks
      # for 1 vCPU and 1 GiB regardless, so the larger m-family members simply
      # leave more for the parent. Burstable types are absent because no t3 or
      # t4g instance supports enclaves at all.
      dynamic "override" {
        for_each = var.instance_types
        content {
          instance_type = override.value
        }
      }
    }
  }

  # Roll the fleet when the launch template changes; user_data is the whole
  # bootstrap, so a change to it has to reach the running host.
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 0 # Capacity 1: the old host must go before the new one arrives.
    }
  }

  tag {
    key                 = "Name"
    value               = "${local.name}-host"
    propagate_at_launch = true
  }

  timeouts {
    delete = "15m"
  }
}
