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
  supported_azs = setintersection(toset(var.availability_zones), [
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

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
resource "aws_security_group" "instance" {
  name        = "${var.name}-instance"
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
  tags   = { Name = "${var.name}-eip" }
}

# ---------------------------------------------------------------------------
# The host
# ---------------------------------------------------------------------------
resource "aws_launch_template" "enclave_host" {
  name_prefix   = "${var.name}-"
  image_id      = data.aws_ami.al2023_arm64.id
  instance_type = var.instance_types[0]

  iam_instance_profile {
    name = var.instance_profile_name
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

  user_data = base64encode(templatefile(var.user_data_template, merge(var.user_data_vars, {
    eip_allocation_id = aws_eip.instance.id
  })))

  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "${var.name}-host" }
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
  name                = "${var.name}-host"
  vpc_zone_identifier = data.aws_subnets.default.ids

  min_size = var.host_count
  # One more than the fleet, so capacity rebalancing can start a replacement
  # before retiring the instance it replaces. Zero when the service is off.
  max_size         = var.host_count == 0 ? 0 : var.host_count + 1
  desired_capacity = var.host_count

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
      # across three zones is fifteen capacity pools, and
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
      # for 1 vCPU and 1 GiB regardless. Burstable types are absent because no
      # t3 or t4g instance supports enclaves at all.
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
    value               = "${var.name}-host"
    propagate_at_launch = true
  }

  timeouts {
    delete = "15m"
  }
}
