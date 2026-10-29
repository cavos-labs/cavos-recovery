variable "region" {
  description = "AWS region. Nitro Enclaves are available in all regions."
  type        = string
  default     = "us-east-1"
}

variable "instance_types" {
  description = <<-EOT
    Graviton instances the spot fleet may draw from, in order of preference.
    Graviton is used because its enclave minimum is 2 vCPUs where Intel/AMD need
    4, which halves the bill.

    c6g.large (2 vCPU / 4 GB) gives the enclave 1 vCPU and the parent 1.
    Graviton has no SMT so that split is real, not shared. It is enough for this
    workload — roughly two seconds of P-256 and AES per request — but it has no
    headroom.

    The list is what makes running 100% spot reasonable. One instance type in
    one subnet is a single capacity pool and a single point of reclamation; five
    types across three zones is fifteen, and the allocation strategy picks the
    deepest. Every entry must support Nitro Enclaves — check with
    `aws ec2 describe-instance-types --filters
    Name=nitro-enclaves-support,Values=supported` before adding one. No
    burstable (t3/t4g) instance qualifies.

    The set is chosen on price as much as breadth, because the autoscaling
    group picks a pool only at launch and stays in it however far its price
    drifts. m6g and m7g were dropped in October 2026: over the previous 90 days
    they averaged $0.030-0.050/h against $0.024-0.030/h for the c-family in the
    zones below, and the host had settled in a c8g pool that drifted from
    $0.030 to $0.040/h. Re-check `get-spot-placement-scores` before trimming:
    c6g, c6gd and c7g alone score 1 of 10 in us-east-1c/d/f, and only adding
    c8g and c6gn brings every zone to 9.
  EOT
  type        = list(string)
  default     = ["c6g.large", "c6gd.large", "c7g.large", "c8g.large", "c6gn.large"]

  validation {
    condition     = length(var.instance_types) > 0
    error_message = "At least one instance type is required."
  }
}

variable "availability_zones" {
  description = <<-EOT
    Zones the host may launch in, intersected with the zones that offer every
    type in var.instance_types. us-east-1a and 1b are left out on price: every
    type above averaged more there over the 90 days to October 2026 (c6g $0.030
    and $0.031/h in 1a and 1b against $0.024-0.026/h in 1c, 1d and 1f).
  EOT
  type        = list(string)
  default     = ["us-east-1c", "us-east-1d", "us-east-1f"]

  validation {
    condition     = length(var.availability_zones) > 0
    error_message = "At least one availability zone is required."
  }
}

variable "root_volume_size" {
  description = <<-EOT
    Root volume in GiB. The host stores the AL2023 base, a handful of packages,
    the enclave image and the relay binary; 10 GiB leaves room without paying
    for empty gp3. Caddy's certificate store is the one thing that must outlive
    the volume, and it lives in S3 for that reason.
  EOT
  type        = number
  default     = 10
}

variable "enclave_cpu_count" {
  description = "vCPUs given to the enclave. The parent keeps the rest."
  type        = number
  default     = 1
}

variable "enclave_memory_mib" {
  description = <<-EOT
    Memory given to the enclave. The workload itself is small, but it links
    OpenSSL statically and holds an RSA keypair plus a bounded session map, so
    1 GiB leaves comfortable margin without starving the parent.
  EOT
  type        = number
  default     = 1024
}

variable "enclave_pcr0" {
  description = <<-EOT
    The measurement of the enclave image, from `scripts/build-enclave.sh`.

    This is the security-critical value: the KMS key policy will not release the
    root sealing key to anything that does not measure to it. It must match a
    value pinned in `@cavos/kit`, or browsers and KMS will disagree about which
    enclave is legitimate.

    Changing it is half of a deploy: KMS will then release the root key only to
    the new image, so the new EIF has to be uploaded in the same step or the
    running enclave dies at boot unable to unwrap it. And the SDK has to accept
    the new measurement *before* either — it is checked in the browser, ahead of
    KMS, so an enclave nobody accepts is one nobody can reach.
  EOT
  type        = string
  default     = "7f32a8b51fabf733339db5425d31851ad2919322581fe21793db17975c44a33702fa9be0c81a391b32049a0daf220cdb"

  validation {
    condition     = can(regex("^[0-9a-f]{96}$", var.enclave_pcr0))
    error_message = "PCR0 must be 96 lowercase hex characters (a SHA-384 digest)."
  }
}

variable "hostname" {
  description = <<-EOT
    Public hostname for the relay. You must point an A record at the Elastic IP
    this stack outputs; Caddy then obtains a Let's Encrypt certificate for it on
    first boot. There is no Route 53 zone for cavos.xyz, so that record is added
    wherever the domain's DNS actually lives.
  EOT
  type        = string
  default     = "enclave.cavos.xyz"
}

variable "ssh_ingress_cidrs" {
  description = <<-EOT
    CIDRs allowed to reach SSH. Empty by default: the instance is managed with
    SSM Session Manager, which needs no inbound port at all. Opening 22 is a
    deliberate act, not a default.
  EOT
  type        = list(string)
  default     = []
}

variable "host_count_us_east_1" {
  description = <<-EOT
    How many enclave hosts to run in us-east-1. One, or zero to turn the host
    off. During the move to us-east-2 both regions may be 1 at once; this goes
    to 0 after the DNS cutover.

    Zero is a real operating state, not a broken one: the enclave holds no
    durable state. The wrapped root key lives in Parameter Store, the image and
    the relay binary in S3, and the KMS key policy is untouched — so coming back
    is this variable and an apply, with nothing to restore.

    While both host counts are zero, social recovery does not work: no
    enrolment, no recovery. Wallets keep signing, because that is the device
    signer against the contract on-chain and has never involved this host. No
    funds are at risk either way.
  EOT
  type        = number
  default     = 1

  validation {
    condition     = var.host_count_us_east_1 >= 0 && var.host_count_us_east_1 <= 1
    error_message = "The enclave host is a singleton: 0 or 1."
  }
}

variable "host_count_us_east_2" {
  description = <<-EOT
    How many enclave hosts to run in us-east-2. One, or zero for none. The KMS
    key, Parameter Store and the artifacts bucket stay in us-east-1; this host
    reaches them across regions. During the migration both regions may be 1 at
    once, and var.host_count_us_east_1 goes to 0 after the DNS cutover.
  EOT
  type        = number
  default     = 0

  validation {
    condition     = var.host_count_us_east_2 >= 0 && var.host_count_us_east_2 <= 1
    error_message = "The enclave host is a singleton: 0 or 1."
  }
}

variable "instance_types_us_east_2" {
  description = <<-EOT
    Graviton instances the us-east-2 spot fleet may draw from, in order of
    preference. 90-day spot averages to October 2026 in us-east-2 were
    $0.013-0.0175/h for c8gn/c7gd/c6gd in their best zones versus ~$0.025/h in
    us-east-1. With these four types every us-east-2 zone scores 9/10 on
    get-spot-placement-scores, while c8gn+c7gd alone score 3.
  EOT
  type        = list(string)
  default     = ["c8gn.large", "c7gd.large", "c6gd.large", "c8g.large"]

  validation {
    condition     = length(var.instance_types_us_east_2) > 0
    error_message = "At least one instance type is required."
  }
}

variable "availability_zones_us_east_2" {
  description = <<-EOT
    Zones the us-east-2 host may launch in, intersected with the zones that
    offer every type in var.instance_types_us_east_2. With the default types
    every zone scores 9/10 on get-spot-placement-scores; c8gn+c7gd alone score 3.
  EOT
  type        = list(string)
  default     = ["us-east-2a", "us-east-2b", "us-east-2c"]

  validation {
    condition     = length(var.availability_zones_us_east_2) > 0
    error_message = "At least one availability zone is required."
  }
}

variable "mail_from" {
  description = <<-EOT
    Visible From address for login codes, e.g. `no-reply@cavos.xyz`. The display
    name beside it is the app the user is signing in to.
    Empty (the default) turns code delivery off: the relay sends the enclave no
    mail configuration and `send_code` answers `email_unavailable`. Setting it
    makes `mail_sender`, `mail_helo` and `mail_dkim_selector` required, and
    creates the SecureString parameter that must then hold the DKIM private key.
  EOT
  type        = string
  default     = "no-reply@cavos.xyz"
}

variable "mail_sender" {
  description = "Envelope sender (the address SPF checks) for login codes. Required when mail_from is set."
  type        = string
  default     = "no-reply@mta.cavos.xyz"
}

variable "mail_helo" {
  description = "Hostname announced in EHLO. Should be the host in the sending IP's PTR and SPF records. Required when mail_from is set."
  type        = string
  default     = "mta.cavos.xyz"
}

variable "mail_dkim_selector" {
  description = "DKIM selector whose public key is published under the mail_sender domain. Required when mail_from is set."
  type        = string
  default     = "otp2"
}
