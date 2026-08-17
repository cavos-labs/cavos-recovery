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
    headroom. The m-family entries are the same 2 vCPUs with more memory, which
    the allocator ignores; they are here for capacity breadth, not performance.

    The list is what makes running 100% spot reasonable. One instance type in
    one subnet is a single capacity pool and a single point of reclamation; five
    types across the default subnets is roughly twenty-five, and the allocation
    strategy picks the deepest. Every entry must support Nitro Enclaves — check
    with `aws ec2 describe-instance-types --filters
    Name=nitro-enclaves-support,Values=supported` before adding one. No
    burstable (t3/t4g) instance qualifies.
  EOT
  type        = list(string)
  default     = ["c6g.large", "c7g.large", "m6g.large", "m7g.large", "c8g.large"]

  validation {
    condition     = length(var.instance_types) > 0
    error_message = "At least one instance type is required."
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
  default     = "3a97720a6e8a7a0ce034703be64d12e6ceadabdedf807656df6516770848da70f9f3a69ba355ccd4d1b1fc7ac3116aa4"

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

variable "host_count" {
  description = <<-EOT
    How many enclave hosts to run. One, or zero to turn the service off.

    Zero is a real operating state, not a broken one: the enclave holds no
    durable state. The wrapped root key lives in Parameter Store, the image and
    the relay binary in S3, and the KMS key policy is untouched — so coming back
    is this variable and an apply, with nothing to restore.

    While it is zero, social recovery does not work: no enrolment, no recovery.
    Wallets keep signing, because that is the device signer against the contract
    on-chain and has never involved this host. No funds are at risk either way.
  EOT
  type        = number
  default     = 0

  validation {
    condition     = var.host_count >= 0 && var.host_count <= 1
    error_message = "The enclave host is a singleton: 0 or 1."
  }
}
