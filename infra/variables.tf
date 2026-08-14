variable "region" {
  description = "AWS region. Nitro Enclaves are available in all regions."
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = <<-EOT
    Graviton instance hosting the enclave. Graviton is used because its enclave
    minimum is 2 vCPUs where Intel/AMD need 4, which halves the bill.

    c6g.large (2 vCPU / 4 GB, ~$50/mo) gives the enclave 1 vCPU and the parent
    1. Graviton has no SMT so that split is real, not shared. It is enough for
    this workload — roughly two seconds of P-256 and AES per request — but it
    has no headroom. If bring-up shows contention, c6g.xlarge is a one-line
    change and a re-apply.
  EOT
  type        = string
  default     = "c6g.large"
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
    root sealing key to anything that does not measure to it. It must match the
    value pinned in `@cavos/kit`, or browsers and KMS will disagree about which
    enclave is legitimate.
  EOT
  type        = string
  default     = "f2f81237afb5ecd3287e622c711bef8e5fe382f13c549794e478be3f54877d0c0c80a7bc9f97150fc28150130f373f87"

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
