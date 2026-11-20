variable "alias" {
  description = "Alias of the key, without the `alias/` prefix. It can never be renamed once the key is sealed."
  type        = string
}

variable "pcr0" {
  description = <<-EOT
    Measurement of the one enclave image allowed to decrypt with this key.

    Leave it null to create the key before its image exists: the key ARN is
    compiled into the image, so the key has to come first. Setting it seals the
    key, and sealing cannot be undone or repeated.
  EOT
  type        = string
  default     = null

  validation {
    condition     = var.pcr0 == null || can(regex("^[0-9a-f]{96}$", var.pcr0))
    error_message = "PCR0 must be 96 lowercase hex characters (a SHA-384 digest)."
  }

  validation {
    condition     = var.pcr0 == null || var.pcr0 != join("", [for _ in range(96) : "0"])
    error_message = "PCR0 must not be all zeros. That is what an enclave started in debug mode reports, and the key policy must never trust it."
  }
}

variable "enclave_role_arn" {
  description = "Role of the enclave host. It decrypts only through an enclave measuring to `pcr0`."
  type        = string
}
