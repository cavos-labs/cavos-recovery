output "elastic_ip" {
  description = <<-EOT
    Point an A record for `var.hostname` at this address, wherever cavos.xyz's
    DNS is hosted. Caddy cannot obtain a certificate until that record resolves,
    so the relay stays unreachable over HTTPS until this step is done.
  EOT
  value = aws_eip.instance.public_ip
}

output "relay_url" {
  description = "Set this as CAVOS_RECOVERY_ENCLAVE_URL in the control plane."
  value       = "https://${var.hostname}"
}

output "artifacts_bucket" {
  description = "Upload enclave.eif and the relay binary here before first boot."
  value       = aws_s3_bucket.artifacts.bucket
}

output "kms_key_arn" {
  description = "Root sealing key. Only an enclave measuring to enclave_pcr0 can decrypt with it."
  value       = aws_kms_key.root.arn
}

output "enclave_pcr0" {
  description = "The measurement this deployment trusts. Must match the value pinned in @cavos/kit."
  value       = var.enclave_pcr0
}

output "instance_id" {
  description = "Connect with: aws ssm start-session --target <this>"
  value       = aws_instance.enclave_host.id
}
