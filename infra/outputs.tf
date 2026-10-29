output "elastic_ip" {
  description = <<-EOT
    Point an A record for `var.hostname` at this address, wherever cavos.xyz's
    DNS is hosted. Caddy cannot obtain a certificate until that record resolves,
    so the relay stays unreachable over HTTPS until this step is done.
  EOT
  value       = module.host_us_east_1.elastic_ip
}

output "elastic_ip_us_east_2" {
  description = "Address of the us-east-2 host. Point `var.hostname` here at the DNS cutover."
  value       = module.host_us_east_2.elastic_ip
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

output "autoscaling_group" {
  description = <<-EOT
    The host is a spot instance in this group, so its id changes whenever AWS
    reclaims capacity. Find the current one with:

      aws autoscaling describe-auto-scaling-groups \
        --auto-scaling-group-names <this> \
        --query 'AutoScalingGroups[0].Instances[0].InstanceId' --output text

    then `aws ssm start-session --target <that>`.
  EOT
  value       = module.host_us_east_1.autoscaling_group
}

output "autoscaling_group_us_east_2" {
  description = "The us-east-2 host's autoscaling group; same lookup as above with `--region us-east-2`."
  value       = module.host_us_east_2.autoscaling_group
}
