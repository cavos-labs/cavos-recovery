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

output "release_keys" {
  description = <<-EOT
    The sealing key of each release. `arn` is what the release's image compiles
    in as `ROOT_KEY_ARN`; `sealed` says whether its policy is final.
  EOT
  value = {
    for release, key in module.release_key : release => {
      arn    = key.arn
      sealed = key.sealed
      pcr0   = var.enclave_releases[release].pcr0
    }
  }
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

output "security_alerts_topic_arn" {
  description = "SNS topic (default region) that receives the custody-relevant security alerts. The email subscription must be confirmed once."
  value       = aws_sns_topic.security_alerts.arn
}
