output "arn" {
  description = "ARN of the key. Compile it into the release's image as `ROOT_KEY_ARN`."
  value       = aws_kms_key.this.arn
}

output "sealed" {
  description = "Whether the policy is final."
  value       = local.sealed
}
