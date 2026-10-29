output "elastic_ip" {
  description = "Public address of this region's host."
  value       = aws_eip.instance.public_ip
}

output "eip_allocation_id" {
  description = "Allocation id of the Elastic IP the host claims at boot."
  value       = aws_eip.instance.id
}

output "autoscaling_group" {
  description = "Name of this region's autoscaling group."
  value       = aws_autoscaling_group.enclave_host.name
}
