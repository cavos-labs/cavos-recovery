variable "name" {
  description = "Name prefix for the security group, launch template, Elastic IP tag and autoscaling group."
  type        = string
}

variable "host_count" {
  description = "How many enclave hosts to run in this region. One, or zero to turn the host off."
  type        = number
}

variable "instance_types" {
  description = "Graviton instance types the spot fleet may draw from. The first is the launch template's own type; every entry is an override."
  type        = list(string)
}

variable "availability_zones" {
  description = "Zones the host may launch in, intersected with the zones that offer every type in instance_types."
  type        = list(string)
}

variable "root_volume_size" {
  description = "Root volume in GiB."
  type        = number
}

variable "ssh_ingress_cidrs" {
  description = "CIDRs allowed to reach SSH. Empty keeps port 22 closed."
  type        = list(string)
}

variable "instance_profile_name" {
  description = "Name of the IAM instance profile attached to the host. IAM is global, so one profile serves every region."
  type        = string
}

variable "user_data_template" {
  description = "Path to the user-data template rendered for this host."
  type        = string
}

variable "user_data_vars" {
  description = "Variables passed to the user-data template. The module adds eip_allocation_id itself."
  type        = map(string)
}
