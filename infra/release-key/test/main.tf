# A throwaway key that goes through the same module as a real release, for
# `run.sh` to seal and then try to break.

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Project = "cavos-confidential-recovery"
      Purpose = "disposable-release-key-test"
    }
  }
}

variable "alias" {
  type = string
}

variable "pcr0" {
  type    = string
  default = null
}

data "aws_iam_role" "enclave_host" {
  name = "cavos-recovery-instance"
}

module "key" {
  source = "../"

  alias            = var.alias
  pcr0             = var.pcr0
  enclave_role_arn = data.aws_iam_role.enclave_host.arn
}

output "arn" {
  value = module.key.arn
}
