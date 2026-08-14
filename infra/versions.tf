terraform {
  required_version = ">= 1.6"

  # State is local for now. It tracks a KMS key and an instance profile, so it
  # is worth moving to S3 with versioning before more than one person applies.
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "cavos-confidential-recovery"
      ManagedBy = "terraform"
    }
  }
}
