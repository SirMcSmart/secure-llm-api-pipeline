terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# Validated and scanned only. This project never runs `terraform apply` and CI holds no cloud credentials.
provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project   = "secure-llm-api-pipeline"
      ManagedBy = "terraform"
    }
  }
}
