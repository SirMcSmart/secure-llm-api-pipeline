variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name" {
  type    = string
  default = "docqa"
}

variable "vpc_cidr" {
  type    = string
  default = "10.40.0.0/16"
}

variable "availability_zones" {
  description = "Exactly two AZs, pinned so the subnet layout never changes underneath a deployment."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
  validation {
    condition     = length(var.availability_zones) == 2
    error_message = "Provide exactly two availability zones."
  }
}

variable "allowed_ingress_cidrs" {
  description = "Client networks allowed to reach the HTTPS listener (no 0.0.0.0/0 by default)."
  type        = list(string)
  default     = ["203.0.113.0/24"] # TEST-NET-3 placeholder
}

variable "certificate_arn" {
  description = "ACM certificate for the HTTPS listener."
  type        = string
  default     = "arn:aws:acm:us-east-1:111122223333:certificate/00000000-0000-0000-0000-000000000000"
}

variable "image_tag" {
  description = "Immutable image tag (git SHA) built and scanned by CI."
  type        = string
  default     = "0000000"
}

variable "desired_count" {
  type    = number
  default = 2
}
