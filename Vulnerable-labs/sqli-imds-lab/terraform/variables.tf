variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "ap-southeast-1"
}

variable "project_name" {
  description = "Prefix used to name/tag all resources."
  type        = string
  default     = "sqli-imds-lab"
}

variable "player_id" {
  description = "Arbitrary id used to namespace the IAM role name and S3 flag path."
  type        = string
  default     = "1"
}

variable "instance_type" {
  description = "EC2 instance type for the vulnerable app host."
  type        = string
  default     = "t3.micro"
}

variable "my_ip_cidr" {
  description = "Your IP in CIDR form (e.g. 203.0.113.7/32), used to restrict SSH. Get it with `curl -s ifconfig.me`."
  type        = string
  default     = "183.82.24.178/32"
}

variable "key_name" {
  description = "Existing EC2 key pair name for SSH access. Leave null to rely on SSM Session Manager only."
  type        = string
  default     = null
}

variable "vpc_cidr" {
  type    = string
  default = "10.42.0.0/16"
}

variable "subnet_cidr" {
  type    = string
  default = "10.42.1.0/24"
}
