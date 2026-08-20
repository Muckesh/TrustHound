terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# Networking — a minimal public VPC. Nothing fancy; the point of this lab is
# the app + IAM chain, not the network topology.
# ---------------------------------------------------------------------------

resource "aws_vpc" "lab" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = { Name = "${var.project_name}-vpc" }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "${var.project_name}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block               = var.subnet_cidr
  map_public_ip_on_launch  = true
  availability_zone        = data.aws_availability_zones.available.names[0]
  tags = { Name = "${var.project_name}-public" }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }
  tags = { Name = "${var.project_name}-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "app" {
  name        = "${var.project_name}-sg"
  description = "Public HTTP for the vulnerable app; SSH restricted to operator IP"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "HTTP - the vulnerable website"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH - operator only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-sg" }
}

# ---------------------------------------------------------------------------
# IAM — the role the attacker is after. Scoped to one S3 prefix so the
# "capture the flag" step proves the stolen credentials actually work,
# without the role being wide open to the whole account.
# ---------------------------------------------------------------------------

resource "aws_iam_role" "app" {
  name = "${var.project_name}-player-${var.player_id}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flag_read" {
  name = "${var.project_name}-flag-read"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.flags.arn
        Condition = {
          StringLike = { "s3:prefix" = ["players/${var.player_id}/*"] }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.flags.arn}/players/${var.player_id}/*"
      }
    ]
  })
}

# Lets you also `aws ssm start-session` in instead of relying on SSH.
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "app" {
  name = "${var.project_name}-player-${var.player_id}"
  role = aws_iam_role.app.name
}

# ---------------------------------------------------------------------------
# S3 — private bucket with a flag object only the stolen role can read.
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "flags" {
  bucket = "${var.project_name}-flags-${data.aws_caller_identity.current.account_id}"
  tags   = { Name = "${var.project_name}-flags" }
}

resource "aws_s3_bucket_public_access_block" "flags" {
  bucket                  = aws_s3_bucket.flags.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "flag" {
  bucket       = aws_s3_bucket.flags.id
  key          = "players/${var.player_id}/flag.txt"
  content      = "SQLIIMDS{sql_injection_pgsql_http_extension_imdsv2_credential_theft_${var.player_id}}"
  content_type = "text/plain"
}

# ---------------------------------------------------------------------------
# EC2 — the vulnerable app host. Ubuntu 24.04 LTS, IMDSv2 required. Hop
# limit is 2 (not the default 1) because the app/db run inside Docker
# containers — a container is one extra network hop past the instance's own
# ENI, and IMDSv2 replies get dropped past the configured hop limit.
# ---------------------------------------------------------------------------

data "aws_ssm_parameter" "ubuntu_ami" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

locals {
  app_dir = "${path.module}/../app"
  db_dir  = "${path.module}/../db"
}

resource "aws_instance" "app" {
  ami                    = data.aws_ssm_parameter.ubuntu_ami.value
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.app.id]
  iam_instance_profile   = aws_iam_instance_profile.app.name
  key_name               = var.key_name

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 2
  }

  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    app_py_b64            = filebase64("${local.app_dir}/app.py")
    app_requirements_b64  = filebase64("${local.app_dir}/requirements.txt")
    app_dockerfile_b64    = filebase64("${local.app_dir}/Dockerfile")
    db_dockerfile_b64     = filebase64("${local.db_dir}/Dockerfile")
    db_init_sql_b64       = filebase64("${local.db_dir}/init.sql")
    docker_compose_b64    = filebase64("${path.module}/../docker-compose.yml")
  })

  tags = { Name = "${var.project_name}-app" }
}
