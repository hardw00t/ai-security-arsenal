###############################################################################
# Intentionally-vulnerable Terraform fixture for IaC scanner testing.
# DO NOT apply to a real AWS account. Used by:
#   - workflows/policy_as_code_loop.md
#   - references/terraform.md scanner regression tests
# Each block is annotated with the primary rule it should trip.
###############################################################################

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

# FAIL: CKV_AWS_19 / CKV_AWS_21 / CKV_AWS_18 / aws-s3-enable-bucket-encryption
# - no encryption, no versioning, no access logging, public ACL
resource "aws_s3_bucket" "public_data" {
  bucket = "company-public-data"
  acl    = "public-read"
  tags = {
    Name = "public-data"
    # Missing Environment / Owner / DataClassification tags
  }
}

# FAIL: CKV_AWS_24 / aws-vpc-no-public-ingress-sgr
# - 0.0.0.0/0 on SSH
resource "aws_security_group" "wide_open" {
  name        = "wide-open"
  description = "Allows SSH from anywhere"
  vpc_id      = "vpc-00000000"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# FAIL: CKV_AWS_17 / CKV_AWS_16 / aws-rds-encrypt-instance-storage-data
# - publicly accessible, unencrypted storage, hardcoded password
resource "aws_db_instance" "legacy" {
  identifier           = "legacy"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "SuperSecret123!"   # FAIL: hardcoded secret
  publicly_accessible  = true                # FAIL: public RDS
  storage_encrypted    = false               # FAIL: unencrypted
  skip_final_snapshot  = true
}

# FAIL: CKV_AWS_40 / aws-iam-no-policy-wildcards
# - IAM policy with *:*
resource "aws_iam_policy" "admin_star" {
  name = "admin-star"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# FAIL: CKV_AWS_7 / aws-kms-enable-key-rotation
# - KMS key without rotation
resource "aws_kms_key" "no_rotation" {
  description         = "Does not rotate"
  enable_key_rotation = false
}

# FAIL: CKV_AWS_3 / aws-ebs-encryption-by-default
# - unencrypted EBS volume
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = false
}

# FAIL: CKV_AWS_20 / aws-s3-block-public-acls
# - S3 bucket without public access block
resource "aws_s3_bucket_public_access_block" "missing_on_purpose" {
  bucket                  = aws_s3_bucket.public_data.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# FAIL: CKV_AWS_126 / aws-vpc-flow-logs-enabled (absence)
# VPC defined without companion flow log resource — many scanners flag.
resource "aws_vpc" "no_flow_logs" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "no-flow-logs"
  }
}

# FAIL: CKV_AWS_91 / aws-elb-logging-enabled
# - ALB without access logs
resource "aws_lb" "no_logs" {
  name               = "no-logs"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.wide_open.id]
  subnets            = ["subnet-00000000", "subnet-11111111"]
  # access_logs block intentionally omitted
}
