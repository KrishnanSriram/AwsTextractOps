terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
  }
}

# ---------- Variables ----------

variable "region" {
  description = "AWS region. The bucket and the Textract endpoint must be in the same region."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "textract-test"
}

variable "iam_user_name" {
  description = "Optional: existing IAM user to attach the Textract policy to. Leave null to skip."
  type        = string
  default     = null
}

provider "aws" {
  region = var.region
}

# ---------- S3 bucket for input documents ----------

resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "docs" {
  bucket        = "${var.name_prefix}-${random_id.suffix.hex}"
  force_destroy = true # lets `terraform destroy` remove the bucket even if it has files
}

resource "aws_s3_bucket_public_access_block" "docs" {
  bucket                  = aws_s3_bucket.docs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------- IAM policy: call Textract + read/write the bucket ----------
# Textract reads the S3 object using the caller's credentials, so the caller
# needs s3:GetObject on the bucket as well as the textract:* actions.

data "aws_iam_policy_document" "textract" {
  statement {
    sid    = "Textract"
    effect = "Allow"
    actions = [
      "textract:DetectDocumentText",
      "textract:AnalyzeDocument",
      "textract:StartDocumentTextDetection",
      "textract:GetDocumentTextDetection",
      "textract:StartDocumentAnalysis",
      "textract:GetDocumentAnalysis",
    ]
    resources = ["*"] # Textract actions don't support resource-level permissions
  }

  statement {
    sid       = "BucketObjects"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.docs.arn}/*"]
  }

  statement {
    sid       = "BucketList"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.docs.arn]
  }
}

resource "aws_iam_policy" "textract" {
  name   = "${var.name_prefix}-${random_id.suffix.hex}"
  policy = data.aws_iam_policy_document.textract.json
}

resource "aws_iam_user_policy_attachment" "textract" {
  count      = var.iam_user_name == null ? 0 : 1
  user       = var.iam_user_name
  policy_arn = aws_iam_policy.textract.arn
}

# ---------- Outputs ----------

output "bucket_name" {
  value = aws_s3_bucket.docs.bucket
}

output "policy_arn" {
  value = aws_iam_policy.textract.arn
}

output "region" {
  value = var.region
}
