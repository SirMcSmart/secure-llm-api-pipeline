data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
}

# One customer-managed key for logs, the image repository and the API-key secret.
resource "aws_kms_key" "main" {
  description             = "${var.name} data at rest"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms.json
}

resource "aws_kms_alias" "main" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.main.key_id
}

data "aws_iam_policy_document" "kms" {
  # Triage: in a KMS *key policy*, Resource "*" means "this key", and the account-root statement is
  # the AWS default that delegates key access to IAM policies (which are least-privilege, see iam.tf).
  #checkov:skip=CKV_AWS_111:Key policy; "*" is this key only. Root statement delegates to scoped IAM policies.
  #checkov:skip=CKV_AWS_356:Key policy; "*" is this key only.
  #checkov:skip=CKV_AWS_109:Key policy; the root statement is required so the key stays manageable.
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"] # in a key policy "*" means this key only
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }
  statement {
    sid       = "CloudWatchLogs"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${local.partition}:logs:${var.region}:${local.account_id}:log-group:/${var.name}/*"]
    }
  }
}
