locals {
  audit_access_enabled = module.this.enabled && var.audit_access_enabled
  audit_account_id     = module.account_map.outputs.full_account_map[module.account_map.outputs.audit_account_account_name]

  kms_key_alias    = var.kms_key_alias != null ? var.kms_key_alias : format("alias/%s", module.this.id)
  kms_abac_enabled = length(var.kms_abac_statements) > 0

}

module "kms_key_cloudtrail" {
  source  = "cloudposse/kms-key/aws"
  version = "0.12.2"

  description             = "KMS key for CloudTrail"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  policy                  = join("", data.aws_iam_policy_document.kms_key_cloudtrail[*].json)

  context = module.this.context
}

data "aws_caller_identity" "this" {
  count = local.enabled ? 1 : 0
}

data "aws_partition" "current" {
  count = local.enabled ? 1 : 0
}

data "aws_iam_policy_document" "kms_key_cloudtrail" {
  count = local.enabled ? 1 : 0

  statement {
    sid    = "Allow the account identity to manage the KMS key"
    effect = "Allow"

    actions = [
      "kms:*"
    ]

    resources = [
      "*"
    ]

    principals {
      type = "AWS"

      identifiers = [
        format("arn:${join("", data.aws_partition.current[*].partition)}:iam::%s:root", join("", data.aws_caller_identity.this[*].account_id))
      ]
    }
  }

  statement {
    sid    = "Allow CloudTrail to encrypt with the KMS key"
    effect = "Allow"

    actions = [
      "kms:Encrypt",
      "kms:GenerateDataKey*"
    ]

    resources = [
      "*"
    ]

    principals {
      type = "Service"

      identifiers = [
        "cloudtrail.amazonaws.com"
      ]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"

      values = [
        format("arn:${join("", data.aws_partition.current[*].partition)}:cloudtrail:*:%s:trail/*", join("", data.aws_caller_identity.this[*].account_id))
      ]
    }
  }

  dynamic "statement" {
    for_each = local.audit_access_enabled ? [1] : []
    content {
      sid    = "Allow Audit to decrypt with the KMS key"
      effect = "Allow"
      actions = [
        "kms:Decrypt*",
      ]
      resources = [
        "*"
      ]
      principals {
        type = "AWS"
        identifiers = [
          format("arn:${join("", data.aws_partition.current[*].partition)}:iam::%s:root", local.audit_account_id)
        ]
      }
    }
  }
}

data "aws_iam_policy_document" "abac_policy" {
  count = local.enabled && var.kms_key_enabled && local.kms_abac_enabled ? 1 : 0
  dynamic "statement" {
    for_each = var.kms_abac_statements
    content {
      sid     = lookup(statement.value, "sid", null)
      effect  = statement.value.effect
      actions = statement.value.actions
      resources = [
        module.kms_key_cloudtrail.key_arn
      ]

      condition {
        test     = "ForAnyValue:StringLike"
        variable = "kms:ResourceAliases"
        values = [
          local.kms_key_alias
        ]
      }

      dynamic "condition" {
        for_each = statement.value.conditions
        content {
          test     = condition.value.test
          variable = condition.value.variable
          values   = condition.value.values
        }
      }
    }
  }
}

# https://docs.aws.amazon.com/kms/latest/developerguide/abac.html
resource "aws_iam_policy" "abac_policy" {
  count       = local.enabled && var.kms_key_enabled && (local.kms_abac_enabled ? 1 : 0) > 0 ? 1 : 0
  name        = format("%s-abac-policy", module.this.id)
  description = "ABAC policy for the KMS key used by the CloudTrail trail"
  policy      = join("", data.aws_iam_policy_document.abac_policy[*].json)
}
