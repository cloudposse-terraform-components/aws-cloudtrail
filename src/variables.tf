variable "account_verification_enabled" {
  type        = bool
  description = <<-DOC
  Enable account verification. When true (default), the component verifies that Terraform is executing
  in the correct AWS account by comparing the current account ID against the expected account from the
  account_map based on the component's tenant-stage context.
  DOC
  default     = true
}

variable "account_map_enabled" {
  type        = bool
  description = <<-DOC
  Enable the account map component. When true (default), the component fetches account mappings from the
  `account-map` component via remote state. When false, the component uses the static `account_map` variable instead.
  DOC
  default     = true
}

variable "account_map" {
  type = object({
    full_account_map              = map(string)
    audit_account_account_name    = optional(string, "")
    root_account_account_name     = optional(string, "")
    identity_account_account_name = optional(string, "")
    aws_partition                 = optional(string, "aws")
    iam_role_arn_templates        = optional(map(string), {})
  })
  description = <<-DOC
  Static account map configuration. Only used when `account_map_enabled` is `false`.
  Map keys use `tenant-stage` format (e.g., `core-security`, `core-audit`, `plat-prod`).
  DOC
  default = {
    full_account_map              = {}
    audit_account_account_name    = ""
    root_account_account_name     = ""
    identity_account_account_name = ""
    aws_partition                 = "aws"
    iam_role_arn_templates        = {}
  }
}

variable "account_map_tenant" {
  type        = string
  default     = "core"
  description = "The tenant where the `account_map` component required by remote-state is deployed"
}

variable "global_environment" {
  type        = string
  default     = "gbl"
  description = "Global environment name"
}

variable "privileged" {
  type        = bool
  default     = false
  description = "true if the default provider already has access to the backend"
}

variable "region" {
  type        = string
  description = "AWS Region"
}

variable "root_account_stage" {
  type        = string
  default     = "root"
  description = <<-DOC
  The stage name for the Organization root (management) account. This is used to lookup account IDs from account names
  using the `account-map` component.
  DOC
}

variable "cloudwatch_logs_retention_in_days" {
  type        = number
  default     = 365
  description = "Number of days to retain logs for. CIS recommends 365 days.  Possible values are: 0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, and 3653. Set to 0 to keep logs indefinitely."
}

variable "cloudwatch_log_group_class" {
  type        = string
  default     = "STANDARD"
  description = "Specifies the log class of the log group. Possible values are STANDARD or INFREQUENT_ACCESS."
  validation {
    condition     = contains(["STANDARD", "INFREQUENT_ACCESS"], var.cloudwatch_log_group_class)
    error_message = "The cloudwatch_log_group_class must be STANDARD or INFREQUENT_ACCESS."
  }
}

variable "enable_logging" {
  type        = bool
  default     = true
  description = "Enable logging for the trail"
}

variable "enable_log_file_validation" {
  type        = bool
  default     = true
  description = "Specifies whether log file integrity validation is enabled. Creates signed digest for validated contents of logs"
}

variable "include_global_service_events" {
  type        = bool
  default     = true
  description = "Specifies whether the trail is publishing events from global services such as IAM to the log files"
}

variable "is_multi_region_trail" {
  type        = bool
  default     = true
  description = "Specifies whether the trail is created in the current region or in all regions"
}

variable "cloudtrail_cloudwatch_logs_role_max_session_duration" {
  type        = number
  default     = 43200
  description = "The maximum session duration (in seconds) for the CloudTrail CloudWatch Logs role. Can have a value from 1 hour to 12 hours"
}

variable "cloudtrail_bucket_component_name" {
  type        = string
  description = "The name of the CloudTrail bucket component"
  default     = "cloudtrail-bucket"
}

variable "cloudtrail_bucket_environment_name" {
  type        = string
  description = "The name of the environment where the CloudTrail bucket is provisioned"
}

variable "cloudtrail_bucket_stage_name" {
  type        = string
  description = "The stage name where the CloudTrail bucket is provisioned"
}

variable "is_organization_trail" {
  type        = bool
  default     = false
  description = <<-EOT
  Specifies whether the trail is created for all accounts in an organization in AWS Organizations, or only for the current AWS account.

  The default is false, and cannot be true unless the call is made on behalf of an AWS account that is the management account
  for an organization in AWS Organizations.
  EOT
}

variable "audit_access_enabled" {
  type        = bool
  default     = false
  description = "If `true`, allows the Audit account access to read Cloudtrail logs directly from S3. This is a requirement for running Athena queries in the Audit account."
}

variable "account_map_component_name" {
  type        = string
  description = "The name of a account-map component"
  default     = "account-map"
}

variable "kms_key_alias" {
  type        = string
  description = "The alias for the KMS key. If not set, the alias will be set to `alias/<module.this.id>`"
  default     = null
}

variable "kms_key_enabled" {
  type        = bool
  description = "Toggle to enable/disable the encrypted log group feature that has not been extensively tested."
  default     = false
}

variable "kms_abac_statements" {
  type = list(object({
    sid        = optional(string)
    effect     = string
    actions    = list(string)
    principals = map(list(string))
    conditions = list(object({
      test     = string
      variable = string
      values   = list(string)
    }))
  }))
  description = <<-EOT
    A list of ABAC statements which are placed in an IAM policy.
    Each statement must have the following attributes:
    - `sid` (optional): A unique identifier for the statement.
    - `effect`: The effect of the statement. Valid values are `Allow` and `Deny`.
    - `actions`: A list of actions to allow or deny.
    - `conditions`: A list of conditions to evaluate when the statement is applied.
  EOT
  default     = []
}
