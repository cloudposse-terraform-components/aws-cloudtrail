variable "account_map_enabled" {
  type        = bool
  description = <<-EOT
    When true, uses the account-map component to look up account IDs dynamically.
    When false, uses the static account_map variable instead. Set to false when
    using Atmos Auth profiles and static account mappings.
    EOT
  default     = true
}

variable "account_map" {
  type = object({
    full_account_map           = map(string)
    audit_account_account_name = optional(string, "")
    root_account_account_name  = optional(string, "")
  })
  description = <<-EOT
    Static account map used when account_map_enabled is false.
    Provides account name to account ID mapping without requiring the account-map component.
    EOT
  default = {
    full_account_map           = {}
    audit_account_account_name = ""
    root_account_account_name  = ""
  }
}

provider "aws" {
  region = var.region

  # Profile is deprecated in favor of terraform_role_arn. When profiles are not in use, terraform_profile_name is null.
  profile = module.iam_roles.terraform_profile_name

  dynamic "assume_role" {
    # module.iam_roles.terraform_role_arn may be null, in which case do not assume a role.
    for_each = compact([module.iam_roles.terraform_role_arn])
    content {
      role_arn = assume_role.value
    }
  }
}

module "iam_roles" {
  source  = "../account-map/modules/iam-roles"
  context = module.this.context
}
