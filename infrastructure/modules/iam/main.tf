# IAM Policy to Enforce MFA
resource "aws_iam_policy" "enforce_mfa" {
  count       = var.enable_mfa_enforcement ? 1 : 0
  name        = "${var.environment}-enforce-mfa-policy"
  description = "Policy to enforce MFA for all IAM users"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyAllExceptListedIfNoMFA"
        Effect = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:GetUser",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice",
          "sts:GetSessionToken"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}

# IAM Group for Security Admins
resource "aws_iam_group" "security_admins" {
  name = "${var.environment}-security-admins"
}

# Attach Security Admin Policies
resource "aws_iam_group_policy_attachment" "security_admin_access" {
  group      = aws_iam_group.security_admins.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_group_policy_attachment" "mfa_enforcement" {
  count      = var.enable_mfa_enforcement ? 1 : 0
  group      = aws_iam_group.security_admins.name
  policy_arn = aws_iam_policy.enforce_mfa[0].arn
}

# IAM Role for Security Operations (RBAC)
resource "aws_iam_role" "security_operations" {
  name = "${var.environment}-security-operations-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      }
      Condition = {
        Bool = {
          "aws:MultiFactorAuthPresent" = "true"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "security_ops_policy" {
  role       = aws_iam_role.security_operations.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# IAM Role for Compliance Auditor (Read-Only RBAC)
resource "aws_iam_role" "compliance_auditor" {
  name = "${var.environment}-compliance-auditor-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      }
      Condition = {
        Bool = {
          "aws:MultiFactorAuthPresent" = "true"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "compliance_readonly" {
  role       = aws_iam_role.compliance_auditor.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

data "aws_caller_identity" "current" {}
