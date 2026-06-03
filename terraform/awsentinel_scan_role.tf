variable "awsentinel_external_id" {
  description = "External ID required when AWSentinel assumes the scan role."
  type        = string
}

variable "awsentinel_trusted_principal_arn" {
  description = "Principal ARN allowed to assume AWSentinelScanRole."
  type        = string
}

resource "aws_iam_role" "awsentinel_scan_role" {
  name = "AWSentinelScanRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = var.awsentinel_trusted_principal_arn
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "sts:ExternalId" = var.awsentinel_external_id
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "awsentinel_scan_policy" {
  name = "AWSentinelScanPolicy"
  role = aws_iam_role.awsentinel_scan_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Identity"
        Effect = "Allow"
        Action = [
          "sts:GetCallerIdentity"
        ]
        Resource = "*"
      },
      {
        Sid    = "IamInventory"
        Effect = "Allow"
        Action = [
          "iam:GenerateServiceLastAccessedDetails",
          "iam:GetAccessKeyLastUsed",
          "iam:GetGroup",
          "iam:GetGroupPolicy",
          "iam:GetInstanceProfile",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:GetServiceLastAccessedDetails",
          "iam:GetUser",
          "iam:GetUserPolicy",
          "iam:ListAccessKeys",
          "iam:ListAttachedGroupPolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListAttachedUserPolicies",
          "iam:ListEntitiesForPolicy",
          "iam:ListGroupPolicies",
          "iam:ListGroups",
          "iam:ListGroupsForUser",
          "iam:ListInstanceProfiles",
          "iam:ListInstanceProfilesForRole",
          "iam:ListPolicies",
          "iam:ListPolicyVersions",
          "iam:ListRolePolicies",
          "iam:ListRoleTags",
          "iam:ListRoles",
          "iam:ListUserPolicies",
          "iam:ListUsers"
        ]
        Resource = "*"
      },
      {
        Sid    = "OrganizationScpInventory"
        Effect = "Allow"
        Action = [
          "organizations:DescribePolicy",
          "organizations:ListParents",
          "organizations:ListPolicies",
          "organizations:ListRoots",
          "organizations:ListTargetsForPolicy"
        ]
        Resource = "*"
      },
      {
        Sid    = "CloudTrailRuntimeCorrelation"
        Effect = "Allow"
        Action = [
          "cloudtrail:LookupEvents"
        ]
        Resource = "*"
      }
    ]
  })
}
