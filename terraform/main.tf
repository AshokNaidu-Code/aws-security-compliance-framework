# ============================================================================
# AWS Security & Compliance Framework - Main Configuration
# ============================================================================
# Description: Production-ready security framework implementing CIS benchmarks,
#              threat detection, compliance monitoring, and encryption
# Author: Ashok Kumar Nallam
# ============================================================================

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  # Backend configuration for remote state (recommended for production)
  # Uncomment and configure as needed
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "security-framework/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "terraform-state-lock"
  #   encrypt        = true
  #   kms_key_id     = "alias/terraform-state"
  # }
}

# ============================================================================
# Provider Configuration
# ============================================================================

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Framework   = "Security-Compliance"
      Owner       = "Security-Team"
      CostCenter  = "Security"
      Compliance  = "CIS-Benchmark"
    }
  }
}

# ============================================================================
# Data Sources
# ============================================================================

# Get current AWS account ID
data "aws_caller_identity" "current" {}

# Get current AWS region
data "aws_region" "current" {}

# Get available availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

# Get AWS partition (aws, aws-cn, aws-us-gov)
data "aws_partition" "current" {}

# ============================================================================
# Local Values
# ============================================================================

locals {
  # Account information
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  partition  = data.aws_partition.current.partition

  # Resource naming
  name_prefix = "${var.project_name}-${var.environment}"

  # Common tags
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Framework   = "Security-Compliance"
  }

  # CloudTrail bucket name (must be globally unique)
  cloudtrail_bucket_name = "${local.name_prefix}-cloudtrail-${local.account_id}"
  
  # Config bucket name
  config_bucket_name = "${local.name_prefix}-config-${local.account_id}"
  
  # Security logs bucket name
  security_logs_bucket_name = "${local.name_prefix}-security-logs-${local.account_id}"

  # SNS topic names
  security_alerts_topic = "${local.name_prefix}-security-alerts"
  compliance_alerts_topic = "${local.name_prefix}-compliance-alerts"

  # KMS key aliases
  cloudtrail_kms_alias = "alias/${local.name_prefix}-cloudtrail"
  s3_kms_alias        = "alias/${local.name_prefix}-s3"
  secrets_kms_alias   = "alias/${local.name_prefix}-secrets"

  # Compliance standards to enable
  compliance_standards = {
    cis_1_2_0 = var.enable_cis_level_1 || var.enable_cis_level_2
    pci_dss   = var.enable_pci_dss
  }

  # Tags for security resources
  security_tags = merge(
    local.common_tags,
    {
      SecurityLayer = "Core"
      Compliance    = "Required"
      DataClass     = "Confidential"
    }
  )
}

# ============================================================================
# Random ID for Unique Resource Names
# ============================================================================

resource "random_id" "suffix" {
  byte_length = 4
}

# ============================================================================
# Outputs
# ============================================================================

output "account_id" {
  description = "AWS Account ID"
  value       = local.account_id
}

output "region" {
  description = "AWS Region"
  value       = local.region
}

output "deployment_id" {
  description = "Unique deployment identifier"
  value       = random_id.suffix.hex
}