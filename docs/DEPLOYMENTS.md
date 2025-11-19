# Deployment Guide - AWS Security & Compliance Framework

Complete step-by-step guide to deploy the AWS Security & Compliance Framework in your AWS account.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Pre-Deployment Checklist](#pre-deployment-checklist)
- [Deployment Steps](#deployment-steps)
- [Post-Deployment Validation](#post-deployment-validation)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Tools

| Tool | Version | Purpose |
|------|---------|---------|
| Terraform | >= 1.0 | Infrastructure provisioning |
| AWS CLI | >= 2.0 | AWS operations |
| Git | Latest | Version control |
| Python | 3.8+ | Scripts (optional) |

### AWS Requirements

- **AWS Account** with admin permissions
- **IAM User** or **Role** with the following permissions:
  - IAM (Full Access)
  - GuardDuty (Full Access)
  - Security Hub (Full Access)
  - Config (Full Access)
  - CloudTrail (Full Access)
  - KMS (Full Access)
  - S3 (Full Access)
  - CloudWatch (Full Access)
  - SNS (Full Access)

### Estimated Costs

**Monthly Cost**: ~$15-16/month for complete security framework

| Service | Monthly Cost |
|---------|--------------|
| GuardDuty | ~$5 |
| Security Hub | ~$2 |
| Config Rules | ~$4 |
| CloudTrail | ~$2 |
| KMS Keys | ~$1-2 |
| S3 Storage | ~$1 |
| CloudWatch | ~$0.50 |
| **Total** | **~$15-16** |

---

## Pre-Deployment Checklist

### ✅ Step 1: Configure AWS CLI

```bash
# Configure AWS credentials
aws configure

# Verify credentials
aws sts get-caller-identity

# Expected output:
# {
#     "UserId": "AIDAXXXXXXXXX",
#     "Account": "123456789012",
#     "Arn": "arn:aws:iam::123456789012:user/your-username"
# }
```

### ✅ Step 2: Clone Repository

```bash
git clone https://github.com/AshokNaidu-Code/aws-security-compliance-framework.git
cd aws-security-compliance-framework
```

### ✅ Step 3: Review Architecture

Review the [ARCHITECTURE.md](ARCHITECTURE.md) to understand what will be deployed.

**Key Components:**
- GuardDuty for threat detection
- Security Hub for compliance monitoring
- AWS Config with 20+ compliance rules
- CloudTrail for audit logging
- KMS encryption keys
- CloudWatch alarms

---

## Deployment Steps

### Step 1: Configure Variables

```bash
cd terraform

# Copy example configuration
cp terraform.tfvars.example terraform.tfvars

# Edit configuration
vim terraform.tfvars
```

**Minimum Required Configuration:**

```hcl
project_name = "my-security-framework"
environment  = "production"
aws_region   = "us-east-1"

# REQUIRED: Your email for security alerts
alert_email  = "security-team@company.com"
```

**Recommended Production Configuration:**

```hcl
# General Settings
project_name = "acme-security"
environment  = "production"
aws_region   = "us-east-1"

# Alerting
alert_email  = "security@acme.com"

# IAM Password Policy (CIS Compliant)
password_minimum_length   = 14
password_max_age          = 90
password_reuse_prevention = 24

# Enable Core Services
enable_guardduty    = true
enable_security_hub = true
enable_config_rules = true
enable_cloudtrail   = true

# Compliance Standards
enable_cis_level_1 = true
enable_cis_level_2 = false  # Enable for stricter controls
enable_pci_dss     = false  # Enable if processing payments

# Encryption
enable_kms_key_rotation = true
enable_ebs_encryption   = true

# Logging Retention
cloudtrail_log_retention = 90   # Minimum 90 days for CIS
cloudwatch_log_retention = 365  # 1 year
```

### Step 2: Initialize Terraform

```bash
# Initialize Terraform
terraform init

# Expected output:
# Initializing the backend...
# Initializing provider plugins...
# Terraform has been successfully initialized!
```

### Step 3: Validate Configuration

```bash
# Format code
terraform fmt -recursive

# Validate configuration
terraform validate

# Expected output:
# Success! The configuration is valid.
```

### Step 4: Review Deployment Plan

```bash
# Generate execution plan
terraform plan

# Save plan for review
terraform plan -out=tfplan

# Review plan carefully
terraform show tfplan
```

**Expected Resources** (~40-50 resources):
- 1 GuardDuty detector
- 1 Security Hub account
- 4-5 Security Hub standards subscriptions
- 20+ AWS Config rules
- 1 CloudTrail trail
- 3-4 KMS keys
- 3-4 S3 buckets
- 2 SNS topics
- 8+ CloudWatch alarms
- 5+ IAM roles

### Step 5: Deploy Security Framework

```bash
# Apply configuration
terraform apply

# Type 'yes' when prompted

# Deployment takes approximately 5-10 minutes
```

**Deployment Timeline:**

| Phase | Duration | Description |
|-------|----------|-------------|
| IAM Configuration | 1 min | Password policy, roles |
| KMS Keys | 1 min | Encryption keys |
| S3 Buckets | 2 min | Log storage buckets |
| CloudTrail | 2 min | Audit logging setup |
| GuardDuty | 1 min | Threat detection |
| Security Hub | 2 min | Compliance monitoring |
| Config | 3 min | Config recorder + rules |
| CloudWatch | 1 min | Alarms and log groups |
| **Total** | **10-15 min** | Complete deployment |

### Step 6: Save Outputs

```bash
# Display all outputs
terraform output

# Save important values
terraform output > deployment-outputs.txt

# Get specific values
terraform output guardduty_detector_id
terraform output security_hub_arn
```

---

## Post-Deployment Validation

### Step 1: Confirm SNS Subscriptions

**Check your email** (configured in `alert_email`):

1. Look for AWS SNS confirmation emails (2 emails)
   - Security Alerts Topic
   - Compliance Alerts Topic
2. Click "Confirm subscription" links in both emails

```bash
# Verify subscriptions
aws sns list-subscriptions \
  --query 'Subscriptions[?Protocol==`email`].[TopicArn,Endpoint,SubscriptionArn]' \
  --output table
```

### Step 2: Verify GuardDuty

```bash
# Check GuardDuty status
aws guardduty list-detectors

# Get detector details
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty get-detector --detector-id $DETECTOR_ID

# Expected: Status = "ENABLED"
```

### Step 3: Verify Security Hub

```bash
# Check Security Hub
aws securityhub describe-hub

# List enabled standards
aws securityhub get-enabled-standards

# Expected standards:
# - CIS AWS Foundations Benchmark
# - AWS Foundational Security Best Practices
```

### Step 4: Verify AWS Config

```bash
# Check Config recorder
aws configservice describe-configuration-recorders

# Check delivery channel
aws configservice describe-delivery-channels

# List Config rules
aws configservice describe-config-rules \
  --query 'ConfigRules[*].ConfigRuleName' \
  --output table

# Expected: 20+ rules listed
```

### Step 5: Verify CloudTrail

```bash
# List trails
aws cloudtrail describe-trails

# Check trail status
TRAIL_NAME=$(aws cloudtrail describe-trails --query 'trailList[0].Name' --output text)
aws cloudtrail get-trail-status --name $TRAIL_NAME

# Expected: IsLogging = true
```

### Step 6: Verify KMS Keys

```bash
# List KMS keys
aws kms list-keys

# Check key rotation
for KEY_ID in $(aws kms list-keys --query 'Keys[*].KeyId' --output text); do
  echo "Key: $KEY_ID"
  aws kms get-key-rotation-status --key-id $KEY_ID
done

# Expected: KeyRotationEnabled = true
```

### Step 7: Test CloudWatch Alarms

```bash
# List alarms
aws cloudwatch describe-alarms \
  --query 'MetricAlarms[*].[AlarmName,StateValue]' \
  --output table

# Expected: 8+ alarms in OK state
```

---

## Configuration

### Custom IAM Password Policy

Edit in `terraform.tfvars`:

```hcl
password_minimum_length   = 16  # Stronger than default
password_max_age          = 60  # More frequent rotation
password_reuse_prevention = 30  # Remember more passwords
```

### Enable PCI-DSS Compliance

```hcl
enable_pci_dss = true
```

**Note**: Adds ~$2/month in Security Hub costs.

### Disable Non-Essential Features (Cost Savings)

For development environments:

```hcl
enable_cis_level_2 = false
enable_inspector   = false
guardduty_finding_frequency = "SIX_HOURS"
cloudtrail_log_retention = 30
```

**Savings**: ~$5-7/month

### Multi-Region Deployment

CloudTrail is automatically multi-region. To extend other services:

1. Deploy in additional regions
2. Use CloudFormation StackSets (recommended)
3. Configure GuardDuty delegated administrator

---

## Troubleshooting

### Issue 1: Terraform Init Fails

**Error**: "Failed to install provider"

**Solution**:
```bash
# Clear cache
rm -rf .terraform .terraform.lock.hcl

# Re-initialize
terraform init
```

### Issue 2: Insufficient IAM Permissions

**Error**: "UnauthorizedOperation"

**Solution**: Ensure IAM user/role has the required permissions listed in [Prerequisites](#aws-requirements).

### Issue 3: S3 Bucket Name Conflict

**Error**: "BucketAlreadyExists"

**Solution**: Bucket names must be globally unique. Change `project_name`:

```hcl
project_name = "security-framework-unique-id-123"
```

### Issue 4: GuardDuty Already Enabled

**Error**: "GuardDuty is already enabled"

**Solution**: Import existing GuardDuty detector:

```bash
# Get detector ID
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

# Import into Terraform
terraform import aws_guardduty_detector.main[0] $DETECTOR_ID
```

### Issue 5: Security Hub Not Enabled

**Error**: "Security Hub is not enabled"

**Solution**: Enable Security Hub first:

```bash
aws securityhub enable-security-hub --enable-default-standards
```

Then run `terraform apply` again.

### Issue 6: Config Recorder Already Exists

**Error**: "Configuration recorder already exists"

**Solution**: Import existing recorder:

```bash
# Get recorder name
RECORDER=$(aws configservice describe-configuration-recorders --query 'ConfigurationRecorders[0].name' --output text)

# Import
terraform import aws_config_configuration_recorder.main[0] $RECORDER
```

### Issue 7: Email Alerts Not Received

**Causes**:
- Email not confirmed
- Spam folder
- Invalid email address

**Solution**:
```bash
# Check subscription status
aws sns list-subscriptions-by-topic --topic-arn <TOPIC_ARN>

# Resend confirmation
aws sns subscribe \
  --topic-arn <TOPIC_ARN> \
  --protocol email \
  --notification-endpoint your-email@company.com
```

---

## Maintenance

### Daily Operations

```bash
# Check Security Hub findings
aws securityhub get-findings \
  --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}]}' \
  --max-items 10

# Check GuardDuty findings
aws guardduty list-findings --detector-id $DETECTOR_ID \
  --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}'
```

### Weekly Operations

```bash
# Review Config compliance
aws configservice describe-compliance-by-config-rule

# Generate compliance report
cd scripts
python3 compliance-report.py
```

### Monthly Operations

```bash
# Review costs
aws ce get-cost-and-usage \
  --time-period Start=$(date -d '1 month ago' +%Y-%m-01),End=$(date +%Y-%m-%d) \
  --granularity MONTHLY \
  --metrics UnblendedCost \
  --filter file://cost-filter.json

# Update Terraform
terraform plan
terraform apply  # Only if changes needed
```

---

## Cleanup (Destroying Infrastructure)

⚠️ **Warning**: This will remove all security controls!

```bash
# Review what will be destroyed
terraform plan -destroy

# Destroy infrastructure
terraform destroy

# Type 'yes' when prompted
```

**Manual Cleanup Required:**
- Disable GuardDuty (if not handled by Terraform)
- Disable Security Hub
- Delete S3 buckets (if not empty)

---

## Next Steps

After successful deployment:

1. ✅ **Review Security Hub Findings**
   - Visit AWS Console > Security Hub
   - Address critical/high findings

2. ✅ **Wait for GuardDuty Baseline**
   - GuardDuty needs 24-48 hours to establish baseline
   - Initial findings are normal

3. ✅ **Review Config Compliance**
   - Check compliance status of all rules
   - Remediate non-compliant resources

4. ✅ **Enable MFA**
   - Enforce MFA for all IAM users
   - Enable MFA for root account

5. ✅ **Document Procedures**
   - Create incident response runbook
   - Document escalation procedures

6. ✅ **Train Team**
   - Security Hub usage
   - Responding to GuardDuty findings
   - Config compliance remediation

---

## Support

- **Issues**: [GitHub Issues](https://github.com/AshokNaidu-Code/aws-security-compliance-framework/issues)
- **Documentation**: [Project Wiki](https://github.com/AshokNaidu-Code/aws-security-compliance-framework/wiki)

---

**🔒 Deployment Complete! Your AWS account is now secured with enterprise-grade controls.**