# AWS Security & Compliance Framework

![Security](https://img.shields.io/badge/Security-Hardened-success)
![Compliance](https://img.shields.io/badge/Compliance-CIS%20Benchmark-blue)
![Terraform](https://img.shields.io/badge/Terraform-v1.0+-blueviolet)
![AWS](https://img.shields.io/badge/AWS-Security%20Services-orange)
![License](https://img.shields.io/badge/License-MIT-blue)

A comprehensive, production-ready AWS security and compliance framework implementing industry best practices, automated threat detection, continuous compliance monitoring, and encryption-at-rest for enterprise environments.

## 🎯 Project Highlights

- **🔐 Multi-Layer Security**: IAM hardening, encryption, network security, threat detection
- **📊 Continuous Compliance**: Automated CIS AWS Foundations Benchmark checks
- **🚨 Real-Time Threat Detection**: GuardDuty with automated alerting
- **📝 Complete Audit Trail**: CloudTrail logging with tamper-proof S3 storage
- **🔑 Centralized Key Management**: KMS with automatic key rotation
- **💰 Cost Effective**: ~$15/month for comprehensive security coverage
- **🤖 Fully Automated**: Infrastructure as Code with Terraform

## 📊 Security Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         AWS Account Security                        │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                     Identity & Access Management                     │
├──────────────────────────────────────────────────────────────────────┤
│  • IAM Password Policy (14+ chars, complexity, rotation)             │
│  • MFA Enforcement for Root & IAM Users                              │
│  • Role-Based Access Control (RBAC)                                  │
│  • Least Privilege Principle                                         │
│  • Cross-Account Access Roles                                        │
└──────────────────────────────────────────────────────────────────────┘
                                   ↓
┌──────────────────────────────────────────────────────────────────────┐
│                      Threat Detection Layer                          │
├──────────────────────────────────────────────────────────────────────┤
│  ┌────────────────┐   ┌────────────────┐   ┌────────────────┐        │
│  │   GuardDuty    │   │  Security Hub  │   │   Inspector    │        │
│  │                │   │                │   │ • Vuln Scan    │        │
│  │ • Anomaly Det  │   │   Findings     │   │ • Network      │        │
│  │ • Malware Det  │   │ • Compliance   │   │   Assessment   │        │
│  └────────────────┘   └────────────────┘   └────────────────┘        │
└──────────────────────────────────────────────────────────────────────┘
                                    ↓
┌──────────────────────────────────────────────────────────────────────┐
│                      Compliance Monitoring                           │
├──────────────────────────────────────────────────────────────────────┤
│  AWS Config + Config Rules                                           │
│                                                                      │
│  • CIS AWS Foundations Benchmark (L1 & L2)                           │
│  • PCI-DSS Compliance Rules                                          │
│  • Automated Remediation                                             │
│  • Continuous Configuration Assessment                               │
│  • Non-Compliance Alerting                                           │
└──────────────────────────────────────────────────────────────────────┘
                                    ↓
┌──────────────────────────────────────────────────────────────────────┐
│                    Encryption & Key Management                       │
├──────────────────────────────────────────────────────────────────────┤
│  AWS KMS (Key Management Service)                                    │
│                                                                      │
│  • Customer Managed Keys (CMK)                                       │
│  • Automatic Key Rotation (365 days)                                 │
│  • Encrypted S3 Buckets (SSE-KMS)                                    │
│  • Encrypted EBS Volumes                                             │
│  • Secrets Manager Integration                                       │
└──────────────────────────────────────────────────────────────────────┘
                                    ↓
┌──────────────────────────────────────────────────────────────────────┐
│                    Logging & Auditing Layer                          │
├──────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐           ┌──────────────────┐                 │
│  │   CloudTrail     │---------->│   S3 Bucket      │                 │
│  │                  │           │   (Encrypted)    │                 │
│  │ • API Logging    │           │                  │                 │
│  │ • Multi-Region   │           │ • Versioning     │                 │
│  │ • Validation     │           │ • MFA Delete     │                 │
│  └──────────────────┘           │ • Lifecycle      │                 │
│           │                     └──────────────────┘                 │
│           ↓                                                          │
│  ┌──────────────────┐           ┌──────────────────┐                 │
│  │  CloudWatch Logs │---------->│   Log Insights   │                 │
│  │                  │           │   & Dashboards   │                 │
│  │ • Aggregation    │           │                  │                 │
│  │ • Retention      │           │ • Query & Alert  │                 │
│  └──────────────────┘           └──────────────────┘                 │
└──────────────────────────────────────────────────────────────────────┘
                                    ↓
┌──────────────────────────────────────────────────────────────────────┐
│                      Alerting & Response                             │
├──────────────────────────────────────────────────────────────────────┤
│  SNS Topics → Email / Slack / PagerDuty                              │
│                                                                      │
│  • Critical Security Findings                                        │
│  • Compliance Violations                                             │
│  • Unauthorized API Calls                                            │
│  • Root Account Usage                                                │
│  • MFA Disabled Alerts                                               │
└──────────────────────────────────────────────────────────────────────┘
```

## 🔒 Security Controls Implemented

### 1. Identity & Access Management (IAM)

| Control | Implementation | Status |
|---------|----------------|--------|
| **Password Policy** | 14+ chars, uppercase, lowercase, numbers, symbols | ✅ |
| **Password Expiration** | 90-day rotation | ✅ |
| **Password Reuse** | Prevent last 24 passwords | ✅ |
| **MFA Enforcement** | Required for all users | ✅ |
| **Root Account Protection** | MFA + no access keys | ✅ |
| **Least Privilege** | Role-based access control | ✅ |
| **Access Key Rotation** | Automated detection (90 days) | ✅ |
| **Unused Credentials** | Automated detection & removal | ✅ |

### 2. Threat Detection & Response

| Service | Purpose | Coverage |
|---------|---------|----------|
| **GuardDuty** | Intelligent threat detection | Account, Network, S3 |
| **Security Hub** | Centralized security findings | Multi-service aggregation |
| **Inspector** | Vulnerability assessment | EC2, ECR, Lambda |
| **CloudWatch Alarms** | Real-time alerting | 15+ security metrics |

### 3. Compliance Monitoring

**CIS AWS Foundations Benchmark v1.4.0**

- ✅ **Level 1**: 50+ automated checks
- ✅ **Level 2**: Advanced security controls
- ✅ **Automated Remediation**: Auto-fix for 30+ rules
- ✅ **Compliance Dashboard**: Real-time compliance score

**Additional Frameworks:**
- PCI-DSS v3.2.1
- HIPAA Security Rule
- GDPR (EU Data Protection)
- SOC 2 Type II

### 4. Encryption Standards

| Resource | Encryption Type | Key Management |
|----------|----------------|----------------|
| **S3 Buckets** | SSE-KMS | Customer Managed Keys |
| **EBS Volumes** | AES-256 | KMS with auto-rotation |
| **RDS Databases** | TDE | KMS encrypted |
| **Secrets** | AES-256 | Secrets Manager |
| **CloudTrail Logs** | SSE-KMS | Dedicated CMK |
| **Data in Transit** | TLS 1.2+ | AWS Certificate Manager |

### 5. Logging & Auditing

| Log Type | Retention | Storage | Monitoring |
|----------|-----------|---------|------------|
| **CloudTrail** | 90 days → Glacier | S3 (encrypted) | CloudWatch Logs |
| **VPC Flow Logs** | 30 days | S3 (encrypted) | CloudWatch Insights |
| **GuardDuty Findings** | 90 days | S3 (encrypted) | Security Hub |
| **Config History** | 7 years | S3 (encrypted) | Config Dashboard |
| **CloudWatch Logs** | 365 days | CloudWatch | Log Insights |

## 📁 Project Structure

```
aws-security-compliance-framework/
│
├── terraform/                          # Infrastructure as Code
│   ├── main.tf                         # Provider configuration
│   ├── iam.tf                          # IAM policies, roles, password policy
│   ├── guardduty.tf                    # Threat detection setup
│   ├── security-hub.tf                 # Security Hub configuration
│   ├── config.tf                       # AWS Config & compliance rules
│   ├── kms.tf                          # Encryption key management
│   ├── cloudtrail.tf                   # Audit logging
│   ├── cloudwatch.tf                   # Log aggregation & alarms
│   ├── inspector.tf                    # Vulnerability scanning
│   ├── sns.tf                          # Alerting topics
│   ├── s3.tf                           # Secure log storage buckets
│   ├── variables.tf                    # Input variables
│   ├── outputs.tf                      # Output values
│   └── terraform.tfvars.example        # Configuration template
│
├── compliance-rules/                   # Compliance configurations
│   ├── cis-benchmarks/                 # CIS AWS Foundations
│   │   ├── level-1-rules.json          # CIS Level 1 rules
│   │   └── level-2-rules.json          # CIS Level 2 rules
│   ├── pci-dss/                        # PCI-DSS compliance
│   │   └── pci-rules.json              # PCI compliance rules
│   └── custom-rules/                   # Custom Config rules
│       └── custom-rules.json           # Organization-specific rules
│
├── policies/                           # Policy documents
│   ├── iam-policies/                   # IAM policy templates
│   │   ├── admin-policy.json           # Admin access policy
│   │   ├── developer-policy.json       # Developer access policy
│   │   ├── readonly-policy.json        # Read-only access policy
│   │   └── security-audit-policy.json  # Security auditor policy
│   ├── bucket-policies/                # S3 bucket policies
│   │   ├── cloudtrail-bucket.json      # CloudTrail logs bucket
│   │   └── config-bucket.json          # Config logs bucket
│   └── kms-policies/                   # KMS key policies
│       ├── cloudtrail-key.json         # CloudTrail encryption key
│       └── s3-key.json                 # S3 encryption key
│
├── scripts/                            # Automation scripts
│   ├── enable-mfa.sh                   # MFA enforcement script
│   ├── security-audit.py               # Security audit automation
│   ├── compliance-report.py            # Generate compliance reports
│   ├── rotate-access-keys.sh           # Access key rotation
│   └── unused-resources.py             # Find unused IAM resources
│
├── .github/workflows/                  # CI/CD workflows
│   ├── security-scan.yml               # Automated security scanning
│   ├── compliance-check.yml            # Compliance validation
│   └── deploy.yml                      # Deploy security controls
│
├── docs/                               # Documentation
│   ├── ARCHITECTURE.md                 # Security architecture details
│   ├── DEPLOYMENT.md                   # Deployment guide
│   ├── COMPLIANCE.md                   # Compliance frameworks guide
│   ├── RUNBOOK.md                      # Operations runbook
│   └── INCIDENT-RESPONSE.md            # Incident response procedures
│
├── dashboards/                         # Monitoring dashboards
│   ├── security-dashboard.json         # Security metrics dashboard
│   └── compliance-dashboard.json       # Compliance status dashboard
│
├── README.md                           # This file
├── LICENSE                             # MIT License
└── .gitignore                          # Git ignore rules
```

## 🚀 Quick Start

### Prerequisites

- AWS Account with admin permissions
- Terraform >= 1.0
- AWS CLI configured
- Python 3.8+ (for scripts)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/AshokNaidu-Code/aws-security-compliance-framework.git
cd aws-security-compliance-framework

# 2. Configure AWS credentials
aws configure

# 3. Create configuration file
cd terraform
cp terraform.tfvars.example terraform.tfvars

# 4. Edit configuration
vim terraform.tfvars

# 5. Initialize Terraform
terraform init

# 6. Review planned changes
terraform plan

# 7. Deploy security controls
terraform apply
```

**Deployment time**: 5-10 minutes

## ⚙️ Configuration

### Minimum Required Configuration

```hcl
# terraform.tfvars

project_name    = "security-framework"
environment     = "production"
aws_region      = "us-east-1"
alert_email     = "security-team@company.com"
```

### Recommended Production Configuration

```hcl
# terraform.tfvars

# General Settings
project_name    = "acme-security"
environment     = "production"
aws_region      = "us-east-1"

# Alerting
alert_email     = "security-team@acme.com"
slack_webhook   = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# IAM Settings
password_max_age           = 90
password_minimum_length    = 14
password_reuse_prevention  = 24
require_uppercase          = true
require_lowercase          = true
require_numbers            = true
require_symbols            = true

# Compliance
enable_cis_level_1         = true
enable_cis_level_2         = true
enable_pci_dss             = false
enable_hipaa               = false

# Logging
cloudtrail_log_retention   = 90
cloudwatch_log_retention   = 365
s3_log_lifecycle_glacier   = 90

# Encryption
enable_kms_key_rotation    = true
kms_deletion_window        = 30

# Threat Detection
enable_guardduty           = true
enable_security_hub        = true
enable_inspector           = true

# Cost Controls
enable_config_rules        = true  # ~$2/month per rule
guardduty_finding_frequency = "FIFTEEN_MINUTES"
```

## 💰 Cost Breakdown

### Monthly Costs (us-east-1)

| Service | Cost | Description |
|---------|------|-------------|
| **GuardDuty** | ~$5 | Threat detection (per GB analyzed) |
| **Security Hub** | ~$2 | Centralized findings ($0.0010 per check) |
| **Config Rules** | ~$4 | ~20 rules × $0.001 per evaluation |
| **CloudTrail** | ~$2 | Management events (first trail free) |
| **KMS** | ~$1 | Customer managed keys ($1/month each) |
| **S3 Storage** | ~$1 | Log storage (~10GB/month) |
| **CloudWatch Logs** | ~$0.50 | Log ingestion & storage |
| **Inspector** | ~$0.50 | Network reachability assessments |
| **SNS** | ~$0.10 | Email notifications |
| **TOTAL** | **~$16/month** | Complete security coverage |

### Cost Optimization Tips

1. **Config Rules**: Start with CIS Level 1 only (~10 rules)
2. **GuardDuty**: Use CloudWatch Events to filter findings
3. **S3 Logs**: Enable lifecycle policies (30 days → Glacier)
4. **CloudWatch Logs**: Set retention to 30 days for non-compliance logs
5. **Security Hub**: Disable unused standards (start with CIS only)

**Optimized cost**: ~$10/month for small environments

## 📊 Security Metrics & KPIs

### Continuous Monitoring

| Metric | Target | Alerting |
|--------|--------|----------|
| **Compliance Score** | >95% | Alert if <90% |
| **Critical Findings** | 0 | Real-time alert |
| **High Findings** | <5 | Daily summary |
| **Failed Config Rules** | <3 | Alert if >5 |
| **Root Account Usage** | 0 | Immediate alert |
| **MFA Disabled** | 0 users | Alert within 1 hour |
| **Old Access Keys** | <5% users | Weekly report |
| **Public S3 Buckets** | 0 | Real-time alert |

### Security Dashboard

Automated CloudWatch Dashboard showing:
- ✅ Compliance score over time
- ✅ GuardDuty findings by severity
- ✅ IAM user security status
- ✅ Encryption coverage percentage
- ✅ CloudTrail event volume
- ✅ Security Hub findings trends

## 🔧 Operations

### Daily Operations

```bash
# Check compliance status
cd scripts
python3 compliance-report.py

# Generate security audit
python3 security-audit.py

# View GuardDuty findings
aws guardduty list-findings \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}'
```

### Weekly Operations

```bash
# Review access key age
./scripts/rotate-access-keys.sh --check

# Find unused IAM resources
python3 scripts/unused-resources.py

# Review CloudTrail logs
aws cloudtrail lookup-events \
  --start-time $(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%S) \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin
```

### Monthly Operations

```bash
# Generate compliance report
python3 scripts/compliance-report.py --format pdf --month $(date +%Y-%m)

# Review Security Hub findings
aws securityhub get-findings \
  --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}]}' \
  --query 'Findings[*].[Title,Id,ProductArn]' \
  --output table

# Rotate encryption keys (if not auto-rotating)
# KMS keys auto-rotate annually by default
```

## 🚨 Incident Response

### Critical Security Event: Root Account Usage

```bash
# 1. Immediate Actions
# - Verify if legitimate
# - If unauthorized, revoke all root access keys

# 2. Investigation
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=root

# 3. Remediation
# - Enable MFA on root account
# - Change root password
# - Review all account changes
# - Enable AWS Organizations SCP to restrict root

# 4. Documentation
# - Create incident report
# - Update runbook
# - Conduct post-mortem
```

### High Severity GuardDuty Finding

```bash
# 1. Get finding details
aws guardduty get-findings \
  --detector-id <DETECTOR_ID> \
  --finding-ids <FINDING_ID>

# 2. Investigate resource
# Based on finding type:
# - Check CloudTrail for related API calls
# - Review VPC Flow Logs for network activity
# - Isolate compromised instance if needed

# 3. Remediate
# - Block malicious IPs in Security Groups
# - Rotate credentials if compromised
# - Terminate/replace affected resources

# 4. Document
# - Update incident log
# - Create JIRA ticket
# - Notify security team
```

## 🧪 Testing & Validation

### Security Control Testing

```bash
# Test 1: IAM Password Policy
aws iam get-account-password-policy

# Test 2: MFA Status
aws iam get-credential-report

# Test 3: GuardDuty Status
aws guardduty get-detector \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

# Test 4: CloudTrail Logging
aws cloudtrail get-trail-status --name <TRAIL_NAME>

# Test 5: Encryption Status
aws kms list-keys
aws kms describe-key --key-id <KEY_ID>

# Test 6: Config Rules Compliance
aws configservice describe-compliance-by-config-rule
```

### Compliance Validation

```bash
# Generate CIS Benchmark report
cd scripts
python3 compliance-report.py --framework cis --level 1

# Check specific control
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name <RULE_NAME>
```

## 📚 Documentation

- [Architecture Details](docs/ARCHITECTURE.md) - Deep dive into security architecture
- [Deployment Guide](docs/DEPLOYMENT.md) - Step-by-step deployment instructions
- [Compliance Guide](docs/COMPLIANCE.md) - Compliance framework mappings
- [Operations Runbook](docs/RUNBOOK.md) - Day-to-day operations procedures
- [Incident Response](docs/INCIDENT-RESPONSE.md) - Security incident procedures

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/security-enhancement`)
3. Commit changes (`git commit -am 'Add new security control'`)
4. Push to branch (`git push origin feature/security-enhancement`)
5. Create Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Ashok Kumar Nallam**

- 🔗 GitHub: [@AshokNaidu-Code](https://github.com/AshokNaidu-Code)
- 💼 LinkedIn: [linkedin.com/in/ashoknallam](https://linkedin.com/in/ashoknallam)
- 📧 Email: ashoknallam06@gmail.com
- 📱 Phone: +91 9963066949

## 🌟 Acknowledgments

- CIS AWS Foundations Benchmark
- AWS Security Best Practices
- NIST Cybersecurity Framework
- Cloud Security Alliance

---

**⭐ Star this repository if you find it helpful!**

**🔒 Built with security-first mindset for production AWS environments**