terraform {
  backend "s3" {
    bucket         = "your-company-terraform-state-security"
    key            = "security-framework/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-state-locks"
    encrypt        = true
  }
}