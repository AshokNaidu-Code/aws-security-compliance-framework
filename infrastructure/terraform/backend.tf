terraform {
  backend "s3" {
    bucket         = "my-terraform-state-bucket-102025"
    key            = "security-compliance/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
    kms_key_id     = "arn:aws:kms:us-east-1:712111072557:key/b8e6a8ae-bf6a-4eea-b25e-0b6b407efc31"
  }
}
