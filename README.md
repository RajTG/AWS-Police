# AWS-Police
A lightweight Python tool to scan AWS infrastructure for common security misconfigurations.

## Features

- **S3** : Buckets: Public access, encryption, versioning, logging
- **EC2**: Security groups, public IPs, IMDSv2 enforcement, unencrypted volumes
- **IAM**: Missing MFA, old access keys, password policy
- **RDS**: Public access, encryption, backup retention

## Prerequisites

Python 3.8 or higher
AWS account with credentials
IAM user with SecurityAudit policy (or read-only permissions)

## Quick Start

```bash
# Clone repository
git clone https://github.com/yourusername/aws-security-scanner.git
cd aws-security-scanner

# Install dependencies
pip install boto3 python-dotenv

# Create .env file with your AWS credentials
cat > .env << 'EOF'
AWS_ACCESS_KEY_ID=your_access_key_here
AWS_SECRET_ACCESS_KEY=your_secret_key_here
AWS_DEFAULT_REGION=us-east-1
EOF

# Run scanner
python3 aws_scanner.py --output report.txt
```

## Usage

```bash
# Scan specific regions
python3 aws_scanner.py --regions us-east-1 us-west-2 --output report.txt

# Scan all regions
python3 aws_scanner.py --all-regions --output report.txt

# Scan specific services
python3 aws_scanner.py --services s3 iam --output report.txt

# JSON output
python3 aws_scanner.py --format json --output report.json
```

## AWS Permissions

Create an IAM user with the `SecurityAudit` policy or use this minimal policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ec2:Describe*",
      "s3:GetBucket*",
      "s3:ListAllMyBuckets",
      "iam:List*",
      "iam:Get*",
      "rds:Describe*"
    ],
    "Resource": "*"
  }]
}
```

## License

MIT

