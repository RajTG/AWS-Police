
import boto3
import json
import os
from datetime import datetime
from collections import defaultdict
import argparse
import logging


try:
    from dotenv import load_dotenv
    load_dotenv()  
except ImportError:
    pass  

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class Finding:
    """Represents a security finding"""
    def __init__(self, severity, service, resource, issue, remediation, region='global'):
        self.severity = severity
        self.service = service
        self.resource = resource
        self.issue = issue
        self.remediation = remediation
        self.region = region
        self.timestamp = datetime.now().isoformat()
    
    def to_dict(self):
        return {
            'severity': self.severity,
            'service': self.service,
            'resource': self.resource,
            'issue': self.issue,
            'remediation': self.remediation,
            'region': self.region,
            'timestamp': self.timestamp
        }


class BaseChecker:
    """Base class for all security checkers"""
    def __init__(self, session):
        self.session = session
        self.findings = []
    
    def add_finding(self, severity, service, resource, issue, remediation, region='global'):
        """Add a finding"""
        finding = Finding(severity, service, resource, issue, remediation, region)
        self.findings.append(finding)
        logger.debug(f"[{severity}] {service}: {issue}")
    
    def check(self, region=None):
        """Override this method in subclasses"""
        raise NotImplementedError


class S3Checker(BaseChecker):
    """Check S3 buckets for basic security issues"""
    
    def check(self, region=None):
        logger.info("Checking S3 buckets...")
        s3 = self.session.client('s3')
        
        try:
            buckets = s3.list_buckets()['Buckets']
        except Exception as e:
            logger.error(f"Failed to list S3 buckets: {e}")
            return self.findings
        
        for bucket in buckets:
            name = bucket['Name']
            self._check_public_access(s3, name)
            self._check_encryption(s3, name)
            self._check_versioning(s3, name)
        
        return self.findings
    
    def _check_public_access(self, s3, bucket_name):
        """Check if bucket has public access"""
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get('Grants', []):
                uri = grant.get('Grantee', {}).get('URI', '')
                if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                    self.add_finding(
                        'CRITICAL',
                        'S3',
                        bucket_name,
                        'Bucket has public access via ACL',
                        'Remove public access from bucket ACL'
                    )
                    break
        except Exception as e:
            logger.debug(f"Could not check ACL for {bucket_name}: {e}")
    
    def _check_encryption(self, s3, bucket_name):
        """Check if bucket has encryption enabled"""
        try:
            s3.get_bucket_encryption(Bucket=bucket_name)
        except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
            self.add_finding(
                'HIGH',
                'S3',
                bucket_name,
                'Bucket encryption is not enabled',
                'Enable default encryption (AES-256 or KMS)'
            )
        except Exception as e:
            logger.debug(f"Could not check encryption for {bucket_name}: {e}")
    
    def _check_versioning(self, s3, bucket_name):
        """Check if bucket has versioning enabled"""
        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            if versioning.get('Status') != 'Enabled':
                self.add_finding(
                    'MEDIUM',
                    'S3',
                    bucket_name,
                    'Versioning is not enabled',
                    'Enable versioning to protect against accidental deletion'
                )
        except Exception as e:
            logger.debug(f"Could not check versioning for {bucket_name}: {e}")


class EC2Checker(BaseChecker):
    """Check EC2 resources for basic security issues"""
    
    def check(self, region):
        logger.info(f"Checking EC2 in {region}...")
        ec2 = self.session.client('ec2', region_name=region)
        
        self._check_security_groups(ec2, region)
        self._check_instances(ec2, region)
        
        return self.findings
    
    def _check_security_groups(self, ec2, region):
        """Check for overly permissive security groups"""
        try:
            sgs = ec2.describe_security_groups()['SecurityGroups']
            
            for sg in sgs:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 'All')
                    protocol = rule.get('IpProtocol', 'All')
                    
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            # Critical ports
                            if from_port in [22, 3389, 1433, 3306, 5432]:
                                self.add_finding(
                                    'CRITICAL',
                                    'EC2',
                                    f"{sg_name} ({sg_id})",
                                    f'Security group allows port {from_port} from internet',
                                    'Restrict to specific IP addresses',
                                    region
                                )
                            elif from_port != 80 and from_port != 443:
                                self.add_finding(
                                    'HIGH',
                                    'EC2',
                                    f"{sg_name} ({sg_id})",
                                    f'Security group allows port {from_port} from internet',
                                    'Restrict to specific IP addresses',
                                    region
                                )
        except Exception as e:
            logger.error(f"Failed to check security groups in {region}: {e}")
    
    def _check_instances(self, ec2, region):
        """Check EC2 instances for basic issues"""
        try:
            reservations = ec2.describe_instances()['Reservations']
            
            for reservation in reservations:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] == 'terminated':
                        continue
                    
                    instance_id = instance['InstanceId']
                    
                    # Check for public IP
                    if instance.get('PublicIpAddress'):
                        self.add_finding(
                            'MEDIUM',
                            'EC2',
                            instance_id,
                            'Instance has public IP address',
                            'Use private subnets with NAT gateway',
                            region
                        )
                    
                    # Check IMDSv2
                    metadata = instance.get('MetadataOptions', {})
                    if metadata.get('HttpTokens') != 'required':
                        self.add_finding(
                            'MEDIUM',
                            'EC2',
                            instance_id,
                            'IMDSv2 not enforced',
                            'Enable IMDSv2 to prevent SSRF attacks',
                            region
                        )
        except Exception as e:
            logger.error(f"Failed to check instances in {region}: {e}")


class IAMChecker(BaseChecker):
    """Check IAM for basic security issues"""
    
    def check(self, region=None):
        logger.info("Checking IAM...")
        iam = self.session.client('iam')
        
        self._check_users(iam)
        self._check_password_policy(iam)
        
        return self.findings
    
    def _check_users(self, iam):
        """Check IAM users for MFA and old access keys"""
        try:
            users = iam.list_users()['Users']
            
            for user in users:
                username = user['UserName']
                
                # Check MFA
                try:
                    mfa_devices = iam.list_mfa_devices(UserName=username)
                    if not mfa_devices['MFADevices']:
                        self.add_finding(
                            'HIGH',
                            'IAM',
                            username,
                            'User does not have MFA enabled',
                            'Enable MFA for the user'
                        )
                except Exception:
                    pass
                
                # Check access key age
                try:
                    keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
                    for key in keys:
                        age = (datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']).days
                        if age > 90:
                            self.add_finding(
                                'MEDIUM',
                                'IAM',
                                f"{username} ({key['AccessKeyId']})",
                                f'Access key is {age} days old',
                                'Rotate access keys (recommended: every 90 days)'
                            )
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"Failed to check IAM users: {e}")
    
    def _check_password_policy(self, iam):
        """Check if account has password policy"""
        try:
            iam.get_account_password_policy()
        except iam.exceptions.NoSuchEntityException:
            self.add_finding(
                'HIGH',
                'IAM',
                'Account',
                'No password policy configured',
                'Set up account password policy with strong requirements'
            )
        except Exception as e:
            logger.debug(f"Could not check password policy: {e}")


class RDSChecker(BaseChecker):
    """Check RDS databases for basic security issues"""
    
    def check(self, region):
        logger.info(f"Checking RDS in {region}...")
        rds = self.session.client('rds', region_name=region)
        
        try:
            instances = rds.describe_db_instances()['DBInstances']
            
            for instance in instances:
                db_id = instance['DBInstanceIdentifier']
                
                # Check public accessibility
                if instance.get('PubliclyAccessible'):
                    self.add_finding(
                        'CRITICAL',
                        'RDS',
                        db_id,
                        'Database is publicly accessible',
                        'Disable public access, use VPN or bastion',
                        region
                    )
                
                # Check encryption
                if not instance.get('StorageEncrypted'):
                    self.add_finding(
                        'HIGH',
                        'RDS',
                        db_id,
                        'Database storage not encrypted',
                        'Enable encryption at rest',
                        region
                    )
                
                # Check backups
                if instance.get('BackupRetentionPeriod', 0) < 7:
                    self.add_finding(
                        'MEDIUM',
                        'RDS',
                        db_id,
                        'Backup retention less than 7 days',
                        'Set backup retention to at least 7 days',
                        region
                    )
        except Exception as e:
            logger.error(f"Failed to check RDS in {region}: {e}")
        
        return self.findings


class AWSSecurityScanner:
    
    def __init__(self, regions=None, services=None, scan_all_regions=False):
        # Create session - will automatically use credentials from .env file
        self.session = boto3.Session()
        
        # Determine which regions to scan
        if scan_all_regions:
            self.regions = self._get_all_regions()
            logger.info("Scanning ALL regions")
        elif regions:
            self.regions = regions
            logger.info(f"Scanning specific regions: {', '.join(regions)}")
        else:
            # Default to a few common regions if not specified
            self.regions = ['us-east-1', 'us-west-2']
            logger.info(f"No regions specified, using default: {', '.join(self.regions)}")
        
        self.services = services or ['s3', 'ec2', 'iam', 'rds']
        self.all_findings = []
    
    def _get_all_regions(self):
        """Get all AWS regions"""
        try:
            ec2 = self.session.client('ec2', region_name='us-east-1')
            response = ec2.describe_regions()
            return [r['RegionName'] for r in response['Regions']]
        except Exception as e:
            logger.warning(f"Could not get regions: {e}. Using default.")
            return ['us-east-1', 'us-west-2']
    
    def run(self):
        
        logger.info("=== Starting AWS Security Scan ===")
        logger.info(f"Regions to scan: {', '.join(self.regions)} ({len(self.regions)} total)")
        logger.info(f"Services to scan: {', '.join(self.services)}")
        logger.info("")
        
        # Global services (run once)
        if 's3' in self.services:
            checker = S3Checker(self.session)
            self.all_findings.extend(checker.check())
        
        if 'iam' in self.services:
            checker = IAMChecker(self.session)
            self.all_findings.extend(checker.check())
        
        # Regional services (run for each region)
        for region in self.regions:
            if 'ec2' in self.services:
                checker = EC2Checker(self.session)
                self.all_findings.extend(checker.check(region))
            
            if 'rds' in self.services:
                checker = RDSChecker(self.session)
                self.all_findings.extend(checker.check(region))
        
        logger.info("")
        logger.info(f"=== Scan Complete: {len(self.all_findings)} findings ===")
        return self.all_findings
    
    def generate_report(self, output_file=None, format='text'):

        summary = self._get_summary()
        
        if format == 'json':
            report = {
                'scan_date': datetime.now().isoformat(),
                'summary': summary,
                'findings': [f.to_dict() for f in self.all_findings]
            }
            output = json.dumps(report, indent=2)
        else:
            output = self._generate_text_report(summary)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            logger.info(f"Report saved to: {output_file}")
        else:
            print(output)
    
    def _get_summary(self):
        
        summary = {
            'total': len(self.all_findings),
            'by_severity': defaultdict(int),
            'by_service': defaultdict(int)
        }
        
        for finding in self.all_findings:
            summary['by_severity'][finding.severity] += 1
            summary['by_service'][finding.service] += 1
        
        return {
            'total': summary['total'],
            'by_severity': dict(summary['by_severity']),
            'by_service': dict(summary['by_service'])
        }
    
    def _generate_text_report(self, summary):
        
        lines = [
            "=" * 80,
            "AWS SECURITY SCAN REPORT",
            "=" * 80,
            f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total Findings: {summary['total']}",
            "",
            "Findings by Severity:",
        ]
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = summary['by_severity'].get(severity, 0)
            if count > 0:
                lines.append(f"  {severity}: {count}")
        
        lines.extend([
            "",
            "Findings by Service:",
        ])
        
        for service, count in summary['by_service'].items():
            lines.append(f"  {service}: {count}")
        
        lines.extend([
            "",
            "=" * 80,
            "DETAILED FINDINGS",
            "=" * 80,
            ""
        ])
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_findings = sorted(
            self.all_findings,
            key=lambda x: severity_order.get(x.severity, 4)
        )
        
        for finding in sorted_findings:
            lines.extend([
                f"[{finding.severity}] {finding.service} - {finding.resource}",
                f"Region: {finding.region}",
                f"Issue: {finding.issue}",
                f"Remediation: {finding.remediation}",
                "-" * 80,
                ""
            ])
        
        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='AWS Security Scanner - Check for common misconfigurations (uses .env file for credentials)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Credentials:
  Create a .env file in the same directory with:
    AWS_ACCESS_KEY_ID=your_access_key
    AWS_SECRET_ACCESS_KEY=your_secret_key
    AWS_DEFAULT_REGION=us-east-1

Examples:
  # Scan specific regions
  python3 aws_scanner.py --regions us-east-1 us-west-2 --output report.txt
  
  # Scan ALL regions
  python3 aws_scanner.py --all-regions --output report.txt
  
  # Scan specific services in all regions
  python3 aws_scanner.py --all-regions --services s3 iam --output report.txt
        """
    )
    parser.add_argument(
        '--regions',
        nargs='+',
        metavar='REGION',
        help='Specific regions to scan (e.g., us-east-1 us-west-2 eu-west-1)'
    )
    parser.add_argument(
        '--all-regions',
        action='store_true',
        help='Scan ALL available AWS regions (overrides --regions)'
    )
    parser.add_argument(
        '--services',
        nargs='+',
        choices=['s3', 'ec2', 'iam', 'rds'],
        help='Specific services to scan (default: all services)'
    )
    parser.add_argument(
        '--output',
        help='Output file path (default: print to console)'
    )
    parser.add_argument(
        '--format',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate arguments
    if args.regions and args.all_regions:
        logger.warning("Both --regions and --all-regions specified. Using --all-regions.")
    
    try:
        scanner = AWSSecurityScanner(
            regions=args.regions,
            services=args.services,
            scan_all_regions=args.all_regions
        )
        
        scanner.run()
        scanner.generate_report(
            output_file=args.output,
            format=args.format
        )
    
    except Exception as e:
        logger.error(f"Scanner failed: {e}")
        import traceback
        traceback.print_exc()
        exit(1)


if __name__ == '__main__':
    main()