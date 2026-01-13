#!/usr/bin/env python3
"""
AWS Security Audit - Comprehensive AWS security assessment tool
Covers IAM, S3, EC2, VPC, CloudTrail, and more
"""

import argparse
import boto3
import json
import csv
import base64
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
from botocore.exceptions import ClientError
import io


class AWSSecurityAudit:
    def __init__(self, profile: str = None, region: str = None):
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.findings = []
        self.region = region or self.session.region_name or 'us-east-1'

    def log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")

    def add_finding(self, title: str, severity: str, resource: str,
                    description: str, remediation: str, service: str):
        finding = {
            "title": title,
            "severity": severity,
            "resource": resource,
            "description": description,
            "remediation": remediation,
            "service": service,
            "region": self.region,
            "timestamp": datetime.now().isoformat()
        }
        self.findings.append(finding)
        self.log(f"[{severity}] {title}: {resource}", "FINDING")

    # ========== IAM AUDITING ==========

    def audit_iam(self):
        """Comprehensive IAM security audit"""
        self.log("Starting IAM audit...")
        iam = self.session.client('iam')

        # Check root account
        self._check_root_account(iam)

        # Check password policy
        self._check_password_policy(iam)

        # Check users
        self._check_iam_users(iam)

        # Check roles
        self._check_iam_roles(iam)

        # Check policies
        self._check_iam_policies(iam)

    def _check_root_account(self, iam):
        """Check root account security"""
        try:
            summary = iam.get_account_summary()['SummaryMap']

            # Check root MFA
            if summary.get('AccountMFAEnabled', 0) != 1:
                self.add_finding(
                    "Root Account MFA Not Enabled",
                    "CRITICAL",
                    "Root Account",
                    "The root account does not have MFA enabled",
                    "Enable MFA for the root account immediately",
                    "IAM"
                )

            # Check root access keys via credential report
            try:
                iam.generate_credential_report()
                import time
                time.sleep(2)
                report = iam.get_credential_report()
                content = base64.b64decode(report['Content']).decode('utf-8')

                reader = csv.DictReader(io.StringIO(content))
                for row in reader:
                    if row['user'] == '<root_account>':
                        if row['access_key_1_active'] == 'true' or row['access_key_2_active'] == 'true':
                            self.add_finding(
                                "Root Account Has Access Keys",
                                "CRITICAL",
                                "Root Account",
                                "The root account has active access keys",
                                "Delete root account access keys",
                                "IAM"
                            )
            except:
                pass

        except ClientError as e:
            self.log(f"Error checking root account: {e}", "ERROR")

    def _check_password_policy(self, iam):
        """Check IAM password policy"""
        try:
            policy = iam.get_account_password_policy()['PasswordPolicy']

            issues = []
            if policy.get('MinimumPasswordLength', 0) < 14:
                issues.append("Minimum length < 14")
            if not policy.get('RequireSymbols', False):
                issues.append("Symbols not required")
            if not policy.get('RequireNumbers', False):
                issues.append("Numbers not required")
            if not policy.get('RequireUppercaseCharacters', False):
                issues.append("Uppercase not required")
            if not policy.get('RequireLowercaseCharacters', False):
                issues.append("Lowercase not required")
            if policy.get('MaxPasswordAge', 999) > 90:
                issues.append("Password age > 90 days")
            if policy.get('PasswordReusePrevention', 0) < 24:
                issues.append("Password reuse prevention < 24")

            if issues:
                self.add_finding(
                    "Weak Password Policy",
                    "MEDIUM",
                    "IAM Password Policy",
                    f"Password policy issues: {', '.join(issues)}",
                    "Strengthen IAM password policy according to CIS benchmarks",
                    "IAM"
                )
        except ClientError as e:
            if 'NoSuchEntity' in str(e):
                self.add_finding(
                    "No Password Policy Configured",
                    "HIGH",
                    "IAM Password Policy",
                    "No IAM password policy is configured",
                    "Configure a strong password policy",
                    "IAM"
                )

    def _check_iam_users(self, iam):
        """Check IAM users for security issues"""
        try:
            # Generate credential report
            iam.generate_credential_report()
            import time
            time.sleep(2)
            report = iam.get_credential_report()
            content = base64.b64decode(report['Content']).decode('utf-8')

            reader = csv.DictReader(io.StringIO(content))
            for row in reader:
                if row['user'] == '<root_account>':
                    continue

                user = row['user']

                # Check MFA
                if row['password_enabled'] == 'true' and row['mfa_active'] == 'false':
                    self.add_finding(
                        "IAM User Without MFA",
                        "HIGH",
                        f"IAM User: {user}",
                        f"User {user} has password but no MFA enabled",
                        "Enable MFA for this user",
                        "IAM"
                    )

                # Check access key age
                for key_num in ['1', '2']:
                    if row[f'access_key_{key_num}_active'] == 'true':
                        last_rotated = row[f'access_key_{key_num}_last_rotated']
                        if last_rotated and last_rotated != 'N/A':
                            try:
                                rotated_date = datetime.fromisoformat(last_rotated.replace('Z', '+00:00'))
                                age_days = (datetime.now(timezone.utc) - rotated_date).days
                                if age_days > 90:
                                    self.add_finding(
                                        "Access Key Not Rotated",
                                        "MEDIUM",
                                        f"IAM User: {user}",
                                        f"Access key {key_num} is {age_days} days old",
                                        "Rotate access keys every 90 days",
                                        "IAM"
                                    )
                            except:
                                pass

                # Check for unused credentials
                if row['password_last_used'] == 'no_information' and row['password_enabled'] == 'true':
                    self.add_finding(
                        "Unused Password",
                        "LOW",
                        f"IAM User: {user}",
                        f"User {user} has password but never used it",
                        "Review if this user needs console access",
                        "IAM"
                    )

        except ClientError as e:
            self.log(f"Error checking IAM users: {e}", "ERROR")

        # Check inline policies
        try:
            users = iam.list_users()['Users']
            for user in users:
                inline_policies = iam.list_user_policies(UserName=user['UserName'])['PolicyNames']
                if inline_policies:
                    self.add_finding(
                        "IAM User Has Inline Policies",
                        "LOW",
                        f"IAM User: {user['UserName']}",
                        f"User has {len(inline_policies)} inline policies",
                        "Use managed policies instead of inline policies",
                        "IAM"
                    )
        except ClientError as e:
            self.log(f"Error checking inline policies: {e}", "ERROR")

    def _check_iam_roles(self, iam):
        """Check IAM roles for security issues"""
        try:
            roles = iam.list_roles()['Roles']

            for role in roles:
                # Skip AWS service roles
                if role['Path'].startswith('/aws-service-role/'):
                    continue

                # Check trust policy for overly permissive access
                trust_policy = role['AssumeRolePolicyDocument']
                for statement in trust_policy.get('Statement', []):
                    principal = statement.get('Principal', {})

                    # Check for wildcard principal
                    if principal == '*' or principal.get('AWS') == '*':
                        self.add_finding(
                            "Role Allows Any AWS Principal",
                            "HIGH",
                            f"IAM Role: {role['RoleName']}",
                            "Role can be assumed by any AWS account",
                            "Restrict trust policy to specific accounts/services",
                            "IAM"
                        )

        except ClientError as e:
            self.log(f"Error checking IAM roles: {e}", "ERROR")

    def _check_iam_policies(self, iam):
        """Check IAM policies for overly permissive permissions"""
        try:
            policies = iam.list_policies(OnlyAttached=True)['Policies']

            for policy in policies:
                # Skip AWS managed policies
                if policy['Arn'].startswith('arn:aws:iam::aws:'):
                    continue

                version_id = policy['DefaultVersionId']
                policy_doc = iam.get_policy_version(
                    PolicyArn=policy['Arn'],
                    VersionId=version_id
                )['PolicyVersion']['Document']

                # Check for admin access
                for statement in policy_doc.get('Statement', []):
                    if statement.get('Effect') == 'Allow':
                        actions = statement.get('Action', [])
                        resources = statement.get('Resource', [])

                        if isinstance(actions, str):
                            actions = [actions]
                        if isinstance(resources, str):
                            resources = [resources]

                        if '*' in actions or '*:*' in actions:
                            if '*' in resources:
                                self.add_finding(
                                    "Policy Grants Full Admin Access",
                                    "HIGH",
                                    f"IAM Policy: {policy['PolicyName']}",
                                    "Policy grants *:* on all resources",
                                    "Apply least privilege principle",
                                    "IAM"
                                )

        except ClientError as e:
            self.log(f"Error checking IAM policies: {e}", "ERROR")

    # ========== S3 AUDITING ==========

    def audit_s3(self):
        """Comprehensive S3 security audit"""
        self.log("Starting S3 audit...")
        s3 = self.session.client('s3')

        try:
            buckets = s3.list_buckets()['Buckets']

            for bucket in buckets:
                bucket_name = bucket['Name']
                self._check_bucket_security(s3, bucket_name)

        except ClientError as e:
            self.log(f"Error listing S3 buckets: {e}", "ERROR")

    def _check_bucket_security(self, s3, bucket_name: str):
        """Check individual bucket security"""

        # Check public access block
        try:
            public_access = s3.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']

            if not all([
                public_access.get('BlockPublicAcls', False),
                public_access.get('IgnorePublicAcls', False),
                public_access.get('BlockPublicPolicy', False),
                public_access.get('RestrictPublicBuckets', False)
            ]):
                self.add_finding(
                    "S3 Public Access Block Not Fully Enabled",
                    "HIGH",
                    f"S3 Bucket: {bucket_name}",
                    "Public access block is not fully configured",
                    "Enable all public access block settings",
                    "S3"
                )
        except ClientError as e:
            if 'NoSuchPublicAccessBlockConfiguration' in str(e):
                self.add_finding(
                    "S3 Bucket Without Public Access Block",
                    "HIGH",
                    f"S3 Bucket: {bucket_name}",
                    "No public access block configuration",
                    "Configure public access block settings",
                    "S3"
                )

        # Check bucket policy
        try:
            policy = s3.get_bucket_policy(Bucket=bucket_name)
            policy_doc = json.loads(policy['Policy'])

            for statement in policy_doc.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    principal = statement.get('Principal', {})
                    if principal == '*' or principal.get('AWS') == '*':
                        self.add_finding(
                            "S3 Bucket Policy Allows Public Access",
                            "CRITICAL",
                            f"S3 Bucket: {bucket_name}",
                            "Bucket policy allows access from any principal",
                            "Restrict bucket policy to specific principals",
                            "S3"
                        )
                        break
        except ClientError:
            pass  # No bucket policy is fine

        # Check encryption
        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as e:
            if 'ServerSideEncryptionConfigurationNotFoundError' in str(e):
                self.add_finding(
                    "S3 Bucket Without Default Encryption",
                    "MEDIUM",
                    f"S3 Bucket: {bucket_name}",
                    "Bucket does not have default encryption enabled",
                    "Enable default encryption with SSE-S3 or SSE-KMS",
                    "S3"
                )

        # Check versioning
        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            if versioning.get('Status') != 'Enabled':
                self.add_finding(
                    "S3 Bucket Versioning Not Enabled",
                    "LOW",
                    f"S3 Bucket: {bucket_name}",
                    "Bucket versioning is not enabled",
                    "Enable versioning for data protection",
                    "S3"
                )
        except ClientError:
            pass

        # Check logging
        try:
            logging = s3.get_bucket_logging(Bucket=bucket_name)
            if 'LoggingEnabled' not in logging:
                self.add_finding(
                    "S3 Bucket Logging Not Enabled",
                    "LOW",
                    f"S3 Bucket: {bucket_name}",
                    "Bucket access logging is not enabled",
                    "Enable access logging for audit trail",
                    "S3"
                )
        except ClientError:
            pass

    # ========== EC2 AUDITING ==========

    def audit_ec2(self):
        """Comprehensive EC2 security audit"""
        self.log("Starting EC2 audit...")
        ec2 = self.session.client('ec2')

        self._check_security_groups(ec2)
        self._check_instances(ec2)
        self._check_ebs_volumes(ec2)
        self._check_vpc_flow_logs(ec2)

    def _check_security_groups(self, ec2):
        """Check security groups for overly permissive rules"""
        try:
            sgs = ec2.describe_security_groups()['SecurityGroups']

            risky_ports = {
                22: 'SSH',
                3389: 'RDP',
                3306: 'MySQL',
                5432: 'PostgreSQL',
                27017: 'MongoDB',
                6379: 'Redis',
                11211: 'Memcached',
                9200: 'Elasticsearch',
                445: 'SMB',
                1433: 'MSSQL',
                23: 'Telnet',
                21: 'FTP'
            }

            for sg in sgs:
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            from_port = rule.get('FromPort', 0)
                            to_port = rule.get('ToPort', 65535)

                            # Check if any risky port is in range
                            for port, service in risky_ports.items():
                                if from_port <= port <= to_port:
                                    self.add_finding(
                                        f"Security Group Allows {service} from Internet",
                                        "CRITICAL" if port in [22, 3389, 3306, 5432] else "HIGH",
                                        f"Security Group: {sg['GroupId']}",
                                        f"Allows 0.0.0.0/0 to port {port} ({service})",
                                        f"Restrict {service} access to specific IPs",
                                        "EC2"
                                    )

        except ClientError as e:
            self.log(f"Error checking security groups: {e}", "ERROR")

    def _check_instances(self, ec2):
        """Check EC2 instances for security issues"""
        try:
            reservations = ec2.describe_instances()['Reservations']

            for reservation in reservations:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']

                    # Check IMDSv2
                    metadata_options = instance.get('MetadataOptions', {})
                    if metadata_options.get('HttpTokens') != 'required':
                        self.add_finding(
                            "Instance Not Using IMDSv2",
                            "MEDIUM",
                            f"EC2 Instance: {instance_id}",
                            "Instance allows IMDSv1 (vulnerable to SSRF)",
                            "Require IMDSv2 tokens for metadata access",
                            "EC2"
                        )

                    # Check for public IP
                    if instance.get('PublicIpAddress'):
                        self.add_finding(
                            "Instance Has Public IP",
                            "LOW",
                            f"EC2 Instance: {instance_id}",
                            f"Instance has public IP: {instance['PublicIpAddress']}",
                            "Use NAT Gateway or private subnets where possible",
                            "EC2"
                        )

                    # Check IAM role
                    if not instance.get('IamInstanceProfile'):
                        self.add_finding(
                            "Instance Without IAM Role",
                            "LOW",
                            f"EC2 Instance: {instance_id}",
                            "Instance does not have an IAM role attached",
                            "Use IAM roles instead of hardcoded credentials",
                            "EC2"
                        )

        except ClientError as e:
            self.log(f"Error checking instances: {e}", "ERROR")

    def _check_ebs_volumes(self, ec2):
        """Check EBS volumes for encryption"""
        try:
            volumes = ec2.describe_volumes()['Volumes']

            for volume in volumes:
                if not volume.get('Encrypted', False):
                    self.add_finding(
                        "Unencrypted EBS Volume",
                        "MEDIUM",
                        f"EBS Volume: {volume['VolumeId']}",
                        "EBS volume is not encrypted",
                        "Enable EBS encryption by default",
                        "EC2"
                    )

        except ClientError as e:
            self.log(f"Error checking EBS volumes: {e}", "ERROR")

    def _check_vpc_flow_logs(self, ec2):
        """Check if VPC flow logs are enabled"""
        try:
            vpcs = ec2.describe_vpcs()['Vpcs']
            flow_logs = ec2.describe_flow_logs()['FlowLogs']

            flow_log_vpc_ids = {fl['ResourceId'] for fl in flow_logs}

            for vpc in vpcs:
                if vpc['VpcId'] not in flow_log_vpc_ids:
                    self.add_finding(
                        "VPC Flow Logs Not Enabled",
                        "MEDIUM",
                        f"VPC: {vpc['VpcId']}",
                        "VPC does not have flow logs enabled",
                        "Enable VPC flow logs for network monitoring",
                        "VPC"
                    )

        except ClientError as e:
            self.log(f"Error checking VPC flow logs: {e}", "ERROR")

    # ========== CLOUDTRAIL AUDITING ==========

    def audit_cloudtrail(self):
        """Check CloudTrail configuration"""
        self.log("Starting CloudTrail audit...")
        cloudtrail = self.session.client('cloudtrail')

        try:
            trails = cloudtrail.describe_trails()['trailList']

            if not trails:
                self.add_finding(
                    "CloudTrail Not Configured",
                    "CRITICAL",
                    "CloudTrail",
                    "No CloudTrail trails are configured",
                    "Enable CloudTrail for audit logging",
                    "CloudTrail"
                )
                return

            for trail in trails:
                trail_name = trail['Name']

                # Check if multi-region
                if not trail.get('IsMultiRegionTrail', False):
                    self.add_finding(
                        "CloudTrail Not Multi-Region",
                        "MEDIUM",
                        f"CloudTrail: {trail_name}",
                        "Trail is not configured for all regions",
                        "Enable multi-region trail",
                        "CloudTrail"
                    )

                # Check log file validation
                if not trail.get('LogFileValidationEnabled', False):
                    self.add_finding(
                        "CloudTrail Log Validation Disabled",
                        "MEDIUM",
                        f"CloudTrail: {trail_name}",
                        "Log file integrity validation is disabled",
                        "Enable log file validation",
                        "CloudTrail"
                    )

                # Check if logging is enabled
                status = cloudtrail.get_trail_status(Name=trail_name)
                if not status.get('IsLogging', False):
                    self.add_finding(
                        "CloudTrail Logging Disabled",
                        "HIGH",
                        f"CloudTrail: {trail_name}",
                        "Trail exists but logging is disabled",
                        "Enable logging on the trail",
                        "CloudTrail"
                    )

        except ClientError as e:
            self.log(f"Error checking CloudTrail: {e}", "ERROR")

    # ========== MAIN AUDIT ==========

    def run_full_audit(self, services: List[str] = None) -> Dict:
        """Run complete security audit"""
        self.log(f"Starting AWS security audit for region {self.region}")
        start_time = datetime.now()

        if services is None:
            services = ['iam', 's3', 'ec2', 'cloudtrail']

        if 'iam' in services:
            self.audit_iam()

        if 's3' in services:
            self.audit_s3()

        if 'ec2' in services:
            self.audit_ec2()

        if 'cloudtrail' in services:
            self.audit_cloudtrail()

        elapsed = (datetime.now() - start_time).total_seconds()

        # Generate summary
        severity_counts = {
            "CRITICAL": len([f for f in self.findings if f['severity'] == 'CRITICAL']),
            "HIGH": len([f for f in self.findings if f['severity'] == 'HIGH']),
            "MEDIUM": len([f for f in self.findings if f['severity'] == 'MEDIUM']),
            "LOW": len([f for f in self.findings if f['severity'] == 'LOW'])
        }

        results = {
            "audit_time": datetime.now().isoformat(),
            "duration_seconds": round(elapsed, 2),
            "region": self.region,
            "services_audited": services,
            "total_findings": len(self.findings),
            "severity_counts": severity_counts,
            "findings": self.findings
        }

        self.log(f"Audit completed in {elapsed:.2f} seconds")
        self.log(f"Total findings: {len(self.findings)}")
        self.log(f"Critical: {severity_counts['CRITICAL']}, High: {severity_counts['HIGH']}, "
                f"Medium: {severity_counts['MEDIUM']}, Low: {severity_counts['LOW']}")

        return results

    def save_report(self, results: Dict, output_file: str):
        """Save audit results to file"""
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        self.log(f"Report saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(description='AWS Security Audit')
    parser.add_argument('--profile', '-p', help='AWS profile name')
    parser.add_argument('--region', '-r', help='AWS region')
    parser.add_argument('--services', '-s', help='Services to audit (comma-separated)')
    parser.add_argument('--output', '-o', default='aws_audit_results.json', help='Output file')

    args = parser.parse_args()

    services = args.services.split(',') if args.services else None

    auditor = AWSSecurityAudit(profile=args.profile, region=args.region)
    results = auditor.run_full_audit(services=services)
    auditor.save_report(results, args.output)


if __name__ == '__main__':
    main()
