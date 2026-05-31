"""
Security Hub Collector - SOC 2 Evidence Collector
===================================================
Pulls HIGH and CRITICAL findings from AWS Security Hub
and maps them to SOC 2 CC6.x and NIST 800-53 controls.

Supports two modes:
  - LOCAL MODE:  uses simulated Security Hub findings (for demo/testing)
  - LIVE MODE:   connects to a real AWS account via boto3

SOC 2 Controls covered:
  CC6.1 - Logical access controls
  CC6.6 - Threat and vulnerability management
  CC6.7 - Encryption controls
  CC7.1 - Vulnerability detection
  CC7.2 - System monitoring and alerting
"""

import pandas as pd
from datetime import datetime
import os

# ----------------------------------------------------------------
# SECURITY HUB FINDING TYPE -> SOC 2 CONTROL MAPPING
# Maps the finding's ProductFields type prefix to a SOC 2 control.
# In live mode, Security Hub finding types follow the format:
#   "Software and Configuration Checks/..."
#   "Industry and Regulatory Standards/..."
#   "TTPs/..."
# ----------------------------------------------------------------
FINDING_TYPE_MAP = {
    "Software and Configuration Checks": {
        "soc2_control": "CC7.1",
        "nist_control": "SI-2",
        "description": "Software misconfiguration or missing security patch detected"
    },
    "Industry and Regulatory Standards": {
        "soc2_control": "CC6.6",
        "nist_control": "RA-5",
        "description": "Violation of an industry or regulatory security standard"
    },
    "TTPs": {
        "soc2_control": "CC7.2",
        "nist_control": "SI-4",
        "description": "Tactic, Technique, or Procedure associated with known threat actor behavior"
    },
    "Sensitive Data Identifications": {
        "soc2_control": "CC6.7",
        "nist_control": "SC-28",
        "description": "Sensitive or regulated data found in an unexpected or unprotected location"
    },
    "Unusual Behaviors": {
        "soc2_control": "CC7.2",
        "nist_control": "SI-4",
        "description": "Anomalous or unusual behavior detected on a resource or account"
    },
    "Default": {
        "soc2_control": "CC6.1",
        "nist_control": "CM-6",
        "description": "Security misconfiguration detected by AWS Security Hub"
    },
}


def load_local_simulated():
    """
    LOCAL MODE: returns a list of simulated Security Hub findings.
    Each dict mirrors the key fields from a real Security Hub finding.
    Only HIGH and CRITICAL are included (same filter as live mode).
    """
    print("[LOCAL MODE] Using simulated Security Hub findings...")

    findings = [
        {
            "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/IAM.1/finding/001",
            "Title": "IAM root user access key should not exist",
            "Description": "The root account has an active access key. Root access keys provide unrestricted access to the AWS account.",
            "Severity": "CRITICAL",
            "ResourceType": "AwsIamUser",
            "ResourceId": "root",
            "Region": "us-east-1",
            "ProductName": "Security Hub",
            "ComplianceStatus": "FAILED",
            "FindingType": "Software and Configuration Checks",
            "CreatedAt": "2026-05-01",
            "UpdatedAt": "2026-05-28",
            "WorkflowStatus": "NEW",
        },
        {
            "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/IAM.6/finding/002",
            "Title": "Hardware MFA should be enabled for the root user",
            "Description": "The root account does not have hardware MFA enabled.",
            "Severity": "CRITICAL",
            "ResourceType": "AwsIamUser",
            "ResourceId": "root",
            "Region": "us-east-1",
            "ProductName": "Security Hub",
            "ComplianceStatus": "FAILED",
            "FindingType": "Software and Configuration Checks",
            "CreatedAt": "2026-05-01",
            "UpdatedAt": "2026-05-28",
            "WorkflowStatus": "NEW",
        },
        {
            "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.2/finding/003",
            "Title": "S3 buckets should prohibit public read access",
            "Description": "medisphere-dev-uploads allows public read access which could expose sensitive data.",
            "Severity": "CRITICAL",
            "ResourceType": "AwsS3Bucket",
            "ResourceId": "medisphere-dev-uploads",
            "Region": "us-east-1",
            "ProductName": "Security Hub",
            "ComplianceStatus": "FAILED",
            "FindingType": "Software and Configuration Checks",
            "CreatedAt": "2026-05-10",
            "UpdatedAt": "2026-05-29",
            "WorkflowStatus": "NEW",
        },
        {
            "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/CloudTrail.2/finding/004",
            "Title": "CloudTrail should have encryption at rest enabled",
            "Description": "medisphere-legacy-trail does not have KMS encryption enabled for log files.",
            "Severity": "HIGH",
            "ResourceType": "AwsCloudTrailTrail",
            "ResourceId": "medisphere-legacy-trail",
            "Region": "us-east-1",
            "ProductName": "Security Hub",
            "ComplianceStatus": "FAILED",
            "FindingType": "Industry and Regulatory Standards",
            "CreatedAt": "2026-05-05",
            "UpdatedAt": "2026-05-27",
            "WorkflowStatus": "NEW",
        },
        {
            "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.6/finding/005",
            "Title": "VPC flow logging should be enabled in all VPCs",
            "Description": "VPC vpc-0abc123 does not have flow logging enabled. Network traffic is not being recorded.",
            "Severity": "MEDIUM",
            "ResourceType": "AwsEc2Vpc",
            "ResourceId": "vpc-0abc123",
            "Region": "us-east-1",
            "ProductName": "Security Hub",
            "ComplianceStatus": "FAILED",
            "FindingType": "Software and Configuration Checks",
            "CreatedAt": "2026-05-12",
            "UpdatedAt": "2026-05-28",
            "WorkflowStatus": "NEW",
        },
        {
            "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/GuardDuty.1/finding/006",
            "Title": "GuardDuty should be enabled",
            "Description": "GuardDuty is not enabled in this region. Threat detection is inactive.",
            "Severity": "HIGH",
            "ResourceType": "AwsAccount",
            "ResourceId": "123456789012",
            "Region": "us-east-1",
            "ProductName": "Security Hub",
            "ComplianceStatus": "FAILED",
            "FindingType": "Unusual Behaviors",
            "CreatedAt": "2026-04-20",
            "UpdatedAt": "2026-05-29",
            "WorkflowStatus": "NEW",
        },
        {
            "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/RDS.3/finding/007",
            "Title": "RDS DB instances should have encryption at rest enabled",
            "Description": "RDS instance medisphere-prod-db does not have encryption at rest enabled.",
            "Severity": "HIGH",
            "ResourceType": "AwsRdsDbInstance",
            "ResourceId": "medisphere-prod-db",
            "Region": "us-east-1",
            "ProductName": "Security Hub",
            "ComplianceStatus": "FAILED",
            "FindingType": "Sensitive Data Identifications",
            "CreatedAt": "2026-05-15",
            "UpdatedAt": "2026-05-30",
            "WorkflowStatus": "NEW",
        },
        {
            "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/IAM.3/finding/008",
            "Title": "IAM users access keys should be rotated every 90 days or less",
            "Description": "Multiple IAM users have access keys older than 90 days.",
            "Severity": "HIGH",
            "ResourceType": "AwsIamUser",
            "ResourceId": "multiple-users",
            "Region": "us-east-1",
            "ProductName": "Security Hub",
            "ComplianceStatus": "FAILED",
            "FindingType": "Industry and Regulatory Standards",
            "CreatedAt": "2026-05-01",
            "UpdatedAt": "2026-05-31",
            "WorkflowStatus": "NEW",
        },
    ]

    # Filter to only HIGH and CRITICAL (same as live mode filter)
    filtered = [f for f in findings if f["Severity"] in ("HIGH", "CRITICAL")]
    print("  " + str(len(filtered)) + " HIGH/CRITICAL findings loaded (1 MEDIUM filtered out).")
    return filtered


def load_live_aws():
    """
    LIVE MODE: pulls real findings from AWS Security Hub via boto3.
    Requires: Security Hub enabled in your AWS account + aws configure
    """
    try:
        import boto3
    except ImportError:
        raise ImportError("boto3 not installed. Run: pip install boto3")

    print("[LIVE MODE] Connecting to AWS Security Hub...")
    sh = boto3.client("securityhub")
    findings = []

    # Filter to only ACTIVE, HIGH and CRITICAL findings
    filters = {
        "SeverityLabel": [
            {"Value": "HIGH",     "Comparison": "EQUALS"},
            {"Value": "CRITICAL", "Comparison": "EQUALS"},
        ],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
    }

    paginator = sh.get_paginator("get_findings")
    for page in paginator.paginate(Filters=filters):
        for f in page.get("Findings", []):
            resources = f.get("Resources", [{}])
            resource = resources[0] if resources else {}

            # Extract the finding type prefix (first segment)
            raw_types = f.get("Types", ["Default"])
            raw_type = raw_types[0] if raw_types else "Default"
            type_prefix = raw_type.split("/")[0] if "/" in raw_type else raw_type

            findings.append({
                "Id":               f.get("Id", ""),
                "Title":            f.get("Title", ""),
                "Description":      f.get("Description", ""),
                "Severity":         f.get("Severity", {}).get("Label", ""),
                "ResourceType":     resource.get("Type", ""),
                "ResourceId":       resource.get("Id", ""),
                "Region":           f.get("Region", ""),
                "ProductName":      f.get("ProductFields", {}).get("aws/securityhub/ProductName", "Security Hub"),
                "ComplianceStatus": f.get("Compliance", {}).get("Status", ""),
                "FindingType":      type_prefix,
                "CreatedAt":        str(f.get("CreatedAt", ""))[:10],
                "UpdatedAt":        str(f.get("UpdatedAt", ""))[:10],
                "WorkflowStatus":   f.get("Workflow", {}).get("Status", ""),
            })

    return findings


def map_finding(finding):
    """
    Map a single Security Hub finding to SOC 2 and NIST controls.
    Returns a flat dict ready for the output DataFrame.
    """
    finding_type = finding.get("FindingType", "Default")
    ctrl = FINDING_TYPE_MAP.get(finding_type, FINDING_TYPE_MAP["Default"])

    return {
        "finding_id":       finding.get("Id", "")[-60:],
        "title":            finding.get("Title", ""),
        "description":      finding.get("Description", ""),
        "severity":         finding.get("Severity", ""),
        "resource_type":    finding.get("ResourceType", ""),
        "resource_id":      finding.get("ResourceId", ""),
        "region":           finding.get("Region", ""),
        "product":          finding.get("ProductName", ""),
        "compliance_status": finding.get("ComplianceStatus", ""),
        "finding_type":     finding_type,
        "workflow_status":  finding.get("WorkflowStatus", ""),
        "created_at":       finding.get("CreatedAt", ""),
        "updated_at":       finding.get("UpdatedAt", ""),
        "soc2_control":     ctrl["soc2_control"],
        "nist_control":     ctrl["nist_control"],
        "control_rationale": ctrl["description"],
    }


def run_securityhub_collector(mode="local"):
    """
    Main entry point.
    mode: "local" or "live"
    Returns a DataFrame of all mapped findings.
    """
    if mode == "local":
        raw_findings = load_local_simulated()
    else:
        raw_findings = load_live_aws()

    if not raw_findings:
        print("  No HIGH/CRITICAL findings in Security Hub.")
        return pd.DataFrame()

    mapped = [map_finding(f) for f in raw_findings]
    findings_df = pd.DataFrame(mapped)

    print("  " + str(len(findings_df)) + " findings mapped to SOC 2 controls.")
    return findings_df


def export_findings(findings_df, output_dir="output"):
    """Save findings to a dated CSV in the output directory."""
    os.makedirs(output_dir, exist_ok=True)
    today_str = datetime.today().strftime("%Y-%m-%d")
    filename = output_dir + "/securityhub_findings_" + today_str + ".csv"
    findings_df.to_csv(filename, index=False)
    print("  Findings saved to: " + filename)
    return filename


def print_summary(findings_df):
    """Print a human-readable summary to the terminal."""
    print("\n" + "=" * 60)
    print("  SECURITY HUB EVIDENCE COLLECTION SUMMARY")
    print("=" * 60)
    print("  Total findings:  " + str(len(findings_df)))
    print()

    print("  By Severity:")
    for sev, count in findings_df["severity"].value_counts().items():
        icon = {"CRITICAL": "[CRITICAL]", "HIGH": "[HIGH]", "MEDIUM": "[MEDIUM]"}.get(sev, "")
        print("    " + icon + " " + sev + ": " + str(count))

    print()
    print("  By SOC 2 Control:")
    for ctrl, count in findings_df["soc2_control"].value_counts().items():
        print("    " + ctrl + ": " + str(count) + " findings")

    print()
    print("  By Resource Type:")
    for rtype, count in findings_df["resource_type"].value_counts().items():
        print("    " + rtype + ": " + str(count))

    print()
    print("  Findings:")
    for _, row in findings_df.iterrows():
        print("    [" + row["severity"] + "] " + row["title"])
        print("      Resource: " + row["resource_id"])
        print("      SOC 2:    " + row["soc2_control"] + " | NIST: " + row["nist_control"])

    print("=" * 60)


# ----------------------------------------------------------------
# Run this script directly to test it
# ----------------------------------------------------------------
if __name__ == "__main__":
    print("\nRunning Security Hub SOC 2 Evidence Collector...\n")

    findings = run_securityhub_collector(mode="local")

    if findings is not None and not findings.empty:
        print_summary(findings)
        export_findings(findings, output_dir="output")
