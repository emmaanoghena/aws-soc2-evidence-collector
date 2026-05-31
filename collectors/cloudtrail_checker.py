"""
CloudTrail Checker - SOC 2 Evidence Collector
===============================================
Checks CloudTrail configuration against SOC 2 CC7.2 and CC6.7 controls.

Supports two modes:
  - LOCAL MODE:  generates realistic simulated trail data (for demo/testing)
  - LIVE MODE:   connects to a real AWS account via boto3

SOC 2 Controls covered:
  CC7.2 - System monitoring (trails enabled, multi-region, log validation)
  CC6.7 - Encryption and protection of log data (KMS, S3 access)
"""

import pandas as pd
from datetime import datetime
import os

# ----------------------------------------------------------------
# SOC 2 CONTROL MAPPING
# ----------------------------------------------------------------
CONTROL_MAP = {
    "TRAIL_NOT_LOGGING": {
        "soc2_control": "CC7.2",
        "nist_control": "AU-2",
        "description": "CloudTrail trail exists but logging is currently disabled"
    },
    "NOT_MULTIREGION": {
        "soc2_control": "CC7.2",
        "nist_control": "AU-2",
        "description": "Trail does not cover all regions - activity in other regions goes unlogged"
    },
    "NO_LOG_VALIDATION": {
        "soc2_control": "CC7.2",
        "nist_control": "AU-9",
        "description": "Log file validation is disabled - logs could be tampered with undetected"
    },
    "NO_KMS_ENCRYPTION": {
        "soc2_control": "CC6.7",
        "nist_control": "AU-9",
        "description": "Trail logs are not encrypted with KMS - data at rest is unprotected"
    },
    "S3_BUCKET_PUBLIC": {
        "soc2_control": "CC6.1",
        "nist_control": "AC-3",
        "description": "S3 bucket storing trail logs is publicly accessible"
    },
    "NO_TRAILS_FOUND": {
        "soc2_control": "CC7.2",
        "nist_control": "AU-2",
        "description": "No CloudTrail trails found in this account - activity is not being logged"
    },
}


def load_local_simulated():
    """
    LOCAL MODE: returns a list of simulated CloudTrail trail configs.
    Mirrors exactly what boto3 returns in live mode so the evaluate
    function works identically in both modes.
    """
    print("[LOCAL MODE] Using simulated CloudTrail trail data...")

    trails = [
        {
            "TrailName": "medisphere-prod-trail",
            "HomeRegion": "us-east-1",
            "IsMultiRegionTrail": True,
            "LogFileValidationEnabled": True,
            "KMSKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc-123",
            "S3BucketName": "medisphere-cloudtrail-logs",
            "IsLogging": True,
            "HasS3PublicAccess": False,
        },
        {
            "TrailName": "medisphere-dev-trail",
            "HomeRegion": "us-west-2",
            "IsMultiRegionTrail": False,
            "LogFileValidationEnabled": False,
            "KMSKeyId": None,
            "S3BucketName": "medisphere-dev-logs",
            "IsLogging": True,
            "HasS3PublicAccess": False,
        },
        {
            "TrailName": "medisphere-legacy-trail",
            "HomeRegion": "us-east-1",
            "IsMultiRegionTrail": False,
            "LogFileValidationEnabled": False,
            "KMSKeyId": None,
            "S3BucketName": "medisphere-old-logs-bucket",
            "IsLogging": False,
            "HasS3PublicAccess": True,
        },
    ]
    return trails


def load_live_aws():
    """
    LIVE MODE: pulls real CloudTrail configuration from AWS via boto3.
    Requires: aws configure (Access Key, Secret, Region)
    """
    try:
        import boto3
    except ImportError:
        raise ImportError("boto3 not installed. Run: pip install boto3")

    print("[LIVE MODE] Connecting to AWS CloudTrail...")
    ct_client = boto3.client("cloudtrail")
    s3_client = boto3.client("s3")
    trails = []

    response = ct_client.describe_trails(includeShadowTrails=False)

    for trail in response.get("trailList", []):
        name = trail["Name"]

        # Check if the trail is actively logging
        status = ct_client.get_trail_status(Name=name)
        is_logging = status.get("IsLogging", False)

        # Check if the S3 bucket is publicly accessible
        bucket = trail.get("S3BucketName", "")
        s3_public = False
        if bucket:
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if "AllUsers" in grantee.get("URI", ""):
                        s3_public = True
            except Exception:
                pass

        trails.append({
            "TrailName":               name,
            "HomeRegion":              trail.get("HomeRegion", ""),
            "IsMultiRegionTrail":      trail.get("IsMultiRegionTrail", False),
            "LogFileValidationEnabled": trail.get("LogFileValidationEnabled", False),
            "KMSKeyId":                trail.get("KMSKeyId"),
            "S3BucketName":            bucket,
            "IsLogging":               is_logging,
            "HasS3PublicAccess":       s3_public,
        })

    return trails


def evaluate_trail(trail):
    """
    Run all SOC 2 checks against a single trail config dict.
    Returns a list of finding dicts.
    """
    findings = []
    name = trail["TrailName"]

    def add_finding(finding_type, severity):
        ctrl = CONTROL_MAP[finding_type]
        findings.append({
            "trail_name":       name,
            "home_region":      trail.get("HomeRegion", ""),
            "s3_bucket":        trail.get("S3BucketName", ""),
            "is_multiregion":   trail.get("IsMultiRegionTrail", False),
            "log_validation":   trail.get("LogFileValidationEnabled", False),
            "kms_encrypted":    bool(trail.get("KMSKeyId")),
            "is_logging":       trail.get("IsLogging", False),
            "s3_public":        trail.get("HasS3PublicAccess", False),
            "finding_type":     finding_type,
            "severity":         severity,
            "soc2_control":     ctrl["soc2_control"],
            "nist_control":     ctrl["nist_control"],
            "finding_detail":   ctrl["description"],
        })

    # CC7.2 - Check 1: Trail is not actively logging
    if not trail.get("IsLogging"):
        add_finding("TRAIL_NOT_LOGGING", "CRITICAL")

    # CC7.2 - Check 2: Trail does not cover all regions
    if not trail.get("IsMultiRegionTrail"):
        add_finding("NOT_MULTIREGION", "HIGH")

    # CC7.2 - Check 3: Log file validation is off
    if not trail.get("LogFileValidationEnabled"):
        add_finding("NO_LOG_VALIDATION", "HIGH")

    # CC6.7 - Check 4: No KMS encryption on logs
    if not trail.get("KMSKeyId"):
        add_finding("NO_KMS_ENCRYPTION", "MEDIUM")

    # CC6.1 - Check 5: S3 bucket is publicly accessible
    if trail.get("HasS3PublicAccess"):
        add_finding("S3_BUCKET_PUBLIC", "CRITICAL")

    return findings


def run_cloudtrail_checker(mode="local"):
    """
    Main entry point.
    mode: "local" or "live"
    Returns a DataFrame of all findings.
    """
    # Step 1: Load trail data
    if mode == "local":
        trails = load_local_simulated()
    else:
        trails = load_live_aws()

    if not trails:
        print("  No CloudTrail trails found in this account.")
        ctrl = CONTROL_MAP["NO_TRAILS_FOUND"]
        return pd.DataFrame([{
            "trail_name":     "NONE",
            "home_region":    "N/A",
            "s3_bucket":      "N/A",
            "is_multiregion": False,
            "log_validation": False,
            "kms_encrypted":  False,
            "is_logging":     False,
            "s3_public":      False,
            "finding_type":   "NO_TRAILS_FOUND",
            "severity":       "CRITICAL",
            "soc2_control":   ctrl["soc2_control"],
            "nist_control":   ctrl["nist_control"],
            "finding_detail": ctrl["description"],
        }])

    print("  Found " + str(len(trails)) + " trail(s). Evaluating...")

    # Step 2: Evaluate each trail
    all_findings = []
    for trail in trails:
        all_findings.extend(evaluate_trail(trail))

    if not all_findings:
        print("  All trails passed SOC 2 checks.")
        return pd.DataFrame()

    findings_df = pd.DataFrame(all_findings)
    print("  " + str(len(findings_df)) + " findings across " + str(findings_df["trail_name"].nunique()) + " trail(s).")
    return findings_df


def export_findings(findings_df, output_dir="output"):
    """Save findings to a dated CSV in the output directory."""
    os.makedirs(output_dir, exist_ok=True)
    today_str = datetime.today().strftime("%Y-%m-%d")
    filename = output_dir + "/cloudtrail_findings_" + today_str + ".csv"
    findings_df.to_csv(filename, index=False)
    print("  Findings saved to: " + filename)
    return filename


def print_summary(findings_df):
    """Print a human-readable summary to the terminal."""
    print("\n" + "=" * 60)
    print("  CLOUDTRAIL EVIDENCE COLLECTION SUMMARY")
    print("=" * 60)
    print("  Total findings:  " + str(len(findings_df)))
    print("  Affected trails: " + str(findings_df["trail_name"].nunique()))
    print()

    print("  By Severity:")
    for sev, count in findings_df["severity"].value_counts().items():
        icon = {"CRITICAL": "[CRITICAL]", "HIGH": "[HIGH]", "MEDIUM": "[MEDIUM]", "LOW": "[LOW]"}.get(sev, "")
        print("    " + icon + " " + sev + ": " + str(count))

    print()
    print("  By SOC 2 Control:")
    for ctrl, count in findings_df["soc2_control"].value_counts().items():
        print("    " + ctrl + ": " + str(count) + " findings")

    print()
    print("  By Finding Type:")
    for ftype, count in findings_df["finding_type"].value_counts().items():
        print("    " + ftype + ": " + str(count))

    print()
    print("  Trail Details:")
    for _, row in findings_df.drop_duplicates("trail_name").iterrows():
        print("    Trail: " + row["trail_name"] + " (" + row["home_region"] + ")")
        print("      Logging:        " + str(row["is_logging"]))
        print("      Multi-region:   " + str(row["is_multiregion"]))
        print("      Log validation: " + str(row["log_validation"]))
        print("      KMS encrypted:  " + str(row["kms_encrypted"]))
        print("      S3 public:      " + str(row["s3_public"]))

    print("=" * 60)


# ----------------------------------------------------------------
# Run this script directly to test it
# ----------------------------------------------------------------
if __name__ == "__main__":
    print("\nRunning CloudTrail SOC 2 Evidence Collector...\n")

    findings = run_cloudtrail_checker(mode="local")

    if findings is not None and not findings.empty:
        print_summary(findings)
        export_findings(findings, output_dir="output")
