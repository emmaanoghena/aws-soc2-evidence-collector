"""
S3 Config Checker - SOC 2 Evidence Collector
==============================================
Checks S3 bucket configurations against SOC 2 controls.

Supports two modes:
  - LOCAL MODE:  uses simulated bucket data (for demo/testing)
  - LIVE MODE:   connects to a real AWS account via boto3

SOC 2 Controls covered:
  CC6.1 - Logical access controls (public access blocking)
  CC6.7 - Encryption of data at rest (server-side encryption)
  A1.2  - Data availability and recovery (versioning)
"""

import pandas as pd
from datetime import datetime
import os

# ----------------------------------------------------------------
# SOC 2 CONTROL MAPPING
# ----------------------------------------------------------------
CONTROL_MAP = {
    "S3_PUBLIC_ACCESS_ENABLED": {
        "soc2_control": "CC6.1",
        "nist_control": "AC-3",
        "description": "S3 bucket does not have public access blocked - data may be exposed to the internet"
    },
    "S3_NO_ENCRYPTION": {
        "soc2_control": "CC6.7",
        "nist_control": "SC-28",
        "description": "S3 bucket does not have server-side encryption enabled - data at rest is unprotected"
    },
    "S3_NO_VERSIONING": {
        "soc2_control": "A1.2",
        "nist_control": "CP-9",
        "description": "S3 bucket does not have versioning enabled - deleted or overwritten data cannot be recovered"
    },
}


def load_local_simulated():
    """
    LOCAL MODE: returns a list of simulated S3 bucket configs.
    Mirrors what boto3 returns in live mode.
    """
    print("[LOCAL MODE] Using simulated S3 bucket data...")

    buckets = [
        {
            "BucketName": "medisphere-patient-records",
            "Region": "us-east-1",
            "PublicAccessBlocked": True,
            "EncryptionEnabled": True,
            "EncryptionType": "aws:kms",
            "VersioningEnabled": True,
        },
        {
            "BucketName": "medisphere-cloudtrail-logs",
            "Region": "us-east-1",
            "PublicAccessBlocked": True,
            "EncryptionEnabled": True,
            "EncryptionType": "AES256",
            "VersioningEnabled": False,
        },
        {
            "BucketName": "medisphere-dev-uploads",
            "Region": "us-west-2",
            "PublicAccessBlocked": False,
            "EncryptionEnabled": False,
            "EncryptionType": None,
            "VersioningEnabled": False,
        },
        {
            "BucketName": "medisphere-staff-assets",
            "Region": "us-east-1",
            "PublicAccessBlocked": False,
            "EncryptionEnabled": True,
            "EncryptionType": "AES256",
            "VersioningEnabled": False,
        },
        {
            "BucketName": "medisphere-billing-exports",
            "Region": "us-east-1",
            "PublicAccessBlocked": True,
            "EncryptionEnabled": False,
            "EncryptionType": None,
            "VersioningEnabled": False,
        },
    ]
    return buckets


def load_live_aws():
    """
    LIVE MODE: pulls real S3 bucket configuration from AWS via boto3.
    Requires: aws configure (Access Key, Secret, Region)
    """
    try:
        import boto3
    except ImportError:
        raise ImportError("boto3 not installed. Run: pip install boto3")

    print("[LIVE MODE] Connecting to AWS S3...")
    s3 = boto3.client("s3")
    buckets = []

    all_buckets = s3.list_buckets().get("Buckets", [])
    print("  Found " + str(len(all_buckets)) + " buckets. Checking each...")

    for bucket in all_buckets:
        name = bucket["Name"]

        # Get bucket region
        try:
            location = s3.get_bucket_location(Bucket=name)
            region = location.get("LocationConstraint") or "us-east-1"
        except Exception:
            region = "unknown"

        # Check public access block
        try:
            pub = s3.get_public_access_block(Bucket=name)
            config = pub.get("PublicAccessBlockConfiguration", {})
            public_blocked = all([
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False),
            ])
        except Exception:
            public_blocked = False

        # Check encryption
        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            enc_enabled = len(rules) > 0
            enc_type = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") if rules else None
        except Exception:
            enc_enabled = False
            enc_type = None

        # Check versioning
        try:
            ver = s3.get_bucket_versioning(Bucket=name)
            versioning = ver.get("Status") == "Enabled"
        except Exception:
            versioning = False

        buckets.append({
            "BucketName":        name,
            "Region":            region,
            "PublicAccessBlocked": public_blocked,
            "EncryptionEnabled": enc_enabled,
            "EncryptionType":    enc_type,
            "VersioningEnabled": versioning,
        })

    return buckets


def evaluate_bucket(bucket):
    """
    Run all SOC 2 checks against a single bucket config dict.
    Returns a list of finding dicts.
    """
    findings = []
    name = bucket["BucketName"]

    def add_finding(finding_type, severity):
        ctrl = CONTROL_MAP[finding_type]
        findings.append({
            "bucket_name":       name,
            "region":            bucket.get("Region", ""),
            "public_blocked":    bucket.get("PublicAccessBlocked", False),
            "encryption":        bucket.get("EncryptionEnabled", False),
            "encryption_type":   bucket.get("EncryptionType") or "None",
            "versioning":        bucket.get("VersioningEnabled", False),
            "finding_type":      finding_type,
            "severity":          severity,
            "soc2_control":      ctrl["soc2_control"],
            "nist_control":      ctrl["nist_control"],
            "finding_detail":    ctrl["description"],
        })

    # CC6.1 - Check 1: Public access not blocked
    if not bucket.get("PublicAccessBlocked"):
        add_finding("S3_PUBLIC_ACCESS_ENABLED", "CRITICAL")

    # CC6.7 - Check 2: No server-side encryption
    if not bucket.get("EncryptionEnabled"):
        add_finding("S3_NO_ENCRYPTION", "HIGH")

    # A1.2 - Check 3: Versioning not enabled
    if not bucket.get("VersioningEnabled"):
        add_finding("S3_NO_VERSIONING", "MEDIUM")

    return findings


def run_s3_checker(mode="local"):
    """
    Main entry point.
    mode: "local" or "live"
    Returns a DataFrame of all findings.
    """
    if mode == "local":
        buckets = load_local_simulated()
    else:
        buckets = load_live_aws()

    print("  Evaluating " + str(len(buckets)) + " bucket(s)...")

    all_findings = []
    for bucket in buckets:
        all_findings.extend(evaluate_bucket(bucket))

    if not all_findings:
        print("  All buckets passed SOC 2 checks.")
        return pd.DataFrame()

    findings_df = pd.DataFrame(all_findings)
    print("  " + str(len(findings_df)) + " findings across " + str(findings_df["bucket_name"].nunique()) + " bucket(s).")
    return findings_df


def export_findings(findings_df, output_dir="output"):
    """Save findings to a dated CSV in the output directory."""
    os.makedirs(output_dir, exist_ok=True)
    today_str = datetime.today().strftime("%Y-%m-%d")
    filename = output_dir + "/s3_findings_" + today_str + ".csv"
    findings_df.to_csv(filename, index=False)
    print("  Findings saved to: " + filename)
    return filename


def print_summary(findings_df):
    """Print a human-readable summary to the terminal."""
    print("\n" + "=" * 60)
    print("  S3 EVIDENCE COLLECTION SUMMARY")
    print("=" * 60)
    print("  Total findings:   " + str(len(findings_df)))
    print("  Affected buckets: " + str(findings_df["bucket_name"].nunique()))
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
    print("  Bucket Details:")
    for _, row in findings_df.drop_duplicates("bucket_name").iterrows():
        pub = "BLOCKED" if row["public_blocked"] else "EXPOSED"
        enc = row["encryption_type"] if row["encryption"] else "NONE"
        ver = "ON" if row["versioning"] else "OFF"
        print("    " + row["bucket_name"])
        print("      Public access: " + pub + " | Encryption: " + enc + " | Versioning: " + ver)

    print("=" * 60)


# ----------------------------------------------------------------
# Run this script directly to test it
# ----------------------------------------------------------------
if __name__ == "__main__":
    print("\nRunning S3 SOC 2 Evidence Collector...\n")

    findings = run_s3_checker(mode="local")

    if findings is not None and not findings.empty:
        print_summary(findings)
        export_findings(findings, output_dir="output")
