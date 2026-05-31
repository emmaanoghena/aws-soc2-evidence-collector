"""
IAM Collector - SOC 2 Evidence Collector
=========================================
Collects IAM user data and evaluates each user against SOC 2 CC6.x controls.

Supports two modes:
  - LOCAL MODE:  reads from a CSV file (great for development/demo)
  - LIVE MODE:   connects to a real AWS account via boto3

SOC 2 Controls covered:
  CC6.1 - Logical access controls (MFA, password rotation, key age)
  CC6.2 - Access removal (inactive users)
  CC6.3 - Privileged access management
"""

import pandas as pd
from datetime import datetime, date
import os

# ----------------------------------------------------------------
# CONFIGURATION -- adjust these thresholds to match your policy
# ----------------------------------------------------------------
ACCESS_KEY_MAX_AGE_DAYS = 90
PASSWORD_MAX_AGE_DAYS = 90
INACTIVE_USER_DAYS = 90
HIGH_PRIVILEGE_ROLES = ["Administrator", "PowerUser"]

# ----------------------------------------------------------------
# SOC 2 CONTROL MAPPING
# ----------------------------------------------------------------
CONTROL_MAP = {
    "MFA_DISABLED": {
        "soc2_control": "CC6.1",
        "nist_control": "IA-2(1)",
        "description": "Multi-factor authentication is not enabled for console access"
    },
    "ACCESS_KEY_TOO_OLD": {
        "soc2_control": "CC6.1",
        "nist_control": "IA-5(1)",
        "description": "Access key has not been rotated in over 90 days"
    },
    "PASSWORD_NOT_ROTATED": {
        "soc2_control": "CC6.1",
        "nist_control": "IA-5(1)",
        "description": "Password has not been rotated in over 90 days"
    },
    "INACTIVE_USER": {
        "soc2_control": "CC6.2",
        "nist_control": "AC-2(3)",
        "description": "User has not logged in for over 90 days"
    },
    "PRIVILEGED_NO_MFA": {
        "soc2_control": "CC6.3",
        "nist_control": "AC-6(5)",
        "description": "User has elevated privileges (Admin/PowerUser) but MFA is not enabled"
    },
}


def load_local_csv(filepath):
    """Load IAM user data from a local CSV file (LOCAL MODE)."""
    print("[LOCAL MODE] Loading IAM data from: " + filepath)
    df = pd.read_csv(filepath)

    today = date.today()
    df["last_login_days"] = df["last_login"].apply(
        lambda x: (today - datetime.strptime(str(x), "%Y-%m-%d").date()).days
        if pd.notna(x) and str(x) != "NEVER" else 9999
    )
    return df


def load_live_aws():
    """Load IAM user data from AWS using boto3 (LIVE MODE)."""
    try:
        import boto3
    except ImportError:
        raise ImportError("boto3 is not installed. Run: pip install boto3")

    print("[LIVE MODE] Connecting to AWS IAM...")
    iam = boto3.client("iam")
    today = date.today()
    rows = []

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]

            mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
            mfa_enabled = len(mfa_devices) > 0

            try:
                iam.get_login_profile(UserName=username)
                console_access = True
            except Exception:
                console_access = False

            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
            key_age = 0
            for key in keys:
                age = (today - key["CreateDate"].date()).days
                key_age = max(key_age, age)

            last_login = user.get("PasswordLastUsed")
            if last_login:
                last_login_days = (today - last_login.date()).days
            else:
                last_login_days = 9999

            rows.append({
                "username": username,
                "department": "Unknown",
                "role": "Unknown",
                "mfa_enabled": mfa_enabled,
                "account_status": "ACTIVE",
                "access_level": "Unknown",
                "access_key_age_days": key_age,
                "password_last_rotated_days": 0,
                "last_login_days": last_login_days,
                "console_access": console_access,
                "programmatic_access": len(keys) > 0,
                "risk_level": "UNKNOWN",
            })

    return pd.DataFrame(rows)


def evaluate_user(row):
    """Run all SOC 2 checks against a single user. Returns a list of findings."""
    findings = []

    def add_finding(finding_type, severity):
        ctrl = CONTROL_MAP[finding_type]
        findings.append({
            "username":                  row["username"],
            "department":                row.get("department", ""),
            "role":                      row.get("role", ""),
            "account_status":            row.get("account_status", "ACTIVE"),
            "finding_type":              finding_type,
            "severity":                  severity,
            "soc2_control":              ctrl["soc2_control"],
            "nist_control":              ctrl["nist_control"],
            "finding_detail":            ctrl["description"],
            "access_key_age_days":       row.get("access_key_age_days", 0),
            "password_last_rotated_days": row.get("password_last_rotated_days", 0),
            "last_login_days":           row.get("last_login_days", 0),
            "mfa_enabled":               row.get("mfa_enabled", False),
            "access_level":              row.get("access_level", ""),
        })

    if str(row.get("account_status", "ACTIVE")).upper() != "ACTIVE":
        return findings

    # CC6.1 - MFA disabled
    if row.get("console_access") and not row.get("mfa_enabled"):
        add_finding("MFA_DISABLED", "CRITICAL")

    # CC6.1 - Access key too old
    if row.get("programmatic_access") and row.get("access_key_age_days", 0) > ACCESS_KEY_MAX_AGE_DAYS:
        severity = "CRITICAL" if row.get("access_key_age_days", 0) > 180 else "HIGH"
        add_finding("ACCESS_KEY_TOO_OLD", severity)

    # CC6.1 - Password not rotated
    if row.get("console_access") and row.get("password_last_rotated_days", 0) > PASSWORD_MAX_AGE_DAYS:
        add_finding("PASSWORD_NOT_ROTATED", "HIGH")

    # CC6.2 - Inactive user
    if row.get("last_login_days", 0) > INACTIVE_USER_DAYS:
        add_finding("INACTIVE_USER", "MEDIUM")

    # CC6.3 - Privileged user without MFA
    if row.get("access_level") in HIGH_PRIVILEGE_ROLES and not row.get("mfa_enabled"):
        add_finding("PRIVILEGED_NO_MFA", "CRITICAL")

    return findings


def run_iam_collector(mode="local", csv_path=None):
    """Main entry point. Returns a DataFrame of all findings."""
    if mode == "local":
        if not csv_path:
            raise ValueError("csv_path is required for local mode")
        df = load_local_csv(csv_path)
    else:
        df = load_live_aws()

    print("  Loaded " + str(len(df)) + " users.")

    all_findings = []
    for _, row in df.iterrows():
        all_findings.extend(evaluate_user(row))

    if not all_findings:
        print("  No findings. All users passed SOC 2 checks.")
        return pd.DataFrame()

    findings_df = pd.DataFrame(all_findings)
    print("  " + str(len(findings_df)) + " findings across " + str(findings_df["username"].nunique()) + " users.")
    return findings_df


def export_findings(findings_df, output_dir="output"):
    """Save findings to a dated CSV in the output directory."""
    os.makedirs(output_dir, exist_ok=True)
    today_str = datetime.today().strftime("%Y-%m-%d")
    filename = output_dir + "/iam_findings_" + today_str + ".csv"
    findings_df.to_csv(filename, index=False)
    print("  Findings saved to: " + filename)
    return filename


def print_summary(findings_df):
    """Print a human-readable summary to the terminal."""
    print("\n" + "=" * 60)
    print("  IAM EVIDENCE COLLECTION SUMMARY")
    print("=" * 60)
    print("  Total findings:  " + str(len(findings_df)))
    print("  Affected users:  " + str(findings_df["username"].nunique()))
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

    print("=" * 60)


# ----------------------------------------------------------------
# Run this script directly to test it
# ----------------------------------------------------------------
if __name__ == "__main__":
    CSV_PATH = "sample_data/medisphere_iam_users_100.csv"

    print("\nRunning IAM SOC 2 Evidence Collector...\n")

    findings = run_iam_collector(mode="local", csv_path=CSV_PATH)

    if findings is not None and not findings.empty:
        print_summary(findings)
        export_findings(findings, output_dir="output")
