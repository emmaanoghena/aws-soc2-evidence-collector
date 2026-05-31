"""
run_all.py - SOC 2 Evidence Collector Master Runner
=====================================================
Runs all four collectors then the control mapper in sequence.
Produces a single dated Excel evidence report in output/

Usage:
    python run_all.py
"""

import sys
import os
from datetime import datetime

# Add project root to path so collectors and mapper can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from collectors.iam_collector        import run_iam_collector, export_findings as export_iam
from collectors.cloudtrail_checker   import run_cloudtrail_checker, export_findings as export_ct
from collectors.s3_config_checker    import run_s3_checker, export_findings as export_s3
from collectors.securityhub_collector import run_securityhub_collector, export_findings as export_sh
from mapper.control_mapper           import run_control_mapper, print_summary

# ----------------------------------------------------------------
# CONFIGURATION
# Change mode to "live" when you have real AWS credentials set up
# ----------------------------------------------------------------
MODE       = "local"
OUTPUT_DIR = "output"
CSV_PATH   = "sample_data/medisphere_iam_users_100.csv"

DIVIDER = "=" * 60


def section(title):
    print("\n" + DIVIDER)
    print("  " + title)
    print(DIVIDER)


def run():
    start = datetime.now()
    print("\n" + DIVIDER)
    print("  AWS SOC 2 EVIDENCE COLLECTOR")
    print("  Started: " + start.strftime("%Y-%m-%d %H:%M:%S"))
    print("  Mode:    " + MODE.upper())
    print(DIVIDER)

    errors = []

    # ── Step 1: IAM ──────────────────────────────────────────────
    section("Step 1 of 5: IAM Collector")
    try:
        findings = run_iam_collector(mode=MODE, csv_path=CSV_PATH)
        if findings is not None and not findings.empty:
            export_iam(findings, output_dir=OUTPUT_DIR)
        else:
            print("  No IAM findings.")
    except Exception as e:
        print("  ERROR: " + str(e))
        errors.append("IAM Collector: " + str(e))

    # ── Step 2: CloudTrail ───────────────────────────────────────
    section("Step 2 of 5: CloudTrail Checker")
    try:
        findings = run_cloudtrail_checker(mode=MODE)
        if findings is not None and not findings.empty:
            export_ct(findings, output_dir=OUTPUT_DIR)
        else:
            print("  No CloudTrail findings.")
    except Exception as e:
        print("  ERROR: " + str(e))
        errors.append("CloudTrail Checker: " + str(e))

    # ── Step 3: S3 ───────────────────────────────────────────────
    section("Step 3 of 5: S3 Config Checker")
    try:
        findings = run_s3_checker(mode=MODE)
        if findings is not None and not findings.empty:
            export_s3(findings, output_dir=OUTPUT_DIR)
        else:
            print("  No S3 findings.")
    except Exception as e:
        print("  ERROR: " + str(e))
        errors.append("S3 Config Checker: " + str(e))

    # ── Step 4: Security Hub ─────────────────────────────────────
    section("Step 4 of 5: Security Hub Collector")
    try:
        findings = run_securityhub_collector(mode=MODE)
        if findings is not None and not findings.empty:
            export_sh(findings, output_dir=OUTPUT_DIR)
        else:
            print("  No Security Hub findings.")
    except Exception as e:
        print("  ERROR: " + str(e))
        errors.append("Security Hub Collector: " + str(e))

    # ── Step 5: Control Mapper ───────────────────────────────────
    section("Step 5 of 5: Control Mapper")
    try:
        run_control_mapper(output_dir=OUTPUT_DIR)
        print_summary(output_dir=OUTPUT_DIR)
    except Exception as e:
        print("  ERROR: " + str(e))
        errors.append("Control Mapper: " + str(e))

    # ── Final status ─────────────────────────────────────────────
    elapsed = (datetime.now() - start).seconds
    print("\n" + DIVIDER)
    if errors:
        print("  COMPLETED WITH ERRORS (" + str(elapsed) + "s)")
        for err in errors:
            print("  - " + err)
    else:
        print("  ALL STEPS COMPLETED SUCCESSFULLY (" + str(elapsed) + "s)")
        print("  Evidence report saved to: " + OUTPUT_DIR + "/")
    print(DIVIDER + "\n")


if __name__ == "__main__":
    run()
