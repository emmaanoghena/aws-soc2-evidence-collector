"""
Control Mapper - SOC 2 Evidence Collector
==========================================
Combines findings from all four collectors into a single
dated evidence report with a summary dashboard tab.

Output: Excel workbook with two sheets
  1. All_Findings  - every finding from all four collectors
  2. Dashboard     - summary counts by control, severity, and source

SOC 2 Controls covered across all collectors:
  CC6.1 - Logical access controls
  CC6.6 - Threat and vulnerability management
  CC6.7 - Encryption of data at rest
  CC7.1 - Vulnerability detection
  CC7.2 - System monitoring
  A1.2  - Data availability and recovery
"""

import pandas as pd
from datetime import datetime
import os
import glob

# ----------------------------------------------------------------
# Column names we want in the final unified report.
# Each collector uses slightly different column names so we
# normalize everything to these standard names here.
# ----------------------------------------------------------------
STANDARD_COLUMNS = [
    "evidence_date",
    "source",
    "resource_id",
    "resource_type",
    "finding_type",
    "severity",
    "soc2_control",
    "nist_control",
    "finding_detail",
]

# Human-readable labels for each SOC 2 control
CONTROL_DESCRIPTIONS = {
    "CC6.1": "Logical Access Controls",
    "CC6.6": "Threat and Vulnerability Management",
    "CC6.7": "Encryption and Data Protection",
    "CC7.1": "Vulnerability Detection",
    "CC7.2": "System Monitoring and Alerting",
    "A1.2":  "Data Availability and Recovery",
}


def load_latest_csv(output_dir, prefix):
    """
    Find and load the most recent CSV for a given collector prefix.
    Example: prefix="iam_findings" loads the latest iam_findings_*.csv
    """
    pattern = os.path.join(output_dir, prefix + "_*.csv")
    files = sorted(glob.glob(pattern), reverse=True)

    if not files:
        print("  [SKIP] No file found matching: " + pattern)
        return None

    latest = files[0]
    print("  [LOAD] " + os.path.basename(latest))
    return pd.read_csv(latest)


def normalize_iam(df):
    """Normalize IAM findings to standard columns."""
    out = pd.DataFrame()
    out["resource_id"]    = df["username"]
    out["resource_type"]  = "IAM User"
    out["finding_type"]   = df["finding_type"]
    out["severity"]       = df["severity"]
    out["soc2_control"]   = df["soc2_control"]
    out["nist_control"]   = df["nist_control"]
    out["finding_detail"] = df["finding_detail"]
    out["source"]         = "IAM Collector"
    return out


def normalize_cloudtrail(df):
    """Normalize CloudTrail findings to standard columns."""
    out = pd.DataFrame()
    out["resource_id"]    = df["trail_name"]
    out["resource_type"]  = "CloudTrail Trail"
    out["finding_type"]   = df["finding_type"]
    out["severity"]       = df["severity"]
    out["soc2_control"]   = df["soc2_control"]
    out["nist_control"]   = df["nist_control"]
    out["finding_detail"] = df["finding_detail"]
    out["source"]         = "CloudTrail Checker"
    return out


def normalize_s3(df):
    """Normalize S3 findings to standard columns."""
    out = pd.DataFrame()
    out["resource_id"]    = df["bucket_name"]
    out["resource_type"]  = "S3 Bucket"
    out["finding_type"]   = df["finding_type"]
    out["severity"]       = df["severity"]
    out["soc2_control"]   = df["soc2_control"]
    out["nist_control"]   = df["nist_control"]
    out["finding_detail"] = df["finding_detail"]
    out["source"]         = "S3 Config Checker"
    return out


def normalize_securityhub(df):
    """Normalize Security Hub findings to standard columns."""
    out = pd.DataFrame()
    out["resource_id"]    = df["resource_id"]
    out["resource_type"]  = df["resource_type"]
    out["finding_type"]   = df["title"]
    out["severity"]       = df["severity"]
    out["soc2_control"]   = df["soc2_control"]
    out["nist_control"]   = df["nist_control"]
    out["finding_detail"] = df["control_rationale"]
    out["source"]         = "Security Hub"
    return out


def build_dashboard(findings_df):
    """
    Build a summary dashboard DataFrame from the combined findings.
    Returns a list of (label, dataframe) tuples — one per dashboard section.
    """
    today_str = datetime.today().strftime("%Y-%m-%d")

    # Section 1: Overall totals
    totals = pd.DataFrame([
        {"Metric": "Evidence Collection Date", "Value": today_str},
        {"Metric": "Total Findings",           "Value": len(findings_df)},
        {"Metric": "CRITICAL Findings",        "Value": len(findings_df[findings_df["severity"] == "CRITICAL"])},
        {"Metric": "HIGH Findings",            "Value": len(findings_df[findings_df["severity"] == "HIGH"])},
        {"Metric": "MEDIUM Findings",          "Value": len(findings_df[findings_df["severity"] == "MEDIUM"])},
        {"Metric": "LOW Findings",             "Value": len(findings_df[findings_df["severity"] == "LOW"])},
        {"Metric": "Unique Resources Affected","Value": findings_df["resource_id"].nunique()},
    ])

    # Section 2: Findings by SOC 2 control
    by_control = (
        findings_df.groupby("soc2_control")
        .size()
        .reset_index(name="Finding Count")
        .rename(columns={"soc2_control": "SOC 2 Control"})
    )
    by_control["Control Description"] = by_control["SOC 2 Control"].map(CONTROL_DESCRIPTIONS)
    by_control = by_control[["SOC 2 Control", "Control Description", "Finding Count"]]
    by_control = by_control.sort_values("Finding Count", ascending=False)

    # Section 3: Findings by source (which collector)
    by_source = (
        findings_df.groupby("source")
        .agg(
            Total=("severity", "count"),
            Critical=("severity", lambda x: (x == "CRITICAL").sum()),
            High=("severity", lambda x: (x == "HIGH").sum()),
            Medium=("severity", lambda x: (x == "MEDIUM").sum()),
        )
        .reset_index()
        .rename(columns={"source": "Collector"})
    )

    # Section 4: Top 10 most critical findings
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    top_findings = findings_df.copy()
    top_findings["sev_rank"] = top_findings["severity"].map(severity_order)
    top_findings = (
        top_findings.sort_values("sev_rank")
        .head(10)
        [["severity", "source", "resource_id", "soc2_control", "finding_type"]]
        .rename(columns={
            "severity":     "Severity",
            "source":       "Collector",
            "resource_id":  "Resource",
            "soc2_control": "SOC 2 Control",
            "finding_type": "Finding",
        })
    )

    return [
        ("Overall Summary",        totals),
        ("By SOC 2 Control",       by_control),
        ("By Collector",           by_source),
        ("Top 10 Critical Findings", top_findings),
    ]


def export_excel(findings_df, dashboard_sections, output_dir="output"):
    """
    Write the final evidence report as an Excel workbook with two sheets:
      - All_Findings: the full normalized findings table
      - Dashboard:    the summary sections stacked vertically
    """
    os.makedirs(output_dir, exist_ok=True)
    today_str = datetime.today().strftime("%Y-%m-%d")
    filename = os.path.join(output_dir, "soc2_evidence_report_" + today_str + ".xlsx")

    with pd.ExcelWriter(filename, engine="openpyxl") as writer:

        # Sheet 1: All findings
        findings_df.to_excel(writer, sheet_name="All_Findings", index=False)

        # Sheet 2: Dashboard — stack each section with a blank row between them
        dashboard_rows = []
        for section_title, section_df in dashboard_sections:
            # Section header row
            header_df = pd.DataFrame([[section_title] + [""] * (len(section_df.columns) - 1)],
                                      columns=section_df.columns)
            dashboard_rows.append(header_df)
            dashboard_rows.append(section_df)
            # Blank spacer row
            spacer = pd.DataFrame([[""] * len(section_df.columns)], columns=section_df.columns)
            dashboard_rows.append(spacer)

        dashboard_combined = pd.concat(dashboard_rows, ignore_index=True)
        dashboard_combined.to_excel(writer, sheet_name="Dashboard", index=False)

    print("  Report saved to: " + filename)
    return filename


def run_control_mapper(output_dir="output"):
    """
    Main entry point. Loads all collector CSVs, normalizes them,
    combines into one DataFrame, builds the dashboard, and exports Excel.
    """
    print("Loading collector outputs from: " + output_dir + "/\n")

    # Load each collector's latest CSV
    iam_df  = load_latest_csv(output_dir, "iam_findings")
    ct_df   = load_latest_csv(output_dir, "cloudtrail_findings")
    s3_df   = load_latest_csv(output_dir, "s3_findings")
    sh_df   = load_latest_csv(output_dir, "securityhub_findings")

    # Normalize and combine only the ones that loaded successfully
    frames = []
    if iam_df is not None and not iam_df.empty:
        frames.append(normalize_iam(iam_df))
    if ct_df is not None and not ct_df.empty:
        frames.append(normalize_cloudtrail(ct_df))
    if s3_df is not None and not s3_df.empty:
        frames.append(normalize_s3(s3_df))
    if sh_df is not None and not sh_df.empty:
        frames.append(normalize_securityhub(sh_df))

    if not frames:
        print("\nNo collector outputs found. Run the collectors first.")
        return

    combined = pd.concat(frames, ignore_index=True)
    combined["evidence_date"] = datetime.today().strftime("%Y-%m-%d")
    combined = combined[STANDARD_COLUMNS]

    print("\nCombined: " + str(len(combined)) + " total findings across all collectors.")

    # Build dashboard
    dashboard_sections = build_dashboard(combined)

    # Export
    print("\nExporting Excel evidence report...")
    export_excel(combined, dashboard_sections, output_dir=output_dir)


def print_summary(output_dir="output"):
    """Quick terminal preview of what was combined."""
    pattern = os.path.join(output_dir, "soc2_evidence_report_*.xlsx")
    files = sorted(glob.glob(pattern), reverse=True)
    if not files:
        return

    print("\n" + "=" * 60)
    print("  SOC 2 EVIDENCE REPORT SUMMARY")
    print("=" * 60)

    # Reload the All_Findings sheet for the summary
    df = pd.read_excel(files[0], sheet_name="All_Findings")
    print("  Total findings:          " + str(len(df)))
    print("  Unique resources:        " + str(df["resource_id"].nunique()))
    print()

    print("  By Severity:")
    for sev, count in df["severity"].value_counts().items():
        icon = {"CRITICAL": "[CRITICAL]", "HIGH": "[HIGH]", "MEDIUM": "[MEDIUM]", "LOW": "[LOW]"}.get(sev, "")
        print("    " + icon + " " + sev + ": " + str(count))

    print()
    print("  By SOC 2 Control:")
    for ctrl, count in df["soc2_control"].value_counts().items():
        label = CONTROL_DESCRIPTIONS.get(ctrl, "")
        print("    " + ctrl + " " + label + ": " + str(count))

    print()
    print("  By Collector:")
    for src, count in df["source"].value_counts().items():
        print("    " + src + ": " + str(count))

    print("=" * 60)


# ----------------------------------------------------------------
# Run this script directly to test it
# ----------------------------------------------------------------
if __name__ == "__main__":
    print("\nRunning SOC 2 Control Mapper...\n")
    run_control_mapper(output_dir="output")
    print_summary(output_dir="output")
