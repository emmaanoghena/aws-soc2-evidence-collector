# AWS SOC 2 Evidence Collector

Automatically collects and formats SOC 2 evidence from an AWS account — IAM, CloudTrail, S3, and Security Hub — and maps findings to SOC 2 CC6.x controls and NIST 800-53 IDs.

## What It Does

| Step | Script | What It Checks |
|------|--------|----------------|
| 1 | `collectors/iam_collector.py` | MFA, access key age, password rotation, inactive users |
| 2 | `collectors/cloudtrail_checker.py` | Logging enabled, multi-region, log validation, KMS encryption |
| 3 | `collectors/s3_config_checker.py` | Public access, encryption, versioning |
| 4 | `collectors/securityhub_collector.py` | HIGH/CRITICAL findings from AWS Security Hub |
| 5 | `mapper/control_mapper.py` | Maps all findings to SOC 2 + NIST controls, exports Excel |

Run everything with one command:
```
python run_all.py
```

## SOC 2 Controls Covered

| Control | Description |
|---------|-------------|
| CC6.1 | Logical Access Controls |
| CC6.3 | Privileged Access Management |
| CC6.6 | Threat and Vulnerability Management |
| CC6.7 | Encryption and Data Protection |
| CC7.1 | Vulnerability Detection |
| CC7.2 | System Monitoring and Alerting |
| A1.2  | Data Availability and Recovery |

## Output

The tool generates a dated Excel workbook in `output/` with two sheets:
- **All_Findings** — every finding normalized across all four collectors
- **Dashboard** — summary by severity, SOC 2 control, and collector

## Project Structure

```
aws-soc2-evidence-collector/
├── run_all.py                        # Master runner
├── collectors/
│   ├── iam_collector.py
│   ├── cloudtrail_checker.py
│   ├── s3_config_checker.py
│   └── securityhub_collector.py
├── mapper/
│   └── control_mapper.py
├── sample_data/
│   └── medisphere_iam_users_100.csv  # Sample IAM dataset
└── output/                           # Generated reports (git ignored)
```

## Setup

### Prerequisites
- Python 3.10+
- AWS CLI (for live mode)

### Install dependencies
```
pip install boto3 pandas openpyxl
```

### Run in local mode (no AWS account needed)
```
python run_all.py
```

### Run in live mode (real AWS account)
1. Configure AWS credentials:
```
aws configure
```
2. Open `run_all.py` and change:
```python
MODE = "live"
```
3. Run:
```
python run_all.py
```

## Sample Data

`sample_data/medisphere_iam_users_100.csv` contains 100 simulated IAM users for a fictional healthcare company. It mirrors the structure of a real AWS IAM credential report and is used to demonstrate the tool without requiring AWS access.

## Tools Used

- Python + boto3
- AWS IAM, CloudTrail, S3, Security Hub
- pandas / openpyxl for CSV and Excel output
