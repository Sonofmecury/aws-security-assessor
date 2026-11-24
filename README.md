# AWS security posture assessor

Collect a scoped inventory, explain 15 posture checks across IAM, S3 and EC2, and confirm which failed controls close in a second snapshot. The assessment and remediation comparison run offline with Python 3.11+.

```sh
python assess.py fixtures/before.json --after fixtures/after.json
python -m unittest discover -v
```

## Read-only collection

Install `requirements-live.txt` in a virtual environment. Use an explicit AWS CLI profile with temporary credentials and run `python collect.py --profile lab-readonly --account ACCOUNT_ID --region REGION`. It checks caller identity before reading inventory. Keep the output in private storage and export only redacted evidence. The documented read permissions are in `iam-read-policy.json`.

Read scope is one region, plus the account’s global IAM settings and customer-managed policy default versions. API denial is incomplete coverage. Individual S3 properties that cannot be obtained stay absent and score unknown. A collected empty inventory scores not applicable. No cloud configuration is applied by this tool.

## Remediation case study

The fictional baseline contains 15 observed failures. The second fixture removes all 15. Compare each resource with an identical account/region scope and a stable resource ID. Replacing or omitting a resource does not prove remediation. For real assessments, record the approved change and repeat the same collection. Use private subnets or configuration fixtures when demonstrating network checks.

The network checks report broad security group rules, not end-to-end reachability. The public-IPv4 finding is an exposure indicator, not a verdict. Bucket flags cover bucket settings only and may be reinforced by account-level settings. Wildcard matching reports a static policy property and does not calculate effective or unused permissions. The tool does not claim full CIS coverage.
