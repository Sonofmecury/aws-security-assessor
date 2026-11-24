"""Assess selected AWS inventory controls and compare remediation snapshots."""
import argparse
import ipaddress
import json
from pathlib import Path


def public_ingress(resource, low, high):
    for rule in resource["IpPermissions"]:
        protocol = rule["IpProtocol"]
        if protocol not in ("-1", "tcp", "6"):
            continue
        if protocol != "-1" and not (rule["FromPort"] <= high and rule["ToPort"] >= low):
            continue
        for family, key in (("IpRanges", "CidrIp"), ("Ipv6Ranges", "CidrIpv6")):
            if any(ipaddress.ip_network(entry[key]).prefixlen == 0
                   for entry in rule.get(family, [])):
                return True
    return False


def broad_policy(resource):
    statements = resource["PolicyDocument"]["Statement"]
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])
        if statement.get("Effect") == "Allow" and ("*" in actions if isinstance(actions, list) else actions == "*") and (
                "*" in resources if isinstance(resources, list) else resources == "*"):
            return True
    return False


# Each predicate tests a single observed property. A match is a review finding.
CHECKS = {
    "IAM-01": ("account", "Root MFA is not enabled", lambda r: r["AccountMFAEnabled"] != 1),
    "IAM-02": ("account", "Root access keys exist", lambda r: r["AccountAccessKeysPresent"] > 0),
    "IAM-03": ("iam_policies", "Policy contains Allow * on *", broad_policy),
    "S3-01": ("buckets", "Policy status reports public", lambda r: r["IsPublic"]),
    "S3-02": ("buckets", "Bucket public ACL block disabled", lambda r: not r["BlockPublicAcls"]),
    "S3-03": ("buckets", "Bucket public ACL ignore disabled", lambda r: not r["IgnorePublicAcls"]),
    "S3-04": ("buckets", "Bucket public policy block disabled", lambda r: not r["BlockPublicPolicy"]),
    "S3-05": ("buckets", "Bucket public policy restriction disabled", lambda r: not r["RestrictPublicBuckets"]),
    "S3-06": ("buckets", "Bucket versioning not enabled", lambda r: r["Versioning"] != "Enabled"),
    "NET-01": ("groups", "Security group permits global SSH", lambda r: public_ingress(r, 22, 22)),
    "NET-02": ("groups", "Security group permits global RDP", lambda r: public_ingress(r, 3389, 3389)),
    "NET-03": ("groups", "Security group permits global SMB", lambda r: public_ingress(r, 445, 445)),
    "EC2-01": ("instances", "Instance allows IMDSv1", lambda r: r["MetadataOptions"]["HttpEndpoint"] == "enabled"
               and r["MetadataOptions"]["HttpTokens"] != "required"),
    "EBS-01": ("volumes", "Volume is unencrypted", lambda r: not r["Encrypted"]),
    "EC2-02": ("instances", "Instance has a public IPv4 address", lambda r: bool(r.get("PublicIpAddress"))),
}


def assess(inventory):
    results = []
    coverage = inventory.get("coverage", {})
    for check, (section, title, predicate) in CHECKS.items():
        resources = inventory.get(section)
        if not isinstance(resources, list):
            results.append({"check": check, "title": title, "resource": None, "status": "unknown",
                            "evidence": coverage.get(section, "Section not collected")})
            continue
        if not resources:
            results.append({"check": check, "title": title, "resource": None,
                            "status": "not_applicable", "evidence": "No resources in scope"})
        for resource in resources:
            identifier = resource.get("id") if isinstance(resource, dict) else None
            try:
                if not isinstance(identifier, str) or not identifier:
                    raise ValueError("Missing resource identifier")
                status = "fail" if predicate(resource) else "pass"
                evidence = title if status == "fail" else "Observed setting meets check"
            except (KeyError, TypeError, ValueError) as error:
                status, evidence = "unknown", f"Evidence incomplete: {error}"
            results.append({"check": check, "title": title, "resource": identifier,
                            "status": status, "evidence": evidence})
    return results


def remediation(before, after):
    if before.get("scope") != after.get("scope") or not before.get("scope"):
        raise ValueError("Remediation comparison requires identical known account/region scope")
    newer = {(row["check"], row["resource"]): row["status"] for row in assess(after)}
    return [{**row, "after": newer.get((row["check"], row["resource"]), "unknown"),
             "verified_closed": newer.get((row["check"], row["resource"])) == "pass"}
            for row in assess(before) if row["status"] == "fail"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path)
    parser.add_argument("--after", type=Path)
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_text(encoding="utf-8-sig"))
    result = remediation(inventory, json.loads(args.after.read_text(encoding="utf-8-sig"))) if args.after else assess(inventory)
    print(json.dumps({"scope": inventory.get("scope"), "results": result}, indent=2))


if __name__ == "__main__":
    main()
