import json
from pathlib import Path
import unittest

from assess import CHECKS, assess, remediation


def fixture(name):
    return json.loads((Path(__file__).parent / "fixtures" / (name + ".json")).read_text())


class PostureTest(unittest.TestCase):
    def test_every_check_with_pass_fail_and_uncollected(self):
        bad, good, unknown = [assess(data) for data in (fixture("before"), fixture("after"), {})]
        self.assertEqual({r["check"] for r in bad if r["status"] == "fail"}, set(CHECKS))
        self.assertEqual({r["check"] for r in good if r["status"] == "pass"}, set(CHECKS))
        self.assertEqual({r["check"] for r in unknown if r["status"] == "unknown"}, set(CHECKS))

    def test_change_is_verified_with_matching_evidence(self):
        result = remediation(fixture("before"), fixture("after"))
        self.assertEqual(len(result), 15)
        self.assertTrue(all(row["verified_closed"] for row in result))

    def test_missing_and_replaced_resources_are_not_passes(self):
        before, after = fixture("before"), fixture("after")
        after["buckets"][0]["id"] = "unrelated-bucket"
        after["volumes"] = []
        result = remediation(before, after)
        self.assertTrue(all(not row["verified_closed"] for row in result
                            if row["check"].startswith("S3") or row["check"] == "EBS-01"))

    def test_scope_cannot_change(self):
        before, after = fixture("before"), fixture("after")
        after["scope"]["region"] = "us-west-2"
        with self.assertRaises(ValueError):
            remediation(before, after)

    def test_bucket_missing_a_setting_is_unknown(self):
        snap = fixture("after")
        del snap["buckets"][0]["BlockPublicAcls"]
        results = {r["check"]: r["status"] for r in assess(snap)}
        self.assertEqual(results["S3-02"], "unknown")
        self.assertEqual(results["S3-03"], "pass")
