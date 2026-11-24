import unittest
try:
    import boto3
    from botocore.stub import Stubber
except ImportError:
    boto3 = None

from assess import assess
from collect import collect

ACCOUNT = "000000000000"
REGION = "us-east-1"


@unittest.skipIf(boto3 is None, "Optional live collector dependencies are not installed")
class CollectorTest(unittest.TestCase):
    def setUp(self):
        session = boto3.Session(aws_access_key_id="fixture",
                                aws_secret_access_key="fictional-credentials",
                                region_name=REGION)
        self.clients = {key: session.client(key) for key in ("sts", "iam", "ec2", "s3")}
        self.stubs = {key: Stubber(client) for key, client in self.clients.items()}
        for stub in self.stubs.values():
            stub.activate()
            self.addCleanup(stub.deactivate)

        class FixtureSession:
            def client(_, service, **kwargs):
                return self.clients[service]

        self.session = FixtureSession()

    def identity(self, account=ACCOUNT):
        self.stubs["sts"].add_response("get_caller_identity", {
            "Account": account, "UserId": "fixture-user", "Arn": f"arn:aws:iam::{account}:user/fixture"
        }, {})

    def test_wrong_account_stops_before_inventory_collection(self):
        self.identity("111111111111")
        with self.assertRaisesRegex(ValueError, "do not match"):
            collect(self.session, ACCOUNT, REGION)
        self.stubs["sts"].assert_no_pending_responses()

    def test_api_contract_denial_and_bucket_partial_evidence(self):
        self.identity()
        self.stubs["iam"].add_response("get_account_summary", {
            "SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}}, {})
        self.stubs["iam"].add_response("list_policies", {"Policies": []}, {"Scope": "Local"})
        self.stubs["ec2"].add_client_error("describe_security_groups", "UnauthorizedOperation", expected_params={})
        self.stubs["ec2"].add_response("describe_instances", {"Reservations": []}, {})
        self.stubs["ec2"].add_response("describe_volumes", {"Volumes": []}, {})
        name = "fictional-lab-bucket"
        self.stubs["s3"].add_response("list_buckets", {"Buckets": [{"Name": name}]}, {"BucketRegion": REGION})
        bucket = {"Bucket": name, "ExpectedBucketOwner": ACCOUNT}
        self.stubs["s3"].add_client_error("get_bucket_policy_status", "AccessDenied", expected_params=bucket)
        self.stubs["s3"].add_client_error("get_public_access_block", "NoSuchPublicAccessBlockConfiguration",
                                         expected_params=bucket)
        self.stubs["s3"].add_response("get_bucket_versioning", {"Status": "Enabled"}, bucket)
        inventory = collect(self.session, ACCOUNT, REGION)
        results = {row["check"]: row for row in assess(inventory)}
        self.assertEqual(results["NET-01"]["status"], "unknown")
        self.assertEqual(results["NET-01"]["evidence"], "UnauthorizedOperation")
        self.assertEqual(results["S3-01"]["status"], "unknown")
        self.assertEqual(results["S3-02"]["status"], "fail")
        self.assertEqual(results["S3-06"]["status"], "pass")
        self.assertEqual(results["EBS-01"]["status"], "not_applicable")
        for stub in self.stubs.values():
            stub.assert_no_pending_responses()
