import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_DIR))

from llm_explainer_v5_1 import validate_llm_output


class TestLLMValidatorV51(unittest.TestCase):

    def setUp(self):
        self.evidence = {
            "unique_source_ip_count": 14,
            "unique_username_count": 5,
            "total_authentication_events_represented": 50,
            "successful_authentication_events_represented": 50,
            "failed_authentication_events_represented": 0,
        }

    def test_correct_numerical_claims_pass(self):
        llm_output = """
        Unique source IP addresses: 14
        Unique usernames: 5
        Total authentication events represented: 50
        Successful authentication events represented: 50
        Failed authentication events represented: 0
        """

        results = validate_llm_output(
            self.evidence,
            llm_output,
        )

        for result in results:
            self.assertEqual(
                result["status"],
                "PASS",
            )

    def test_ip_octet_not_mistaken_for_username_count(self):
        llm_output = """
        Unique source IP addresses: 14
        137.189.241.248
        Usernames:
        Unique usernames: 5
        """

        results = validate_llm_output(
            self.evidence,
            llm_output,
        )

        username_result = next(
            result
            for result in results
            if result["name"] == "Username count"
        )

        self.assertEqual(
            username_result["claimed"],
            5,
        )

        self.assertEqual(
            username_result["status"],
            "PASS",
        )

    def test_incorrect_username_count_fails(self):
        llm_output = """
        Unique usernames: 10
        """

        results = validate_llm_output(
            self.evidence,
            llm_output,
        )

        username_result = next(
            result
            for result in results
            if result["name"] == "Username count"
        )

        self.assertEqual(
            username_result["claimed"],
            10,
        )

        self.assertEqual(
            username_result["status"],
            "FAIL",
        )


if __name__ == "__main__":
    unittest.main()