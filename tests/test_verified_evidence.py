import unittest

import pandas as pd

from src.llm_explainer_v4_1 import build_verified_evidence


class TestVerifiedEvidence(unittest.TestCase):

    def setUp(self):
        """
        Create a small controlled dataset.

        The dataset contains:
        - 2 ordinary failed authentication records
        - 1 compressed record representing 5 failed events

        Therefore:
        - CSV records = 3
        - Represented authentication events = 7
        """

        self.logs = pd.DataFrame(
            {
                "Raw_Log": [
                    (
                        "Jan  3 10:07:06 LabSZ sshd[27130]: "
                        "Failed password for root from 59.63.188.30 "
                        "port 11972 ssh2"
                    ),
                    (
                        "Jan  3 10:07:10 LabSZ sshd[27130]: "
                        "Failed password for root from 59.63.188.30 "
                        "port 11973 ssh2"
                    ),
                    (
                        "Jan  3 10:07:20 LabSZ sshd[27130]: "
                        "message repeated 5 times: [ Failed password "
                        "for root from 59.63.188.30 port 11974 ssh2]"
                    ),
                ],
                "Authentication_Result": [
                    "FAILURE",
                    "FAILURE",
                    "FAILURE",
                ],
                "Source_IP": [
                    "59.63.188.30",
                    "59.63.188.30",
                    "59.63.188.30",
                ],
                "Username": [
                    "root",
                    "root",
                    "root",
                ],
                "Timestamp": [
                    "Jan 03 10:07:06",
                    "Jan 03 10:07:10",
                    "Jan 03 10:07:20",
                ],
                "Source_Port": [
                    11972,
                    11973,
                    11974,
                ],
                "Authentication_Method": [
                    "password",
                    "password",
                    "password",
                ],
            }
        )

        self.evidence = build_verified_evidence(self.logs)

    def test_csv_record_count(self):
        """The controlled dataset should contain three CSV records."""
        self.assertEqual(
            self.evidence["total_csv_records"],
            3
        )

    def test_ordinary_and_compressed_records(self):
        """Python should distinguish ordinary and compressed records."""
        self.assertEqual(
            self.evidence["ordinary_authentication_records"],
            2
        )

        self.assertEqual(
            self.evidence["compressed_repeat_records"],
            1
        )

    def test_represented_event_count(self):
        """
        Two ordinary records plus one record repeated five times
        should represent seven authentication events.
        """
        self.assertEqual(
            self.evidence["ordinary_events_represented"],
            2
        )

        self.assertEqual(
            self.evidence["repeated_events_represented"],
            5
        )

        self.assertEqual(
            self.evidence["total_authentication_events_represented"],
            7
        )

    def test_failed_authentication_counts(self):
        """All represented authentication events should be failures."""
        self.assertEqual(
            self.evidence["failed_csv_records"],
            3
        )

        self.assertEqual(
            self.evidence["successful_csv_records"],
            0
        )

        self.assertEqual(
            self.evidence[
                "failed_authentication_events_represented"
            ],
            7
        )

        self.assertEqual(
            self.evidence[
                "successful_authentication_events_represented"
            ],
            0
        )

    def test_source_information(self):
        """The verified evidence should preserve source information."""
        self.assertEqual(
            self.evidence["source_ip_addresses"],
            ["59.63.188.30"]
        )

        self.assertEqual(
            self.evidence["usernames"],
            ["root"]
        )

        self.assertEqual(
            self.evidence["authentication_methods"],
            ["password"]
        )

    def test_timeline(self):
        """The timeline should be calculated from the supplied records."""
        self.assertEqual(
            self.evidence["first_record"],
            "Jan 03 10:07:06"
        )

        self.assertEqual(
            self.evidence["last_record"],
            "Jan 03 10:07:20"
        )

        self.assertEqual(
            self.evidence["observed_time_span"],
            "0 minutes 14 seconds"
        )


if __name__ == "__main__":
    unittest.main()