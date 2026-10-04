import unittest

from src.llm_explainer_v4_1 import get_repeat_count


class TestRepeatCount(unittest.TestCase):

    def test_normal_authentication_record(self):
        """A normal authentication log record should represent one event."""
        log = (
            "Jan  3 10:07:06 LabSZ sshd[27130]: "
            "Failed password for root from 59.63.188.30 "
            "port 11972 ssh2"
        )

        result = get_repeat_count(log)

        self.assertEqual(result, 1)

    def test_repeated_authentication_record(self):
        """A compressed syslog record should use its recorded repeat count."""
        log = (
            "Jan  3 10:07:20 LabSZ sshd[27130]: "
            "message repeated 5 times: [ Failed password for root "
            "from 59.63.188.30 port 11972 ssh2]"
        )

        result = get_repeat_count(log)

        self.assertEqual(result, 5)

    def test_different_repeat_count(self):
        """The function should not be hard-coded specifically to five."""
        log = (
            "Jan  3 10:07:20 LabSZ sshd[27130]: "
            "message repeated 8 times: [ Failed password for root "
            "from 59.63.188.30 port 11972 ssh2]"
        )

        result = get_repeat_count(log)

        self.assertEqual(result, 8)


if __name__ == "__main__":
    unittest.main()