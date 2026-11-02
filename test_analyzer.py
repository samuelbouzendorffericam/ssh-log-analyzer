import unittest
from datetime import datetime, timedelta
from pathlib import Path

import analyzer

SAMPLE = Path(__file__).parent / "sample_auth.log"
YEAR = 2026


class TestParsing(unittest.TestCase):
    def test_failed_line(self):
        e = analyzer.parse_line(
            "Oct 12 03:12:07 srv-demo sshd[3101]: Failed password for invalid user admin from 203.0.113.45 port 40122 ssh2",
            YEAR)
        self.assertEqual((e.kind, e.user, e.ip), ("failed", "admin", "203.0.113.45"))
        self.assertEqual(e.when, datetime(2026, 10, 12, 3, 12, 7))

    def test_accepted_line_with_padded_day(self):
        e = analyzer.parse_line(
            "Oct  2 08:02:11 srv-demo sshd[3402]: Accepted publickey for alice from 192.0.2.10 port 51234 ssh2", YEAR)
        self.assertEqual((e.kind, e.user, e.ip), ("accepted", "alice", "192.0.2.10"))

    def test_unrelated_lines_are_ignored(self):
        self.assertIsNone(analyzer.parse_line(
            "Oct 12 02:00:01 srv-demo CRON[2210]: pam_unix(cron:session): session opened", YEAR))
        self.assertIsNone(analyzer.parse_line("n'importe quoi", YEAR))


class TestDetection(unittest.TestCase):
    def test_sliding_window(self):
        base = datetime(2026, 1, 1)
        times = [base + timedelta(seconds=s) for s in (0, 10, 20, 200, 205)]
        self.assertEqual(analyzer.max_failures_in_window(times, timedelta(seconds=60)), 3)

    def test_sample_log(self):
        with open(SAMPLE, encoding="utf-8") as f:
            events = analyzer.parse_lines(f, YEAR)
        report = analyzer.analyze(events, threshold=5, window_seconds=60)
        flagged = report["brute_force_ips"]
        self.assertIn("203.0.113.45", flagged)       # rafale de 14 échecs
        self.assertIn("198.51.100.23", flagged)      # rafale de 7 échecs
        self.assertNotIn("192.0.2.25", flagged)      # simples fautes de frappe
        self.assertNotIn("203.0.113.99", flagged)    # échecs étalés sur la journée
        critical = report["success_after_failures"]
        self.assertEqual([a["ip"] for a in critical], ["198.51.100.23"])
        self.assertEqual(critical[0]["user"], "deploy")


if __name__ == "__main__":
    unittest.main()
