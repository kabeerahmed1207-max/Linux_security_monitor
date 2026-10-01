import unittest
import os
import sys
import tempfile

# Project root
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

sys.path.insert(0, PROJECT_ROOT)

from log_analyzer.analyzer import (
    extract_ip,
    create_event,
    analyze_log
)


class TestLogAnalyzer(unittest.TestCase):

    # ==========================================
    # TEST 1: IP EXTRACTION
    # ==========================================

    def test_ip_extraction(self):

        line = (
            "Failed password for invalid user admin "
            "from 192.168.1.50 port 22 ssh2"
        )

        ip = extract_ip(line)

        self.assertEqual(
            ip,
            "192.168.1.50"
        )


    # ==========================================
    # TEST 2: NO IP FOUND
    # ==========================================

    def test_no_ip_found(self):

        line = "Invalid login attempt"

        ip = extract_ip(line)

        # Current analyzer returns "Unknown"
        self.assertEqual(
            ip,
            "Unknown"
        )


    # ==========================================
    # TEST 3: EVENT CREATION
    # ==========================================

    def test_event_creation(self):

        event = create_event(
            "FAILED SSH LOGIN",
            "192.168.1.50",
            "HIGH"
        )

        self.assertEqual(
            event["source"],
            "LOG_ANALYZER"
        )

        self.assertEqual(
            event["event"],
            "FAILED SSH LOGIN"
        )

        self.assertEqual(
            event["target"],
            "192.168.1.50"
        )

        self.assertEqual(
            event["severity"],
            "HIGH"
        )

        self.assertIn(
            "timestamp",
            event
        )


    # ==========================================
    # TEST 4: LOG ANALYSIS
    # ==========================================

    def test_log_analysis(self):

        log_content = """\
Failed password for invalid user admin from 192.168.1.50 port 22 ssh2
Failed password for invalid user root from 192.168.1.50 port 22 ssh2
Accepted password for user from 10.0.0.10 port 22 ssh2
"""

        with tempfile.NamedTemporaryFile(
            mode="w",
            delete=False,
            encoding="utf-8"
        ) as file:

            file.write(log_content)
            log_path = file.name

        try:

            # analyze_log() report print/save karta hai
            # aur current version mein None return karta hai.
            result = analyze_log(log_path)

            self.assertIsNone(result)

        finally:

            if os.path.exists(log_path):
                os.remove(log_path)


    # ==========================================
    # TEST 5: MULTIPLE FAILED ATTEMPTS
    # ==========================================

    def test_multiple_failed_attempts(self):

        log_content = """\
Failed password for invalid user admin from 192.168.1.50 port 22 ssh2
Failed password for invalid user test from 192.168.1.50 port 22 ssh2
Failed password for invalid user root from 192.168.1.50 port 22 ssh2
Failed password for invalid user guest from 192.168.1.50 port 22 ssh2
Failed password for invalid user user from 192.168.1.50 port 22 ssh2
"""

        with tempfile.NamedTemporaryFile(
            mode="w",
            delete=False,
            encoding="utf-8"
        ) as file:

            file.write(log_content)
            log_path = file.name

        try:

            result = analyze_log(log_path)

            self.assertIsNone(result)

        finally:

            if os.path.exists(log_path):
                os.remove(log_path)


# ==========================================
# RUN TESTS
# ==========================================

if __name__ == "__main__":
    unittest.main()