import unittest
import os
import sys
import tempfile

# Project root ko Python path mein add karo
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

sys.path.insert(0, PROJECT_ROOT)

from file_integrity.fim import (
    calculate_hash,
    create_event,
    scan_directory
)


class TestFIM(unittest.TestCase):

    # ==========================================
    # TEST 1: SHA-256 HASH
    # ==========================================

    def test_hash_generation(self):

        with tempfile.NamedTemporaryFile(
            mode="w",
            delete=False,
            encoding="utf-8"
        ) as file:

            file.write("Hello Security")
            file_path = file.name

        try:

            file_hash = calculate_hash(file_path)

            self.assertIsNotNone(file_hash)

            self.assertEqual(
                len(file_hash),
                64
            )

        finally:

            os.remove(file_path)


    # ==========================================
    # TEST 2: EVENT CREATION
    # ==========================================

    def test_event_creation(self):

        event = create_event(
            "FILE MODIFIED",
            "test.txt",
            "HIGH"
        )

        self.assertEqual(
            event["source"],
            "FIM"
        )

        self.assertEqual(
            event["event"],
            "FILE MODIFIED"
        )

        self.assertEqual(
            event["target"],
            "test.txt"
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
    # TEST 3: DIRECTORY SCANNING
    # ==========================================

    def test_directory_scan(self):

        with tempfile.TemporaryDirectory() as directory:

            file1 = os.path.join(
                directory,
                "file1.txt"
            )

            file2 = os.path.join(
                directory,
                "file2.txt"
            )

            with open(
                file1,
                "w",
                encoding="utf-8"
            ) as file:

                file.write("Security Test 1")

            with open(
                file2,
                "w",
                encoding="utf-8"
            ) as file:

                file.write("Security Test 2")

            result = scan_directory(directory)

            self.assertEqual(
                len(result),
                2
            )

            self.assertIn(
                file1,
                result
            )

            self.assertIn(
                file2,
                result
            )


    # ==========================================
    # TEST 4: HASH CHANGES AFTER FILE MODIFICATION
    # ==========================================

    def test_hash_changes_after_modification(self):

        with tempfile.NamedTemporaryFile(
            mode="w",
            delete=False,
            encoding="utf-8"
        ) as file:

            file.write("Original Content")
            file_path = file.name

        try:

            original_hash = calculate_hash(
                file_path
            )

            with open(
                file_path,
                "w",
                encoding="utf-8"
            ) as file:

                file.write("Modified Content")

            new_hash = calculate_hash(
                file_path
            )

            self.assertNotEqual(
                original_hash,
                new_hash
            )

        finally:

            os.remove(file_path)


    # ==========================================
    # TEST 5: SAME FILE = SAME HASH
    # ==========================================

    def test_same_file_same_hash(self):

        with tempfile.NamedTemporaryFile(
            mode="w",
            delete=False,
            encoding="utf-8"
        ) as file:

            file.write("Same Content")
            file_path = file.name

        try:

            hash1 = calculate_hash(
                file_path
            )

            hash2 = calculate_hash(
                file_path
            )

            self.assertEqual(
                hash1,
                hash2
            )

        finally:

            os.remove(file_path)


if __name__ == "__main__":
    unittest.main()