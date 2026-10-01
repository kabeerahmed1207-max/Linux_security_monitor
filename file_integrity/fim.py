import hashlib
import json
import argparse
import os
import sys
from datetime import datetime

# Project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from security_events import add_event


BASELINE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "baseline.json"
)

REPORT_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "reports"
)

REPORT_FILE = os.path.join(
    REPORT_DIR,
    "fim_report.json"
)


# ==========================================
# SHA-256 HASH
# ==========================================

def calculate_hash(file_path):
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            while True:
                data = file.read(4096)

                if not data:
                    break

                sha256.update(data)

        return sha256.hexdigest()

    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        return None

    except PermissionError:
        print(f"[ERROR] Permission denied: {file_path}")
        return None

    except OSError as error:
        print(f"[ERROR] Unable to read file: {error}")
        return None


# ==========================================
# DIRECTORY SCAN
# ==========================================

def scan_directory(directory):
    files = {}

    if not os.path.exists(directory):
        print(f"[ERROR] Directory not found: {directory}")
        return files

    if not os.path.isdir(directory):
        print(f"[ERROR] Path is not a directory: {directory}")
        return files

    try:
        for filename in os.listdir(directory):

            file_path = os.path.join(directory, filename)

            if os.path.isfile(file_path):

                file_hash = calculate_hash(file_path)

                if file_hash:
                    files[file_path] = file_hash

    except PermissionError:
        print(f"[ERROR] Permission denied: {directory}")

    except OSError as error:
        print(f"[ERROR] Directory scan failed: {error}")

    return files


# ==========================================
# EVENT CREATION
# ==========================================

def create_event(event_type, file_path, severity):

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source": "FIM",
        "event": event_type,
        "target": file_path,
        "severity": severity
    }


# ==========================================
# CENTRAL EVENT LOG
# ==========================================

def record_event(event):

    try:
        add_event(event)
        print("[+] Event added to central security log.")

    except (OSError, json.JSONDecodeError) as error:
        print(f"[ERROR] Could not update central security log: {error}")

    except Exception as error:
        print(f"[ERROR] Unexpected event logging error: {error}")


# ==========================================
# SAVE REPORT
# ==========================================

def save_report(report):

    try:
        os.makedirs(REPORT_DIR, exist_ok=True)

        with open(REPORT_FILE, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        print("\n[+] Security report saved:")
        print("    reports/fim_report.json")

    except PermissionError:
        print("[ERROR] Permission denied while saving report.")

    except OSError as error:
        print(f"[ERROR] Could not save report: {error}")

    except TypeError:
        print("[ERROR] Report contains invalid data.")


# ==========================================
# CREATE BASELINE
# ==========================================

def create_baseline(path):

    if not os.path.exists(path):
        print(f"[ERROR] File or directory not found: {path}")
        return

    if os.path.isdir(path):

        files = scan_directory(path)

        if not files:
            print("[WARNING] No files found. Baseline was not created.")
            return

        try:
            with open(BASELINE_FILE, "w", encoding="utf-8") as file:
                json.dump(files, file, indent=4)

            print("\n[+] Directory baseline created!")
            print(f"[+] Directory: {path}")
            print(f"[+] Files monitored: {len(files)}")

        except PermissionError:
            print("[ERROR] Permission denied while creating baseline.")

        except OSError as error:
            print(f"[ERROR] Could not create baseline: {error}")

        return

    if os.path.isfile(path):

        file_hash = calculate_hash(path)

        if not file_hash:
            return

        baseline = {
            path: file_hash
        }

        try:
            with open(BASELINE_FILE, "w", encoding="utf-8") as file:
                json.dump(baseline, file, indent=4)

            print("\n[+] File baseline created!")
            print(f"File: {path}")
            print(f"SHA-256: {file_hash}")

        except PermissionError:
            print("[ERROR] Permission denied while creating baseline.")

        except OSError as error:
            print(f"[ERROR] Could not create baseline: {error}")


# ==========================================
# LOAD BASELINE
# ==========================================

def load_baseline():

    if not os.path.exists(BASELINE_FILE):
        print("[ERROR] baseline.json not found.")
        print("[INFO] Run --init first.")
        return None

    try:

        with open(BASELINE_FILE, "r", encoding="utf-8") as file:
            baseline = json.load(file)

        if not isinstance(baseline, dict):
            print("[ERROR] baseline.json contains invalid data.")
            return None

        return baseline

    except json.JSONDecodeError:
        print("[ERROR] baseline.json is corrupted or invalid JSON.")
        return None

    except PermissionError:
        print("[ERROR] Permission denied while reading baseline.json.")
        return None

    except OSError as error:
        print(f"[ERROR] Could not read baseline: {error}")
        return None


# ==========================================
# CHECK FILE / DIRECTORY
# ==========================================

def check_path(path):

    if not os.path.exists(path):

        print(f"[ERROR] Path not found: {path}")
        return

    baseline = load_baseline()

    if baseline is None:
        return

    # ======================================
    # DIRECTORY CHECK
    # ======================================

    if os.path.isdir(path):

        current_files = scan_directory(path)

        events = []

        new_files = 0
        modified_files = 0
        deleted_files = 0

        # Check deleted / modified files
        for file_path in baseline:

            if file_path not in current_files:

                print("\n[ALERT] FILE DELETED!")
                print(f"File: {file_path}")

                event = create_event(
                    "FILE DELETED",
                    file_path,
                    "HIGH"
                )

                events.append(event)
                record_event(event)

                deleted_files += 1

            else:

                if current_files[file_path] != baseline[file_path]:

                    print("\n[ALERT] FILE MODIFIED!")
                    print(f"File: {file_path}")

                    event = create_event(
                        "FILE MODIFIED",
                        file_path,
                        "HIGH"
                    )

                    events.append(event)
                    record_event(event)

                    modified_files += 1

        # Check new files
        for file_path in current_files:

            if file_path not in baseline:

                print("\n[ALERT] NEW FILE DETECTED!")
                print(f"File: {file_path}")

                event = create_event(
                    "NEW FILE",
                    file_path,
                    "MEDIUM"
                )

                events.append(event)
                record_event(event)

                new_files += 1

        # Security status
        security_status = "ALERT" if events else "CLEAN"

        summary = {

            "scan_time":
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

            "source": "FIM",

            "directory": path,

            "files_checked": len(current_files),

            "new_files": new_files,

            "modified_files": modified_files,

            "deleted_files": deleted_files,

            "security_status": security_status,

            "events": events
        }

        print("\n")
        print("=" * 40)
        print("        FILE INTEGRITY SCAN")
        print("=" * 40)

        print(f"\nDirectory       : {path}")
        print(f"Files checked   : {len(current_files)}")
        print(f"New files       : {new_files}")
        print(f"Modified files  : {modified_files}")
        print(f"Deleted files   : {deleted_files}")

        print(f"\nSecurity Status : {security_status}")

        save_report(summary)

        return

    # ======================================
    # SINGLE FILE CHECK
    # ======================================

    if path not in baseline:

        print("[NEW] File is not present in baseline.")
        return

    if not os.path.exists(path):

        print("[ALERT] FILE DELETED!")
        print(f"File: {path}")

        event = create_event(
            "FILE DELETED",
            path,
            "HIGH"
        )

        record_event(event)

        report = {

            "scan_time":
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

            "source": "FIM",

            "security_status": "ALERT",

            "events": [event]
        }

        save_report(report)

        return

    current_hash = calculate_hash(path)

    if not current_hash:
        return

    original_hash = baseline[path]

    print(f"\nFile: {path}")

    print(f"Original SHA-256: {original_hash}")

    print(f"Current SHA-256 : {current_hash}")

    if current_hash == original_hash:

        print("\n[OK] File integrity verified.")
        print("[OK] No changes detected.")

    else:

        print("\n[ALERT] FILE MODIFIED!")

        event = create_event(
            "FILE MODIFIED",
            path,
            "HIGH"
        )

        record_event(event)

        report = {

            "scan_time":
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

            "source": "FIM",

            "security_status": "ALERT",

            "events": [event]
        }

        save_report(report)


# ==========================================
# MAIN
# ==========================================

def main():

    parser = argparse.ArgumentParser(
        description="File Integrity Monitoring Tool"
    )

    parser.add_argument(
        "--path",
        required=True,
        help="File or directory to monitor"
    )

    parser.add_argument(
        "--init",
        action="store_true",
        help="Create trusted baseline"
    )

    parser.add_argument(
        "--check",
        action="store_true",
        help="Check integrity"
    )

    args = parser.parse_args()

    if args.init:

        create_baseline(args.path)

    elif args.check:

        check_path(args.path)

    else:

        parser.print_help()


if __name__ == "__main__":
    main()