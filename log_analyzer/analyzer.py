import re
import json
import argparse
import os
import time
import sys

from collections import Counter
from datetime import datetime


# ========================================
# Allow Import From Project Root
# ========================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.insert(
    0,
    PROJECT_ROOT
)


from security_events import add_event


# ========================================
# Create Security Event
# ========================================

def create_event(
    event_type,
    target,
    severity
):

    return {
        "timestamp":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "source":
            "LOG_ANALYZER",

        "event":
            event_type,

        "target":
            target,

        "severity":
            severity
    }


# ========================================
# Save Local Report
# ========================================

def save_report(report):

    os.makedirs(
        "reports",
        exist_ok=True
    )

    with open(
        "reports/security_report.json",
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    print(
        "\n[+] Local security report saved:"
    )

    print(
        "    reports/security_report.json"
    )


# ========================================
# Extract IP
# ========================================

def extract_ip(line):

    ip_match = re.search(
        r"from (\d+\.\d+\.\d+\.\d+)",
        line
    )

    if ip_match:

        return ip_match.group(1)

    return "Unknown"


# ========================================
# Analyze Log
# ========================================

def analyze_log(file_path):

    failed_logins = []
    successful_logins = []

    try:

        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            for line in file:

                line = line.strip()

                if not line:
                    continue

                if "Failed password" in line:

                    ip = extract_ip(line)

                    failed_logins.append(ip)

                elif "Accepted password" in line:

                    ip = extract_ip(line)

                    successful_logins.append(ip)

    except FileNotFoundError:

        print(
            f"[ERROR] Log file not found: "
            f"{file_path}"
        )

        return

    except PermissionError:

        print(
            f"[ERROR] Permission denied: "
            f"{file_path}"
        )

        return


    # ====================================
    # Count Failed Attempts
    # ====================================

    failed_counts = Counter(
        failed_logins
    )

    events = []


    # ====================================
    # Failed Login Events
    # ====================================

    for ip, count in failed_counts.items():

        if count >= 5:

            severity = "HIGH"

        elif count >= 3:

            severity = "MEDIUM"

        else:

            severity = "LOW"


        event = create_event(
            "FAILED SSH LOGIN",
            ip,
            severity
        )

        events.append(event)


        # Add to central report

        add_event(event)


    # ====================================
    # Successful Login Events
    # ====================================

    successful_ips = set(
        successful_logins
    )

    for ip in successful_ips:

        event = create_event(
            "SUCCESSFUL SSH LOGIN",
            ip,
            "INFO"
        )

        events.append(event)

        add_event(event)


    # ====================================
    # Security Status
    # ====================================

    security_status = "ALERT" if failed_logins else "CLEAN"

    for event in events:

        if event["severity"] in [
            "HIGH",
            "MEDIUM"
        ]:

            security_status = "ALERT"

            break


    # ====================================
    # Local Report
    # ====================================

    report = {

        "scan_time":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "source":
            "LOG_ANALYZER",

        "log_file":
            file_path,

        "failed_login_attempts":
            len(failed_logins),

        "successful_login_attempts":
            len(successful_logins),

        "unique_failed_ips":
            len(failed_counts),

        "security_status":
            security_status,

        "events":
            events
    }


    # ====================================
    # Display
    # ====================================

    print("\n")
    print("=" * 45)
    print("          LOG SECURITY ANALYSIS")
    print("=" * 45)

    print(
        f"\nLog File              : "
        f"{file_path}"
    )

    print(
        f"Failed Login Attempts : "
        f"{len(failed_logins)}"
    )

    print(
        f"Successful Logins     : "
        f"{len(successful_logins)}"
    )

    print(
        f"Unique Failed IPs     : "
        f"{len(failed_counts)}"
    )

    print(
        f"\nSecurity Status       : "
        f"{security_status}"
    )

    print("\nSecurity Events:")

    for event in events:

        print(
            f"\n[{event['severity']}] "
            f"{event['event']}"
        )

        print(
            f"Target    : "
            f"{event['target']}"
        )

        print(
            f"Timestamp : "
            f"{event['timestamp']}"
        )


    save_report(report)

    print(
        "\n[+] Events added to central security log."
    )


# ========================================
# Real-Time Monitoring
# ========================================

def watch_log(file_path):

    print(
        f"\n[*] Monitoring: {file_path}"
    )

    print(
        "[*] Waiting for new log entries..."
    )

    print(
        "[*] Press CTRL+C to stop.\n"
    )

    try:

        file_position = os.path.getsize(
            file_path
        )

        while True:

            try:

                with open(
                    file_path,
                    "r",
                    encoding="utf-8",
                    errors="ignore"
                ) as file:

                    file.seek(file_position)

                    new_lines = file.readlines()

                    file_position = file.tell()

            except PermissionError:

                time.sleep(1)

                continue


            for line in new_lines:

                line = line.strip()

                if not line:
                    continue


                print(
                    f"\n[NEW LOG] {line}"
                )


                if "Failed password" in line:

                    ip = extract_ip(line)

                    event = create_event(
                        "FAILED SSH LOGIN",
                        ip,
                        "MEDIUM"
                    )

                    add_event(event)

                    print(
                        "\n[ALERT] "
                        "Failed Login Detected"
                    )

                    print(
                        f"IP       : {ip}"
                    )

                    print(
                        "Severity : MEDIUM"
                    )

                    print(
                        "[+] Event added to central log."
                    )


                elif "Accepted password" in line:

                    ip = extract_ip(line)

                    event = create_event(
                        "SUCCESSFUL SSH LOGIN",
                        ip,
                        "INFO"
                    )

                    add_event(event)

                    print(
                        "\n[INFO] "
                        "Successful Login"
                    )

                    print(
                        f"IP       : {ip}"
                    )

                    print(
                        "[+] Event added to central log."
                    )


            time.sleep(1)


    except FileNotFoundError:

        print(
            f"[ERROR] Log file not found: "
            f"{file_path}"
        )

    except KeyboardInterrupt:

        print(
            "\n[*] Monitoring stopped."
        )


# ========================================
# Main
# ========================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Linux Security Log Analyzer"
        )
    )

    parser.add_argument(
        "--log",
        required=True,
        help="Path to log file"
    )

    parser.add_argument(
        "--watch",
        action="store_true",
        help="Monitor log file in real time"
    )

    args = parser.parse_args()


    if args.watch:

        watch_log(
            args.log
        )

    else:

        analyze_log(
            args.log
        )


# ========================================
# Start
# ========================================

if __name__ == "__main__":

    main()