import json
import os


# ========================================
# Central Security Event File
# ========================================

REPORT_FILE = os.path.join(
    os.path.dirname(__file__),
    "reports",
    "security_events.json"
)


# ========================================
# Load Events
# ========================================

def load_events():

    if not os.path.exists(REPORT_FILE):

        return []

    try:

        with open(
            REPORT_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

            if isinstance(data, list):
                return data

            return []

    except (json.JSONDecodeError, OSError):

        return []


# ========================================
# Save Events
# ========================================

def save_events(events):

    os.makedirs(
        os.path.dirname(REPORT_FILE),
        exist_ok=True
    )

    with open(
        REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            events,
            file,
            indent=4
        )


# ========================================
# Add Security Event
# ========================================

def add_event(event):

    events = load_events()

    events.append(event)

    save_events(events)


# ========================================
# Display Events
# ========================================

def display_events():

    events = load_events()

    if not events:

        print(
            "\n[INFO] No security events found."
        )

        return

    print("\n")
    print("=" * 50)
    print("       CENTRAL SECURITY EVENTS")
    print("=" * 50)

    for event in events:

        print(
            f"\n[{event.get('severity', 'UNKNOWN')}] "
            f"{event.get('event', 'UNKNOWN')}"
        )

        print(
            f"Source    : "
            f"{event.get('source', 'UNKNOWN')}"
        )

        print(
            f"Target    : "
            f"{event.get('target', 'UNKNOWN')}"
        )

        print(
            f"Timestamp : "
            f"{event.get('timestamp', 'UNKNOWN')}"
        )


# ========================================
# Main
# ========================================

if __name__ == "__main__":

    print("Linux Security Monitor")
    print("Central Event Collector")

    display_events()