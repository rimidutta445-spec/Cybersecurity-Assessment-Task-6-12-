
import csv
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "sample_logs.csv"
REPORT_FILE = BASE_DIR / "findings_report.txt"

FAILED_LOGIN_LIMIT = 5
FAILED_LOGIN_WINDOW_MINUTES = 10
REQUEST_LIMIT = 10
REQUEST_WINDOW_MINUTES = 5


def load_logs():
    events = []

    with open(LOG_FILE, "r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        required = {
            "timestamp", "user_id", "event_type",
            "ip_address", "device", "details"
        }

        if not reader.fieldnames:
            raise ValueError("CSV file is empty or missing its header.")

        # Remove accidental spaces or a BOM from column names.
        reader.fieldnames = [
            name.strip().lstrip("\ufeff") for name in reader.fieldnames
        ]

        if not required.issubset(reader.fieldnames):
            missing = required - set(reader.fieldnames)
            raise ValueError(
                f"CSV is missing required columns: {', '.join(sorted(missing))}"
            )

        for line_number, row in enumerate(reader, start=2):
            # Skip completely blank rows.
            if not any((value or "").strip() for value in row.values()):
                continue

            try:
                row["timestamp_parsed"] = datetime.strptime(
                    row["timestamp"].strip(), "%Y-%m-%d %H:%M:%S"
                )
            except (ValueError, TypeError, AttributeError):
                raise ValueError(
                    f"Invalid timestamp at CSV line {line_number}"
                )

            # Normalize text fields.
            for field in (
                "user_id", "event_type", "ip_address", "device", "details"
            ):
                row[field] = (row.get(field) or "").strip()

            events.append(row)

    return sorted(events, key=lambda event: event["timestamp_parsed"])


def analyse_logs(events):
    findings = []
    event_counts = Counter(event["event_type"] for event in events)

    # Detect repeated failed logins for the same user and IP.
    failed_groups = defaultdict(list)

    for event in events:
        if event["event_type"] == "LOGIN_FAILED":
            key = (event["user_id"], event["ip_address"])
            failed_groups[key].append(event)

    for (user, ip), attempts in failed_groups.items():
        for index, first in enumerate(attempts):
            window_end = first["timestamp_parsed"] + timedelta(
                minutes=FAILED_LOGIN_WINDOW_MINUTES
            )

            window = [
                event for event in attempts[index:]
                if event["timestamp_parsed"] <= window_end
            ]

            if len(window) >= FAILED_LOGIN_LIMIT:
                findings.append({
                    "severity": "HIGH",
                    "type": "MULTIPLE_FAILED_LOGINS",
                    "evidence": (
                        f"User={user}, IP={ip}, "
                        f"{len(window)} failed attempts within "
                        f"{FAILED_LOGIN_WINDOW_MINUTES} minutes; "
                        f"first={first['timestamp']}"
                    ),
                    "reason": (
                        "Repeated failures may indicate password guessing. "
                        "Confirm whether the activity was legitimate."
                    )
                })
                break

    # Detect bursts of requests from the same IP.
    requests_by_ip = defaultdict(list)

    for event in events:
        if event["event_type"] == "REQUEST":
            requests_by_ip[event["ip_address"]].append(event)

    for ip, requests in requests_by_ip.items():
        for index, first in enumerate(requests):
            window_end = first["timestamp_parsed"] + timedelta(
                minutes=REQUEST_WINDOW_MINUTES
            )

            window = [
                event for event in requests[index:]
                if event["timestamp_parsed"] <= window_end
            ]

            if len(window) >= REQUEST_LIMIT:
                findings.append({
                    "severity": "MEDIUM",
                    "type": "REPEATED_REQUESTS",
                    "evidence": (
                        f"IP={ip}, {len(window)} requests within "
                        f"{REQUEST_WINDOW_MINUTES} minutes; "
                        f"first={first['timestamp']}"
                    ),
                    "reason": (
                        "A request burst may indicate automated activity. "
                        "Check request paths, response codes and expected usage."
                    )
                })
                break

    # Detect successful logins between 11 PM and before 6 AM.
    for event in events:
        if event["event_type"] == "LOGIN_SUCCESS":
            hour = event["timestamp_parsed"].hour

            if hour >= 23 or hour < 6:
                findings.append({
                    "severity": "MEDIUM",
                    "type": "UNUSUAL_LOGIN_TIME",
                    "evidence": (
                        f"User={event['user_id']}, IP={event['ip_address']}, "
                        f"time={event['timestamp']}, "
                        f"device={event['device']}"
                    ),
                    "reason": (
                        "The login occurred between 11 PM and 6 AM. "
                        "Check the user's normal schedule and confirm legitimacy."
                    )
                })

    return event_counts, findings


def write_report(events, event_counts, findings):
    lines = [
        "CYBERSHIELD 360 - SECURITY LOG ANALYSIS",
        "=" * 48,
        f"Total log events: {len(events)}",
        "",
        "EVENT SUMMARY"
    ]

    for event_type, count in sorted(event_counts.items()):
        lines.append(f"{event_type}: {count}")

    lines.extend([
        "",
        "NORMAL BEHAVIOUR OBSERVATIONS",
        "Normal login and request events were present in the dataset.",
        "This is a sample dataset; it is not enough to establish a real "
        "user's baseline behaviour.",
        "",
        "ANALYSIS METHOD",
        f"- Flagged {FAILED_LOGIN_LIMIT} or more failed logins for the same "
        f"user and IP within {FAILED_LOGIN_WINDOW_MINUTES} minutes.",
        f"- Flagged {REQUEST_LIMIT} or more requests from the same IP within "
        f"{REQUEST_WINDOW_MINUTES} minutes.",
        "- Flagged successful logins between 11 PM and before 6 AM.",
        "- Findings are indicators for investigation, not proof of an attack.",
        "",
        "ANNOTATED FINDINGS"
    ])

    if not findings:
        lines.append("No configured detection rule was triggered.")

    for number, finding in enumerate(findings, start=1):
        lines.extend([
            "",
            f"Finding {number}: {finding['type']}",
            f"Severity: {finding['severity']}",
            f"Evidence: {finding['evidence']}",
            f"Reason: {finding['reason']}",
            "Status: Requires further investigation; not proof of an attack."
        ])

    lines.extend([
        "",
        "RECOMMENDED INVESTIGATION",
        "- Review account history and confirm repeated failed logins with the user.",
        "- Check request paths, response codes and request frequency.",
        "- Confirm unusual-hour logins match the user's normal schedule.",
        "- Compare findings with additional logs before concluding an attack occurred.",
        "",
        "LIMITATIONS",
        "- Only the supplied sample logs were analysed.",
        "- The sample is too small to establish a reliable user behaviour baseline.",
        "- Thresholds are demonstration settings, not universal rules.",
        "- Missing logs, time-zone differences and clock errors can affect results."
    ])

    with open(REPORT_FILE, "w", encoding="utf-8-sig") as file:
        file.write("\n".join(lines) + "\n")


def main():
    try:
        events = load_logs()
        event_counts, findings = analyse_logs(events)
        write_report(events, event_counts, findings)

        print("CYBERSHIELD 360 - LOG ANALYSIS")
        print(f"Logs analysed: {len(events)}")
        print(f"Findings generated: {len(findings)}")

        for finding in findings:
            print(
                f"[{finding['severity']}] {finding['type']} - "
                f"{finding['evidence']}"
            )

        print(f"\nReport saved to: {REPORT_FILE}")

    except (OSError, ValueError, csv.Error) as error:
        print(f"ERROR: {error}")


if __name__ == "__main__":
    main()
