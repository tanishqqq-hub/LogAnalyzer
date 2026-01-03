from datetime import datetime
import re
import os
import json
import argparse

#FILE READING 

def reading_file(file_path):
    try:
        with open(file_path, "r") as file:
            return file.readlines()
    except FileNotFoundError:
        print("File not found")
        return []

# CUSTOM LOG PARSER 

def parsing_custom_logs(line):
    parts = line.strip().split(" ")
    if len(parts) < 5:
        return None

    date = parts[0]
    time = parts[1]
    level = parts[2]
    service = parts[3]
    message = " ".join(parts[4:])

    timestamp_str = f"{date} {time}"

    return {
        "Timestamp": parse_timestamp(timestamp_str),
        "Level": level,
        "Service": service,
        "Message": message
    }

# APACHE LOG PARSER

def parse_apache_logs(line):
    pattern = (
        r'(?P<ip>\S+) .* '
        r'\[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) .*" '
        r'(?P<status>\d{3})'
    )

    match = re.search(pattern, line)
    if not match:
        return None

    raw_time = match.group("timestamp")
    timestamp = datetime.strptime(raw_time.split()[0], "%d/%b/%Y:%H:%M:%S")

    status = int(match.group("status"))
    level = "ERROR" if status >= 500 else "INFO"

    return {
        "Timestamp": timestamp,
        "Level": level,
        "Service": "web_server",
        "Message": f"{match.group('method')} {match.group('path')} (status {status})"
    }

#PARSER ROUTER

def parse_log_line(line):
    if "[" in line and "]" in line:
        return parse_apache_logs(line)
    else:
        return parsing_custom_logs(line)

#PARSING PIPELINE

def parsing_perm(lines):
    parsed_logs = []
    for line in lines:
        parsed = parse_log_line(line)
        if parsed:
            parsed_logs.append(parsed)
    return parsed_logs

#ANALYSIS

def count_levels(parsed_logs):
    counts = {}
    for log in parsed_logs:
        level = log["Level"]
        counts[level] = counts.get(level, 0) + 1
    return counts


def count_errors_by_service(parsed_logs):
    counts = {}
    for log in parsed_logs:
        if log["Level"] == "ERROR":
            service = log["Service"]
            counts[service] = counts.get(service, 0) + 1
    return counts


def get_most_failed_service(error_counts):
    if not error_counts:
        return None
    return max(error_counts, key=error_counts.get)


def parse_timestamp(timestamp_str):
    return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")


def sorted_timestamp(parsed_logs):
    return sorted(parsed_logs, key=lambda log: log["Timestamp"])

#STATE HANDLING

def load_state(state_path):
    if not os.path.exists(state_path):
        return {
            "runs": 0,
            "total_logs": 0,
            "service_errors": {},
            "last_run": None
        }

    with open(state_path, "r") as f:
        return json.load(f)


def save_state(state_path, state):
    with open(state_path, "w") as f:
        json.dump(state, f, indent=2, default=str)


def update_state(state, parsed_logs, service_errors):
    state["runs"] += 1
    state["total_logs"] += len(parsed_logs)
    state["last_run"] = datetime.now()

    for service, count in service_errors.items():
        state["service_errors"][service] = (
            state["service_errors"].get(service, 0) + count
        )

    return state

#PRINTING

def print_system_summary(level_counts, service_errors, worst_service, error_events, state,alerts):
    print("\n" + "=" * 50)
    print("SYSTEM SUMMARY")
    print("=" * 50)

    print("\nLog Levels:")
    for level, count in level_counts.items():
        print(f"  {level}: {count}")

    print("\nErrors by Service:")
    if service_errors:
        for service, count in service_errors.items():
            print(f"  {service}: {count}")
    else:
        print("  No errors detected")

    if worst_service:
        print(f"\nMost Failing Service: {worst_service}")

    print("\nRecent Error Events:")
    if error_events:
        for log in error_events:
            time_str = log["Timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            print(f"  {time_str} | {log['Service']} | {log['Message']}")
    else:
        print("  No recent errors")

    print("\nSystem Memory:")
    print(f"  Total Runs      : {state['runs']}")
    print(f"  Total Logs Seen : {state['total_logs']}")
    print(f"  Last Run        : {state['last_run']}")

    print("\nHistorical Error Totals:")
    for service, count in state["service_errors"].items():
        print(f"  {service}: {count}")

    if alerts:
        print("\n🚨 ANOMALY ALERTS")
        for alert in alerts:
            print(
                f"Service: {alert['service']} | "
                f"Current Errors: {alert['current_errors']} | "
                f"Historical Avg: {alert['historical_avg']} | "
                f"Severity: {alert['severity']}"
                )
    else:
        print("\nNo anomalies detected.")
    


    print("=" * 50)

#ANOMALIES

def detect_anomalies(state, current_service_errors,threshold):
    alerts = []

    historical_runs = state["runs"]
    historical_errors = state["service_errors"]

    for service, current_count in current_service_errors.items():
        past_total = historical_errors.get(service, 0)

        if historical_runs <= 1:
            continue  # not enough data for baseline

        avg_errors = past_total / historical_runs

        if avg_errors > 0 and current_count > avg_errors * threshold:
            alerts.append({
                "service": service,
                "current_errors": current_count,
                "historical_avg": round(avg_errors, 2),
                "severity": "HIGH"
            })

    return alerts

#CLI

def build_cli():
    parser = argparse.ArgumentParser(
        description="LogIntel – Adaptive Log Analysis & Anomaly Detection Tool"
    )

    subparsers = parser.add_subparsers(dest="command")

    analyze_parser = subparsers.add_parser(
        "analyze", help="Analyze log files and detect anomalies"
    )

    analyze_parser.add_argument(
        "--log",
        required=True,
        help="Path to log file (e.g. apache_access.log)"
    )

    analyze_parser.add_argument(
        "--threshold",
        type=float,
        default=2.0,
        help="Anomaly threshold multiplier (default: 2.0)"
    )

    return parser

#MAIN

if __name__ == "__main__":
    parser = build_cli()
    args = parser.parse_args()

    if args.command != "analyze":
        parser.print_help()
        exit(1)

    LOG_PATH = args.log
    THRESHOLD = args.threshold
    STATE_PATH = "../state/system_state.json"

    raw_logs = reading_file(LOG_PATH)
    parsed_logs = parsing_perm(raw_logs)
    sorted_logs = sorted_timestamp(parsed_logs)

    level_counts = count_levels(parsed_logs)
    service_errors = count_errors_by_service(parsed_logs)
    worst_service = get_most_failed_service(service_errors)

    state = load_state(STATE_PATH)

    alerts = detect_anomalies(state, service_errors, THRESHOLD)

    state = update_state(state, parsed_logs, service_errors)
    save_state(STATE_PATH, state)

    error_events = [log for log in sorted_logs if log["Level"] == "ERROR"]

    print_system_summary(
        level_counts=level_counts,
        service_errors=service_errors,
        worst_service=worst_service,
        error_events=error_events,
        state=state,
        alerts=alerts
    )

    

