import json
from collections import defaultdict
from datetime import datetime, timedelta

def parse_log_line(line):
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None

def find_ddos_attacks(logs, time_window_seconds=60, request_threshold=10):
    ip_request_times = defaultdict(list)
    ddos_logs = []

    for log in logs:
        user_ip = log.get("user_ip")
        timestamp = datetime.fromisoformat(log.get("timestamp").replace('Z', '+00:00'))
        status_code = log.get("status_code")

        if status_code == 503:
            ddos_logs.append(log)
            continue

        ip_request_times[user_ip].append(timestamp)

    for ip, timestamps in ip_request_times.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            window_start = timestamps[i]
            window_end = window_start + timedelta(seconds=time_window_seconds)
            requests_in_window = sum(window_start <= t <= window_end for t in timestamps)
            if requests_in_window >= request_threshold:
                ddos_logs.extend([log for log in logs if log["user_ip"] == ip and log not in ddos_logs])

    return ddos_logs

def analyze_log_file(file_path):
    with open(file_path, 'r') as file:
        logs = [parse_log_line(line) for line in file if parse_log_line(line)]

    ddos_logs = find_ddos_attacks(logs)
    num_ddos_logs = len(ddos_logs)

    if num_ddos_logs > 0:
        print(f"Potential DDoS attack detected. Number of suspicious logs: {num_ddos_logs}")
        for log in ddos_logs:
            print(json.dumps(log, indent=4))
    else:
        print("No DDoS attack detected.")

log_file_path = '/Users/beaut/Downloads/Log_DDos(txt).txt'
analyze_log_file(log_file_path)
