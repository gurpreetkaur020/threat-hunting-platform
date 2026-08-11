#!/usr/bin/env python3
"""
SSH Auth Log Threat Hunter
---------------------------
Parses a Linux SSH auth.log file and flags suspicious activity:
  - Brute-force attempts (many failed logins from one IP in a short window)
  - Invalid usernames being tried (common attack indicator)
  - IPs that failed many times then succeeded (possible compromised credential)

Author: [Your Name]
Purpose: Educational project - BCA Cyber Security & Cloud Computing, Chandigarh University

Usage:
    python3 analyzer.py sample_logs/auth.log
    python3 analyzer.py sample_logs/auth.log --threshold 5 --window 60
"""

import re
import argparse
from collections import defaultdict
from datetime import datetime

# Regex patterns for common SSH auth log lines
FAILED_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2}).*"
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
ACCEPTED_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2}).*"
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def parse_timestamp(month, day, time_str, year=None):
    """Convert log's month/day/time into a datetime object (assumes current year)."""
    year = year or datetime.now().year
    return datetime.strptime(f"{year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")


def parse_log(filepath):
    """Read the log file and extract all failed and successful login events."""
    failed_events = []
    accepted_events = []

    with open(filepath, "r") as f:
        for line in f:
            fm = FAILED_PATTERN.search(line)
            if fm:
                ts = parse_timestamp(fm["month"], fm["day"], fm["time"])
                failed_events.append({"time": ts, "user": fm["user"], "ip": fm["ip"]})
                continue
            am = ACCEPTED_PATTERN.search(line)
            if am:
                ts = parse_timestamp(am["month"], am["day"], am["time"])
                accepted_events.append({"time": ts, "user": am["user"], "ip": am["ip"]})

    return failed_events, accepted_events


def detect_brute_force(failed_events, threshold=10, window_minutes=5):
    """
    Flag IPs with more than `threshold` failed attempts within any
    `window_minutes` sliding window.
    """
    by_ip = defaultdict(list)
    for event in failed_events:
        by_ip[event["ip"]].append(event["time"])

    alerts = []
    for ip, timestamps in by_ip.items():
        timestamps.sort()
        # Sliding window check
        for i in range(len(timestamps)):
            window_end = timestamps[i]
            window_start = window_end.replace(microsecond=0)
            count_in_window = sum(
                1 for t in timestamps
                if 0 <= (window_end - t).total_seconds() <= window_minutes * 60
            )
            if count_in_window >= threshold:
                alerts.append({
                    "ip": ip,
                    "count": count_in_window,
                    "window_minutes": window_minutes,
                    "last_seen": window_end,
                })
                break  # one alert per IP is enough
    return alerts


def detect_credential_stuffing(failed_events, accepted_events):
    """Flag IPs that failed multiple times and then succeeded - a red flag."""
    failed_ips = defaultdict(int)
    for event in failed_events:
        failed_ips[event["ip"]] += 1

    suspicious = []
    for event in accepted_events:
        ip = event["ip"]
        if failed_ips.get(ip, 0) >= 3:
            suspicious.append({
                "ip": ip,
                "user": event["user"],
                "failed_attempts_before_success": failed_ips[ip],
                "success_time": event["time"],
            })
    return suspicious


def summarize_usernames(failed_events):
    """Count which usernames were most targeted - shows attacker's guess list."""
    counts = defaultdict(int)
    for event in failed_events:
        counts[event["user"]] += 1
    return sorted(counts.items(), key=lambda x: x[1], reverse=True)


def print_report(failed_events, accepted_events, brute_force_alerts, cred_stuffing, top_users):
    print("=" * 60)
    print("THREAT HUNTING REPORT — SSH Auth Log Analysis")
    print("=" * 60)
    print(f"Total failed login attempts   : {len(failed_events)}")
    print(f"Total successful logins       : {len(accepted_events)}")
    print()

    print("-" * 60)
    print("[!] BRUTE-FORCE ALERTS")
    print("-" * 60)
    if brute_force_alerts:
        for alert in brute_force_alerts:
            print(f"  IP {alert['ip']:<16} -> {alert['count']} failed attempts "
                  f"within {alert['window_minutes']} min (last seen {alert['last_seen']})")
    else:
        print("  No brute-force patterns detected at current threshold.")
    print()

    print("-" * 60)
    print("[!] POSSIBLE COMPROMISED CREDENTIALS")
    print("-" * 60)
    if cred_stuffing:
        for s in cred_stuffing:
            print(f"  IP {s['ip']:<16} failed {s['failed_attempts_before_success']}x "
                  f"then SUCCEEDED as '{s['user']}' at {s['success_time']}")
    else:
        print("  None detected.")
    print()

    print("-" * 60)
    print("TOP TARGETED USERNAMES")
    print("-" * 60)
    for user, count in top_users[:10]:
        print(f"  {user:<20} {count} attempts")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Threat hunter for SSH auth logs.")
    parser.add_argument("logfile", help="Path to the auth.log file to analyze")
    parser.add_argument("--threshold", type=int, default=10,
                         help="Failed attempts within window to trigger brute-force alert (default: 10)")
    parser.add_argument("--window", type=int, default=5,
                         help="Time window in minutes for brute-force detection (default: 5)")
    args = parser.parse_args()

    failed_events, accepted_events = parse_log(args.logfile)
    brute_force_alerts = detect_brute_force(failed_events, args.threshold, args.window)
    cred_stuffing = detect_credential_stuffing(failed_events, accepted_events)
    top_users = summarize_usernames(failed_events)

    print_report(failed_events, accepted_events, brute_force_alerts, cred_stuffing, top_users)


if __name__ == "__main__":
    main()
