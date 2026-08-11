#!/usr/bin/env python3
"""
Generates a realistic sample SSH auth.log file for testing the analyzer.
This simulates normal logins mixed with a brute-force attack pattern,
so the analyzer has something meaningful to detect.
"""

import random
from datetime import datetime, timedelta

USERNAMES_VALID = ["gurpreet", "admin", "deploy"]
USERNAMES_ATTACK = ["root", "admin", "test", "oracle", "postgres", "user", "ubuntu"]

NORMAL_IPS = ["192.168.1.10", "192.168.1.15", "10.0.0.5"]
ATTACKER_IPS = ["185.220.101.7", "45.155.205.30", "103.121.88.44"]

HOST = "ubuntu-server"

lines = []
start_time = datetime.now() - timedelta(hours=2)


def fmt(ts):
    return ts.strftime("%b %d %H:%M:%S")


# --- Normal successful logins scattered over 2 hours ---
t = start_time
for _ in range(15):
    t += timedelta(minutes=random.randint(2, 10))
    user = random.choice(USERNAMES_VALID)
    ip = random.choice(NORMAL_IPS)
    pid = random.randint(1000, 9999)
    lines.append(f"{fmt(t)} {HOST} sshd[{pid}]: Accepted password for {user} from {ip} port {random.randint(30000,60000)} ssh2")

# --- A few isolated failed logins (normal human typos, not an attack) ---
for _ in range(4):
    t += timedelta(minutes=random.randint(3, 8))
    user = random.choice(USERNAMES_VALID)
    ip = random.choice(NORMAL_IPS)
    pid = random.randint(1000, 9999)
    lines.append(f"{fmt(t)} {HOST} sshd[{pid}]: Failed password for {user} from {ip} port {random.randint(30000,60000)} ssh2")

# --- Brute-force attack burst: many failed logins, short intervals, one IP ---
attack_ip = random.choice(ATTACKER_IPS)
t_attack = start_time + timedelta(minutes=45)
for _ in range(40):
    t_attack += timedelta(seconds=random.randint(2, 8))
    user = random.choice(USERNAMES_ATTACK)
    pid = random.randint(1000, 9999)
    lines.append(f"{fmt(t_attack)} {HOST} sshd[{pid}]: Failed password for {'invalid user ' if user!='admin' else ''}{user} from {attack_ip} port {random.randint(30000,60000)} ssh2")

# --- Second, smaller brute-force burst from a different IP ---
attack_ip2 = random.choice([ip for ip in ATTACKER_IPS if ip != attack_ip])
t_attack2 = start_time + timedelta(minutes=90)
for _ in range(12):
    t_attack2 += timedelta(seconds=random.randint(3, 10))
    user = random.choice(USERNAMES_ATTACK)
    pid = random.randint(1000, 9999)
    lines.append(f"{fmt(t_attack2)} {HOST} sshd[{pid}]: Failed password for {'invalid user ' if user!='admin' else ''}{user} from {attack_ip2} port {random.randint(30000,60000)} ssh2")

# Sort all lines chronologically by re-parsing the embedded timestamp isn't trivial
# across year boundaries, so instead we just build them already in time order per block.
# Merge normal + attack blocks in a realistic interleaved order:
random.shuffle(lines[:19])  # shuffle normal logins/failures amongst themselves only

with open("sample_logs/auth.log", "w") as f:
    f.write("\n".join(lines) + "\n")

print(f"Sample log generated: sample_logs/auth.log ({len(lines)} lines)")
print(f"Attacker IP #1 (heavy brute-force): {attack_ip}")
print(f"Attacker IP #2 (lighter brute-force): {attack_ip2}")
