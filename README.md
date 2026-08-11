# SSH Auth Log Threat Hunter

A Python tool that analyzes Linux SSH authentication logs (auth.log) to detect suspicious activity — brute-force attacks, targeted usernames, and possible compromised credentials. Built as a hands-on project while studying Cyber Security & Cloud Computing at Chandigarh University.

## Why I built this

SSH brute-force attacks are one of the most common real-world threats against any internet-facing server. Manually reading through thousands of log lines isn't practical, so I built this to automate the "threat hunting" process — the same kind of pattern analysis a SOC analyst does when reviewing logs.

## What it detects

1. Brute-force attacks — flags any IP with an unusually high number of failed login attempts within a short time window
2. Possible compromised credentials — flags any IP that failed several times and then succeeded
3. Most-targeted usernames — ranks which usernames attackers tried most

## Usage

python3 generate_sample_log.py
python3 analyzer.py sample_logs/auth.log

## Requirements

Python 3.x (standard library only — no external dependencies)

## Author

Gurpreet Kaur — BCA Cyber Security & Cloud Computing, Chandigarh University
https://www.linkedin.com/in/gurpreet-kaur-b5b333410
