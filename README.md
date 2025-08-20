🛡️ Security Audit Tool (SAT) - Plus Edition
This is a comprehensive Bash script for performing security audits and analysis on Linux systems, with a specific focus on the Kali Linux distribution. It is designed to help users assess the security posture of their system and identify potential vulnerabilities.

Key Features
Comprehensive Checks: Audits SSH configurations, analyzes Cron jobs, checks kernel hardening measures, and examines Docker security.

Customizable: Includes different scan modes (full, SSH-only, network-only) to suit your needs.

Kali-Aware: Runs additional checks specific to Kali Linux systems, such as repository analysis, system health checks, and OpenVPN file identification.

Report Generation: Generates detailed reports in text, JSON, and HTML formats for easy review and analysis.

Security Scoring: Provides a weighted security score based on the findings.

Prerequisites
The script is built to run with standard Linux tools. The following tools are required:

ss

ps

df

grep

awk

timeout

find

stat

It also uses optional tools like jq, aide, docker, systemctl, and sudo for extended checks.

Usage
Download and Run:

Download the SAT.sh script file to your machine.

Grant it execute permissions:

chmod +x SAT.sh


Run the script:

./SAT.sh


Options:
The script supports various arguments to customize the scan:

Option

Description

Example

--full

Perform a full security scan (default)

./SAT.sh --full

--ssh-only

Run SSH security checks only

./SAT.sh --ssh-only

--network

Run network security checks only

./SAT.sh --network

--quiet

Quiet mode (displays warnings & errors)

./SAT.sh --quiet

--verbose

Verbose mode (displays debug messages)

./SAT.sh --verbose

--help

Display the help message

./SAT.sh --help

Reports
Upon completion, the script will generate the following files in the ~/security_audits/ directory (or /tmp/security_audits/ if the home directory is not writable):

security_audit_[TIMESTAMP].txt - A simple text report.

security_audit_[TIMESTAMP].json - A JSON-formatted report.

security_audit_[TIMESTAMP].html - An HTML report for easy viewing in a browser.

License
This project is licensed under the MIT License.
