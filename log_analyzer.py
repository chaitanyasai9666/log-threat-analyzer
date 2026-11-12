"""Detect common attacks in SSH auth logs and web access logs, mapped to MITRE ATT&CK.

Usage: python log_analyzer.py samples/auth.log samples/access.log [--json report.json]
"""
import argparse
import json
import re
from collections import defaultdict
from datetime import datetime
from urllib.parse import unquote_plus

# Thresholds: how many events, inside how many seconds, count as an attack.
BRUTE_N, BRUTE_WINDOW = 5, 300      # failed SSH logins from one IP
SPRAY_USERS = 5                     # distinct usernames tried from one IP
SCAN_404, SCAN_WINDOW = 15, 60      # "not found" web responses from one IP

TS = r"^(\w{3}\s+\d+ [\d:]{8}) "
# Greedy (.+) so the LAST " from <ip> port" wins: an attacker can put
# "x from 9.9.9.9" in the username to frame another IP.
SSH_FAIL = re.compile(TS + r".*sshd\[\d+\]: Failed password for (?:invalid user )?(.+) from (\S+) port \d+")
SSH_OK = re.compile(TS + r".*sshd\[\d+\]: Accepted \w+ for (.+) from (\S+) port \d+")
USERADD = re.compile(TS + r".*useradd\[\d+\]: new user: name=([^,\s]+)")
WEB = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "\S+ (\S+)[^"]*" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?')

SQLI = re.compile(r"union(\s|/\*.*?\*/)+select|'\s*or\s+'?\d|\bor\s+1\s*=\s*1|sleep\(\d+\)|information_schema")
TRAVERSAL = re.compile(r"\.\./|\.\.\\|/etc/passwd")
SCANNER_UA = re.compile(r"nikto|sqlmap|nmap|gobuster|dirbuster|wpscan|masscan|nuclei", re.I)


def burst(times, n, window):
    """True if any n of the timestamps fall inside `window` seconds."""
    times = sorted(times)
    return any((times[i + n - 1] - times[i]).total_seconds() <= window
               for i in range(len(times) - n + 1))


def analyze(lines):
    """Return a list of findings (dicts) for an iterable of log lines."""
    fails = defaultdict(list)       # ip -> [(time, user)]
    logins = []                     # (time, user, ip)
    not_found = defaultdict(list)   # ip -> [time]
    hits = defaultdict(list)        # (rule, ip) -> [example]
    findings = []

    def add(rule, mitre, severity, ip, count, detail):
        findings.append(dict(rule=rule, mitre=mitre, severity=severity,
                             source_ip=ip, count=count, detail=detail))

    for line in lines:
        if m := SSH_FAIL.match(line):
            # syslog has no year; a fixed leap year keeps "Feb 29" parseable
            t = datetime.strptime("2000 " + m[1], "%Y %b %d %H:%M:%S")
            fails[m[3]].append((t, m[2]))
        elif m := SSH_OK.match(line):
            logins.append((datetime.strptime("2000 " + m[1], "%Y %b %d %H:%M:%S"), m[2], m[3]))
        elif m := USERADD.match(line):
            add("New local account created", "T1136.001", "medium", "-", 1, f"user '{m[2]}'")
        elif m := WEB.match(line):
            ip, ts, url, status, agent = m.groups()
            url = unquote_plus(url).lower()   # decode %27, + etc. before matching
            if status == "404":
                not_found[ip].append(datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z"))
            if SQLI.search(url):
                hits["SQL injection attempt", ip].append(url)
            if TRAVERSAL.search(url):
                hits["Path traversal attempt", ip].append(url)
            if agent and (s := SCANNER_UA.search(agent)):
                hits["Scanner tool user-agent", ip].append(s[0])

    for ip, events in fails.items():
        times = [t for t, _ in events]
        users = {u for _, u in events}
        if burst(times, BRUTE_N, BRUTE_WINDOW):
            add("SSH brute force", "T1110.001", "high", ip, len(events),
                f"{len(events)} failed logins, {BRUTE_N}+ within {BRUTE_WINDOW}s")
            for t, user, lip in logins:
                if lip == ip and t > min(times):
                    add("Successful login after brute force", "T1078", "critical", ip, 1,
                        f"user '{user}' logged in - likely compromised")
        if len(users) >= SPRAY_USERS:
            add("SSH password spraying", "T1110.003", "high", ip, len(users),
                f"{len(users)} different usernames tried")

    for ip, times in not_found.items():
        if burst(times, SCAN_404, SCAN_WINDOW):
            add("Web directory scan", "T1595.003", "medium", ip, len(times),
                f"{len(times)} 404 responses, {SCAN_404}+ within {SCAN_WINDOW}s")

    mitre = {"SQL injection attempt": ("T1190", "high"),
             "Path traversal attempt": ("T1190", "high"),
             "Scanner tool user-agent": ("T1595.002", "medium")}
    for (rule, ip), examples in hits.items():
        add(rule, *mitre[rule], ip, len(examples), f"e.g. {examples[0][:60]}")

    return findings


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("logs", nargs="+", help="auth.log and/or web access log files")
    ap.add_argument("--json", metavar="FILE", help="also write findings to a JSON file")
    args = ap.parse_args()

    lines = []
    for path in args.logs:
        with open(path, encoding="utf-8", errors="replace") as f:  # logs can hold junk bytes
            lines += f.readlines()
    findings = analyze(lines)

    print(f"{len(lines)} log lines analyzed, {len(findings)} findings\n")
    for f in findings:
        print(f"[{f['severity'].upper():8}] {f['mitre']:10} {f['rule']:36} {f['source_ip']:15} {f['detail']}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as out:
            json.dump(findings, out, indent=2)


if __name__ == "__main__":
    main()
