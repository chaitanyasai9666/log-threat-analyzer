"""Regenerate the sample logs: python samples/make_samples.py
All IPs are from documentation ranges (RFC 5737), not real hosts."""
from pathlib import Path

here = Path(__file__).parent
ATTACKER, SPRAYER, WEB_ATTACKER, USER = "203.0.113.50", "203.0.113.77", "198.51.100.23", "192.0.2.10"

auth = [f"Nov 12 09:00:01 web01 sshd[1001]: Accepted publickey for chaitu from {USER} port 50001 ssh2"]
# brute force: 12 wrong passwords for root in under a minute, then a success
for i in range(12):
    auth.append(f"Nov 12 10:15:{i * 4:02d} web01 sshd[{2000 + i}]: Failed password for root from {ATTACKER} port {40000 + i} ssh2")
auth.append(f"Nov 12 10:16:02 web01 sshd[2050]: Accepted password for root from {ATTACKER} port 40050 ssh2")
auth.append("Nov 12 10:17:30 web01 useradd[2101]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash")
# password spraying: one try each for many usernames, slowly
for i, user in enumerate(["admin", "test", "oracle", "postgres", "ubuntu", "deploy", "git"]):
    auth.append(f"Nov 12 11:{i * 7:02d}:10 web01 sshd[{3000 + i}]: Failed password for invalid user {user} from {SPRAYER} port {41000 + i} ssh2")
# benign: one typo
auth.append(f"Nov 12 12:00:05 web01 sshd[4001]: Failed password for chaitu from {USER} port 50002 ssh2")
auth.append(f"Nov 12 12:00:11 web01 sshd[4001]: Accepted password for chaitu from {USER} port 50002 ssh2")


def web(ip, sec, url, status, agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"):
    return f'{ip} - - [12/Nov/2026:10:{sec // 60:02d}:{sec % 60:02d} +0000] "GET {url} HTTP/1.1" {status} 512 "-" "{agent}"'


access = [web(USER, i * 20, p, 200) for i, p in enumerate(["/", "/about", "/login", "/static/app.css"])]
access.append(web(USER, 90, "/favicon.ico", 404))
# directory scan with gobuster: 25 guesses in 25 seconds
for i, word in enumerate("admin backup config db dev old test tmp uploads wp-admin phpmyadmin .git .env api v1 "
                         "shell cgi-bin server-status console debug private secret staging logs dump".split()):
    access.append(web(WEB_ATTACKER, 120 + i, f"/{word}", 404, "gobuster/3.6"))
# SQL injection and path traversal (URL-encoded, as a real attacker would send them)
access.append(web(WEB_ATTACKER, 200, "/products?id=1%27%20OR%20%271%27=%271", 200))
access.append(web(WEB_ATTACKER, 203, "/products?id=1+UNION+SELECT+username,password+FROM+users", 500))
access.append(web(WEB_ATTACKER, 210, "/download?file=..%2F..%2F..%2Fetc%2Fpasswd", 403))

(here / "auth.log").write_text("\n".join(auth) + "\n", encoding="utf-8")
(here / "access.log").write_text("\n".join(access) + "\n", encoding="utf-8")
print(f"wrote {len(auth)} auth lines, {len(access)} access lines")
