import unittest
from pathlib import Path

from log_analyzer import analyze


def fail(sec, ip="203.0.113.50", user="root", minute=15):
    return f"Nov 12 10:{minute:02d}:{sec:02d} h sshd[1]: Failed password for {user} from {ip} port 4000 ssh2"


def web(url, status=200, ip="198.51.100.23", sec=0, agent="Mozilla/5.0"):
    return f'{ip} - - [12/Nov/2026:10:00:{sec:02d} +0000] "GET {url} HTTP/1.1" {status} 1 "-" "{agent}"'


def rules(lines):
    return {f["rule"] for f in analyze(lines)}


class Tests(unittest.TestCase):
    def test_brute_force(self):
        self.assertEqual(rules(fail(i) for i in range(5)), {"SSH brute force"})

    def test_below_threshold_is_quiet(self):
        self.assertEqual(rules(fail(i) for i in range(4)), set())

    def test_slow_failures_are_quiet(self):
        # 5 failures but 10 minutes apart: a forgetful user, not a brute force
        self.assertEqual(rules(fail(0, minute=m) for m in range(0, 50, 10)), set())

    def test_success_after_brute_force(self):
        lines = [fail(i) for i in range(5)]
        lines.append("Nov 12 10:16:00 h sshd[1]: Accepted password for root from 203.0.113.50 port 4000 ssh2")
        self.assertIn("Successful login after brute force", rules(lines))

    def test_spoofed_ip_in_username_is_ignored(self):
        found = analyze(fail(i, user="x from 9.9.9.9") for i in range(5))
        self.assertEqual([f["source_ip"] for f in found], ["203.0.113.50"])

    def test_password_spraying(self):
        lines = [fail(0, user=f"invalid user u{m}", minute=m) for m in range(0, 50, 10)]
        self.assertEqual(rules(lines), {"SSH password spraying"})

    def test_new_account(self):
        self.assertEqual(rules(["Nov 12 10:17:30 h useradd[9]: new user: name=evil, UID=1002"]),
                         {"New local account created"})

    def test_sqli_url_encoded(self):
        self.assertEqual(rules([web("/p?id=1%27%20OR%20%271%27=%271")]), {"SQL injection attempt"})
        self.assertEqual(rules([web("/p?id=1+UNION+SELECT+a,b")]), {"SQL injection attempt"})

    def test_path_traversal(self):
        self.assertEqual(rules([web("/d?file=..%2F..%2Fetc%2Fpasswd")]), {"Path traversal attempt"})

    def test_directory_scan(self):
        self.assertEqual(rules(web(f"/x{i}", 404, sec=i) for i in range(15)), {"Web directory scan"})

    def test_scanner_user_agent(self):
        self.assertEqual(rules([web("/", agent="sqlmap/1.8")]), {"Scanner tool user-agent"})

    def test_normal_traffic_is_quiet(self):
        self.assertEqual(rules([web("/"), web("/search?q=select+a+phone"), web("/missing", 404),
                                fail(0, ip="192.0.2.10")]), set())

    def test_sample_logs_trigger_every_rule(self):
        samples = Path(__file__).parent / "samples"
        lines = (samples / "auth.log").read_text().splitlines() + (samples / "access.log").read_text().splitlines()
        found = analyze(lines)
        self.assertEqual(len({f["rule"] for f in found}), 8)
        self.assertNotIn("192.0.2.10", {f["source_ip"] for f in found})  # the legit user


if __name__ == "__main__":
    unittest.main()
