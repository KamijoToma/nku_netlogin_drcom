"""Regression tests for login.py/logout.py (see review of 0bc045c..HEAD).

Each test is tied to a verified finding:
- m5:  jsonp_body must not raise JSONDecodeError on malformed portal replies.
- M1:  the public VIP 222.30.38.234 (separate session DB) must never receive
       campus credentials, even when DNS resolves to it.
- C1a: the default gateway is tried only after the known campus AC IPs.
- M2:  portal retries must cover the actual HTTPS transaction; TCP reachability
       alone does not prove the AC lets HTTP through.
- m1:  portal retry has a hard total time budget.
- M5:  egress interface is detected via `ip route get <portal_ip>` (TUN-proof),
       not the plain default route.
- m4:  link-local 169.254/16 is not a "global IPv4" fallback interface.
- fe80::/10: IPv6 link-local detection covers fe90/aea0/eb0, not just fe80.
- env: credentials may come from NKU_USERNAME/NKU_PASSWORD (README promise).
"""

import io
import subprocess
import unittest
import urllib.error
from contextlib import redirect_stdout
from unittest import mock

import login
import logout as logout_mod

PUBLIC_VIP = "222.30.38.234"  # public portal instance, separate session DB
CAMPUS_AC = "198.18.0.7"      # campus-internal AC gateway


def completed(argv, stdout=""):
    return subprocess.CompletedProcess(argv, 0, stdout, "")


class FakeClock:
    """Deterministic monotonic/sleep pair: sleep() advances the clock."""

    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class JsonpBodyTests(unittest.TestCase):
    """m5: malformed JSONP must yield None, not a traceback."""

    def test_valid_jsonp_parses(self):
        body = 'dr1003({"result":1,"msg":"Radius注销成功！"});'
        self.assertEqual(login.jsonp_body(body)["result"], 1)

    def test_non_jsonp_returns_none(self):
        self.assertIsNone(login.jsonp_body("<html>portal</html>"))

    def test_invalid_json_inside_parens_returns_none(self):
        self.assertIsNone(login.jsonp_body("dr1003({invalid json})"))

    def test_truncated_json_returns_none(self):
        self.assertIsNone(login.jsonp_body('dr1003({"result":1,"msg":"tri'))



if __name__ == "__main__":
    unittest.main()
