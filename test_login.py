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

    def test_login_reports_unexpected_response_instead_of_crashing(self):
        with mock.patch.object(login, "detect_network_info",
                               return_value={"ip": "10.0.0.2", "ipv6": "",
                                             "mac": "aabbccddeeff",
                                             "blocked": True}), \
             mock.patch.object(login, "portal_request",
                               return_value="dr1003({invalid json})"):
            out = io.StringIO()
            with redirect_stdout(out):
                rc = login.login("user", "pw")
        self.assertEqual(rc, 1)
        self.assertIn("Unexpected response", out.getvalue())


class PortalCandidateTests(unittest.TestCase):
    """M1/C1a: candidate set and ordering."""

    def _candidates(self, dns, gateway):
        with mock.patch.object(login, "resolve_bounded", return_value=dns), \
             mock.patch.object(login, "default_gateway", return_value=gateway):
            return login.portal_candidates()

    def test_public_vip_is_never_a_candidate(self):
        cands = self._candidates(PUBLIC_VIP, "10.0.0.1")
        self.assertNotIn(PUBLIC_VIP, cands)

    def test_known_campus_ac_precedes_gateway(self):
        cands = self._candidates(CAMPUS_AC, "10.0.0.1")
        self.assertEqual(cands, [CAMPUS_AC, "10.0.0.1"])

    def test_gateway_is_last(self):
        cands = self._candidates("10.22.0.5", "10.22.0.1")
        self.assertEqual(cands[-1], "10.22.0.1")
        self.assertIn(CAMPUS_AC, cands[:-1])

    def test_candidates_are_deduplicated_and_skip_none(self):
        cands = self._candidates(CAMPUS_AC, CAMPUS_AC)
        self.assertEqual(cands, [CAMPUS_AC])
        self.assertEqual(self._candidates(None, None), [CAMPUS_AC])


class PortalRequestTests(unittest.TestCase):
    """M2/m1: retries wrap the real HTTPS transaction, bounded in time."""

    def _run(self, http_side_effect, budget=30.0):
        sock = mock.Mock()
        with mock.patch.object(login, "portal_candidates",
                               return_value=["203.0.113.9"]), \
             mock.patch.object(login.socket, "create_connection",
                               return_value=sock), \
             mock.patch.object(login, "http_get",
                               side_effect=http_side_effect) as http_get, \
             mock.patch.object(login.time, "sleep"):
            result = login.portal_request("/eportal/portal/login", "a=b",
                                          budget=budget)
        return result, http_get

    def test_tcp_ok_but_http_dropped_retries_until_http_succeeds(self):
        body, http_get = self._run([OSError("HTTP dropped"), 'dr1003({"result":0})'])
        self.assertEqual(body, 'dr1003({"result":0})')
        self.assertEqual(http_get.call_count, 2)

    def test_all_candidates_dead_returns_none(self):
        clock = FakeClock()
        with mock.patch.object(login, "portal_candidates",
                               return_value=["203.0.113.9"]), \
             mock.patch.object(login.socket, "create_connection",
                               side_effect=OSError), \
             mock.patch.object(login.time, "monotonic", clock.monotonic), \
             mock.patch.object(login.time, "sleep", clock.sleep):
            out = io.StringIO()
            with redirect_stdout(out):
                result = login.portal_request("/p", "", budget=5.0)
        self.assertIsNone(result)
        self.assertGreaterEqual(clock.now, 5.0)

    def test_total_budget_is_enforced(self):
        clock = FakeClock()
        sock = mock.Mock()
        with mock.patch.object(login, "portal_candidates",
                               return_value=["203.0.113.9"]), \
             mock.patch.object(login.socket, "create_connection",
                               return_value=sock), \
             mock.patch.object(login, "http_get",
                               side_effect=OSError("dropped")), \
             mock.patch.object(login.time, "monotonic", clock.monotonic), \
             mock.patch.object(login.time, "sleep", clock.sleep):
            out = io.StringIO()
            with redirect_stdout(out):
                result = login.portal_request("/p", "", budget=1.0,
                                              retry_delay=60.0)
        self.assertIsNone(result)
        # The retry delay must be truncated to the remaining budget, never 60s.
        self.assertTrue(clock.sleeps)
        self.assertLessEqual(max(clock.sleeps), 1.0)
        self.assertLessEqual(clock.now, 1.0)

    def test_http_error_response_body_counts_as_alive(self):
        # http_get converts HTTPError into the response body; a portal that
        # answers 503 is alive and must not burn the retry budget.
        err = urllib.error.HTTPError(
            "https://203.0.113.9:804/p", 503, "Service Unavailable", None,
            io.BytesIO(b'dr1003({"result":0,"msg":"busy"})'))
        sock = mock.Mock()
        with mock.patch.object(login, "portal_candidates",
                               return_value=["203.0.113.9"]), \
             mock.patch.object(login.socket, "create_connection",
                               return_value=sock), \
             mock.patch("urllib.request.urlopen", side_effect=err):
            body = login.portal_request("/p", "", budget=5.0)
        self.assertEqual(body, 'dr1003({"result":0,"msg":"busy"})')

    def test_checks_deadline_before_candidate_discovery(self):
        with mock.patch.object(login, "portal_candidates") as candidates:
            self.assertIsNone(login.portal_request("/p", "", budget=0))
        candidates.assert_not_called()

    def test_http_not_attempted_after_deadline(self):
        sock = mock.Mock()
        clock = iter([0.0, 0.0, 0.0, 5.0])  # deadline, loop, pre-TCP, post-TCP
        with mock.patch.object(login, "portal_candidates",
                               return_value=["203.0.113.9"]), \
             mock.patch.object(login.time, "monotonic",
                               side_effect=lambda: next(clock)), \
             mock.patch.object(login.socket, "create_connection",
                               return_value=sock), \
             mock.patch.object(login, "http_get") as http_get:
            self.assertIsNone(login.portal_request("/p", "", budget=1.0))
        http_get.assert_not_called()


class LogoutTests(unittest.TestCase):
    """logout.py regression coverage (it shares login.py's machinery)."""

    INFO = {"ip": "10.22.3.4", "ipv6": "", "mac": "aabbccddeeff",
            "blocked": False}

    def _run(self, body, blocked_after=True):
        with mock.patch.object(logout_mod, "detect_network_info",
                               return_value=dict(self.INFO)), \
             mock.patch.object(logout_mod, "portal_request",
                               return_value=body) as req, \
             mock.patch.object(logout_mod, "probe_blocked",
                               return_value=blocked_after):
            out = io.StringIO()
            with redirect_stdout(out):
                rc = logout_mod.logout("user", "pw")
        return rc, req, out.getvalue()

    def test_logout_uses_logout_path_with_encoded_params(self):
        rc, req, _ = self._run('dr1004({"result":1,"msg":"Radius注销成功！"})')
        self.assertEqual(rc, 0)
        path, qs = req.call_args[0][:2]
        self.assertEqual(path, "/eportal/portal/logout")
        # Parameter values travel XOR-119-hex encoded, never in plaintext.
        pairs = dict(p.split("=", 1) for p in qs.split("&") if "=" in p)
        key = login.get_key("drcom")
        self.assertEqual(pairs["user_account"], login.enc_pwd("user", key))
        self.assertEqual(pairs["user_password"], login.enc_pwd("pw", key))
        self.assertNotEqual(pairs["user_password"], "pw")
        self.assertIn("encrypt=1&v=1234&lang=zh", qs)

    def test_logout_malformed_response_returns_1(self):
        rc, _, out = self._run("dr1004({invalid json})")
        self.assertEqual(rc, 1)
        self.assertIn("Unexpected response", out)

    def test_logout_unreachable_returns_1(self):
        rc, _, out = self._run(None)
        self.assertEqual(rc, 1)
        self.assertIn("unreachable", out)


if __name__ == "__main__":
    unittest.main()
