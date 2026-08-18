#!/usr/bin/env python3
"""NKU campus network (Dr.COM ePortal) login tool.

Protocol verified live on the campus VLAN (LicheePi 4A, Aug 2026):

- Endpoint:  https://netauth.nankai.edu.cn:804/eportal/portal/login
- Every parameter value is XOR-119-hex encoded (key = 'd'^'r'^'c'^'o'^'m' = 0x77),
  followed by the plaintext suffix  encrypt=1&v=1234&lang=zh
- Success:   dr1003({"result":0,"msg":"Welcome to Drcom System:<nas>","ret_code":1})
             or msg "Portal协议认证成功!" (session-refresh style login)
- Failure:   msg "统一身份认证验证失败" (wrong password)
             or "无法获取用户认证账号!" (account not found / undecodable)
- The account is the plain student ID (e.g. 1234567890); email forms are rejected.
- Standard library only (no third-party dependencies). Never hangs on DNS:
  all name resolution runs in a bounded daemon thread.
"""

import json
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

PORTAL_HOST = "netauth.nankai.edu.cn"
PORTAL_PORT = 804
LOGIN_PATH = "/eportal/portal/login"
PROBE_HOST = "www.baidu.com"

# Known portal IPs used when DNS is unreachable (e.g. AC black-holes it):
# campus-internal AC gateway, public VIP.
PORTAL_IP_CANDIDATES = ["198.18.0.7", "222.30.38.234"]

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get_key(secret_key):
    ret = 0
    for char in secret_key:
        ret ^= ord(char)
    return ret


def enc_pwd(value, key):
    """XOR each character of value with key, return lowercase hex (empty stays empty)."""
    if not value:
        return ""
    return "".join(f"{ord(c) ^ key:02x}" for c in str(value))


def jsonp_body(text):
    """Parse the JSON object out of a JSONP response like dr1003({...});"""
    m = re.search(r"\((\{.*\})\)", text, re.S)
    return json.loads(m.group(1)) if m else None


def resolve_bounded(host, port, timeout=3.0):
    """Resolve host to an IPv4 with a hard time budget (returns None on timeout).

    The system resolver can block indefinitely when the AC black-holes DNS,
    so the lookup runs in a daemon thread.
    """
    result = []
    def lookup():
        try:
            result.append(socket.getaddrinfo(host, port, socket.AF_INET)[0][4][0])
        except OSError:
            pass
    threading.Thread(target=lookup, daemon=True).start()
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if result:
            return result[0]
        time.sleep(0.1)
    return None
def default_iface():
    """Name of the interface carrying the default route (None if unavailable)."""
    try:
        route = subprocess.run(["ip", "route"],
                               capture_output=True, text=True, timeout=3).stdout
        for line in route.splitlines():
            if line.startswith("default"):
                parts = line.split()
                return parts[parts.index("dev") + 1]
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        pass
def _first_global_v4_ifaces():
    """Interfaces with a global IPv4, virtual/bridge interfaces excluded."""
    skip = ("docker", "veth", "br-", "tailscale", "tailscale0", "tun", "tap",
            "Meta", "lo", "kube")
    try:
        out = subprocess.run(["ip", "-o", "-4", "addr", "show"],
                             capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    ifaces = []
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 4 and "inet" in p:
            name = p[1]
            if name.startswith(skip):
                continue
            ifaces.append(name)
    return ifaces


def default_gateway():
    try:
        route = subprocess.run(["ip", "route"],
                               capture_output=True, text=True, timeout=3).stdout
        for line in route.splitlines():
            if line.startswith("default"):
                parts = line.split()
                if "via" in parts:
                    return parts[parts.index("via") + 1]
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        pass
    return None


def _read_mac(name):
    try:
        with open(f"/sys/class/net/{name}/address") as f:
            return f.read().strip()
    except OSError:
        return ""


def portal_endpoint(retries=15, retry_delay=20.0):
    """Return a reachable portal endpoint ('ip') on PORTAL_PORT, or None.

    Tries (per round): DNS result (bounded), default gateway, known campus
    and public portal IPs -- each with a short TCP probe. After a logout the
    AC black-holes the client (portal included) for a short window, so the
    whole round is retried a few times before giving up.
    """
    for attempt in range(retries):
        seen = []
        cands = []
        ip = resolve_bounded(PORTAL_HOST, PORTAL_PORT, timeout=3.0)
        if ip:
            cands.append(ip)
        cands.append(default_gateway())
        cands.extend(PORTAL_IP_CANDIDATES)
        for cand in cands:
            if not cand or cand in seen:
                continue
            seen.append(cand)
            try:
                s = socket.create_connection((cand, PORTAL_PORT), timeout=2)
                s.close()
                return cand
            except OSError:
                continue
        if attempt < retries - 1:
            print(f"Portal unreachable (AC block window?), retrying in "
                  f"{retry_delay:.0f}s... ({attempt + 1}/{retries - 1})")
            time.sleep(retry_delay)
    return None

def detect_network_info():
    """Detect local IP/MAC/IPv6 and whether we are in the unauthenticated state.

    Returns {"ip", "ipv6", "mac", "blocked"} or None if the IP could not be found.
    """
    info = {"ip": "", "ipv6": "", "mac": "", "blocked": None}

    try:
        iface = default_iface()
        if not iface:
            alts = _first_global_v4_ifaces()
            iface = alts[0] if alts else None
        if iface:
            info["mac"] = _read_mac(iface)
            out = subprocess.run(["ip", "-o", "-4", "addr", "show", "dev", iface],
                                 capture_output=True, text=True, timeout=3).stdout
            for line in out.splitlines():
                p = line.split()
                if "inet" in p:
                    info["ip"] = p[p.index("inet") + 1].split("/")[0]
                    break
            # Global IPv6 on the same interface (skip link-local fe80::/10).
            out6 = subprocess.run(["ip", "-o", "-6", "addr", "show", "dev", iface],
                                  capture_output=True, text=True, timeout=3).stdout
            for line in out6.splitlines():
                p = line.split()
                if "inet6" in p:
                    addr = p[p.index("inet6") + 1].split("/")[0]
                    if not addr.startswith("fe80") and addr not in ("::", "ff00::"):
                        info["ipv6"] = addr
                        break
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        pass
    if not info["ip"]:
        # Fallback (no `ip` binary, e.g. macOS): UDP connect trick (no packets sent).
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.connect((PORTAL_HOST, PORTAL_PORT))
            info["ip"] = s.getsockname()[0]
            s.close()
        except OSError:
            return None
    if not info["mac"]:
        import uuid
        info["mac"] = "%012x" % uuid.getnode()
    info["mac"] = info["mac"].replace(":", "").lower()

    info["blocked"] = probe_blocked()
    return info


def probe_blocked():
    """True when the AC is intercepting (302) or black-holing traffic.

    False means the client is currently passed through (online).
    Resolves the probe host with a bounded wait; on DNS failure assumes blocked.
    """
    ip = resolve_bounded(PROBE_HOST, 80, timeout=3.0)
    if not ip:
        return True
    opener = urllib.request.build_opener(_NoRedirect())
    req = urllib.request.Request(f"http://{ip}/", headers={"User-Agent": "curl/8.0"})
    try:
        opener.open(req, timeout=4)
        return False
    except urllib.error.HTTPError as e:
        return e.code == 302
    except (urllib.error.URLError, OSError):
        return True


def http_get(url, timeout=10):
    """GET url (TLS verified-False); returns body text or raises OSError."""
    try:
        with urllib.request.urlopen(url, timeout=timeout, context=SSL_CTX) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", "replace")


def portal_url(path, qs):
    """Build the portal URL on a reachable endpoint (DNS or fallback IP)."""
    host = portal_endpoint()
    if not host:
        return None
    return f"https://{host}:{PORTAL_PORT}{path}?{qs}"


def login(username, password):
    info = detect_network_info()
    if info is None:
        print("Error: could not determine local IP. Are you on the campus network?")
        return 1

    print(f"Detected: ip={info['ip']} ipv6={info['ipv6']} mac={info['mac']} "
          f"blocked={info['blocked']}")
    if not info["blocked"]:
        print("Already online; sending login anyway (session refresh).")

    key = get_key("drcom")  # 119
    params = [
        ("callback", "dr1003"),
        ("login_method", "1"),
        ("user_account", username),
        ("user_password", password),
        ("wlan_user_ip", info["ip"]),
        ("wlan_user_ipv6", info["ipv6"]),
        ("wlan_user_mac", info["mac"]),
        ("wlan_ac_ip", ""),
        ("wlan_ac_name", ""),
        ("jsVersion", "4.3"),
    ]
    qs = "&".join(f"{k}={enc_pwd(v, key)}" for k, v in params) + "&encrypt=1&v=1234&lang=zh"
    url = portal_url(LOGIN_PATH, qs)
    if not url:
        print("Error: portal unreachable (DNS and known IPs failed).")
        return 1

    try:
        body = http_get(url)
    except (urllib.error.URLError, OSError) as e:
        print(f"Error: {e}")
        return 1

    data = jsonp_body(body)
    if data is None:
        print(f"Unexpected response: {body[:200]}")
        return 1
    msg = data.get("msg", "")
    print(f"Response: {msg}")
    if msg.startswith("Welcome to Drcom System") or "认证成功" in msg:
        print("Login succeeded.")
        return 0
    print("Login failed.")
    return 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 login.py <username> <password>")
        sys.exit(1)
    sys.exit(login(sys.argv[1], sys.argv[2]))
