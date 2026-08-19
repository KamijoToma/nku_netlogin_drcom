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

import ipaddress
import json
import os
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

# Known campus-internal AC gateway, used when DNS is unreachable (e.g. the
# AC black-holes it). The public VIP 222.30.38.234 is NOT here on purpose:
# it runs a separate session DB and cannot affect the campus VLAN session
# (see TECHNICAL_DOCS.md), so it must never carry campus credentials.
PORTAL_IP_CANDIDATES = ["198.18.0.7"]

# Portal instances that must never receive campus login/logout requests.
PUBLIC_PORTAL_IPS = frozenset({"222.30.38.234"})

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
    """Parse the JSON object out of a JSONP response like dr1003({...});

    Returns None for non-JSONP input and for malformed JSON (truncated or
    proxied error pages), so callers take the "Unexpected response" path
    instead of crashing on JSONDecodeError.
    """
    m = re.search(r"\((\{.*\})\)", text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return None


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
def route_iface(target_ip):
    """(iface, src) of the route toward target_ip, per `ip route get`.

    `ip route get <ip>` asks the kernel for the route to the actual portal,
    so TUN/proxy interfaces shadowing the plain default route cannot divert
    the detected identity. (None, None) when unavailable.
    """
    try:
        out = subprocess.run(["ip", "route", "get", target_ip],
                             capture_output=True, text=True, timeout=3).stdout
        parts = out.split()
        dev = parts[parts.index("dev") + 1] if "dev" in parts else None
        src = parts[parts.index("src") + 1] if "src" in parts else None
        return dev, src
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        return None, None


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
    return None


def _first_global_v4_ifaces():
    """Interfaces with a global IPv4, virtual/bridge interfaces excluded."""
    skip = ("docker", "veth", "br-", "tailscale", "tailscale0", "tun", "tap",
            "Meta", "lo", "kube")
    try:
        out = subprocess.run(["ip", "-o", "-4", "addr", "show", "scope", "global"],
                             capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    ifaces = []
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 4 and "inet" in p:
            name = p[1]
            if name.startswith(skip) or name in ifaces:
                continue
            try:
                addr = ipaddress.ip_address(p[p.index("inet") + 1].split("/")[0])
            except ValueError:
                continue
            if addr.is_link_local or addr.is_loopback:
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


def portal_candidates():
    """Ordered, deduplicated portal endpoint candidates.

    Order: bounded DNS answer, known campus AC IPs, default gateway last
    (off-campus the gateway is attacker territory; on-campus it is rarely
    the portal). Public portal instances (separate session DB) are always
    excluded, even when DNS resolves to them.
    """
    cands, seen = [], set()

    def add(ip):
        if ip and ip not in seen and ip not in PUBLIC_PORTAL_IPS:
            seen.add(ip)
            cands.append(ip)

    add(resolve_bounded(PORTAL_HOST, PORTAL_PORT, timeout=3.0))
    for ip in PORTAL_IP_CANDIDATES:
        add(ip)
    add(default_gateway())
    return cands


# Hard total budget for endpoint probing + request retries. The AC
# black-holes the client (portal included) for a short window after a
# logout, so requests are retried until this deadline.
PORTAL_BUDGET = 300.0


def portal_request(path, qs, budget=PORTAL_BUDGET, retry_delay=20.0):
    """GET path?qs from a reachable portal endpoint; return body or None.

    A candidate only counts when the actual HTTPS request succeeds: the AC
    can pass TCP SYNs while dropping HTTP payloads (see TECHNICAL_DOCS.md),
    so TCP-only probing would skip the very block window the retries exist
    for. All waiting is truncated to the total budget.
    """
    url = f":{PORTAL_PORT}{path}?{qs}"
    deadline = time.monotonic() + budget
    attempt = 0
    while True:
        attempt += 1
        if time.monotonic() >= deadline:
            return None
        for cand in portal_candidates():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                s = socket.create_connection((cand, PORTAL_PORT),
                                             timeout=min(2.0, remaining))
                s.close()
            except OSError:
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                return http_get(f"https://{cand}{url}",
                                timeout=min(10.0, remaining))
            except OSError:
                continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        delay = min(retry_delay, remaining)
        print(f"Portal unreachable (AC block window?), retrying in "
              f"{delay:.0f}s... (round {attempt})")
        time.sleep(delay)

def detect_network_info():
    """Detect local IP/MAC/IPv6 and whether we are in the unauthenticated state.

    Returns {"ip", "ipv6", "mac", "blocked"} or None if the IP could not be found.
    """
    info = {"ip": "", "ipv6": "", "mac": "", "blocked": None}

    try:
        # Egress toward the first trusted portal candidate (DNS answer is
        # filtered, TUN/proxy-proof); falls back to the plain default route,
        # then to any global-IPv4 interface.
        iface = None
        targets = portal_candidates()
        if targets:
            iface, src = route_iface(targets[0])
            if iface and src:
                info["ip"] = src
        if not iface:
            iface = default_iface()
        if not iface:
            alts = _first_global_v4_ifaces()
            iface = alts[0] if alts else None
        if iface:
            info["mac"] = _read_mac(iface)
            if not info["ip"]:
                out = subprocess.run(["ip", "-o", "-4", "addr", "show", "dev", iface],
                                     capture_output=True, text=True, timeout=3).stdout
                for line in out.splitlines():
                    p = line.split()
                    if "inet" in p:
                        cand = p[p.index("inet") + 1].split("/")[0]
                        try:
                            addr = ipaddress.ip_address(cand)
                        except ValueError:
                            continue
                        if addr.is_link_local or addr.is_loopback:
                            continue
                        info["ip"] = cand
                        break
            # Global IPv6 on the same interface (skip link-local fe80::/10).
            out6 = subprocess.run(["ip", "-o", "-6", "addr", "show", "dev", iface],
                                  capture_output=True, text=True, timeout=3).stdout
            for line in out6.splitlines():
                p = line.split()
                if "inet6" in p:
                    addr = p[p.index("inet6") + 1].split("/")[0]
                    try:
                        ip6 = ipaddress.ip_address(addr)
                    except ValueError:
                        continue
                    if ip6.is_link_local or ip6.is_loopback \
                            or ip6.is_unspecified or ip6.is_multicast:
                        continue
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
    body = portal_request(LOGIN_PATH, qs)
    if body is None:
        print("Error: portal unreachable (DNS and known IPs failed).")
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


def cli_credentials(argv):
    """(username, password) from argv, falling back to NKU_USERNAME/NKU_PASSWORD.

    argv takes precedence; (None, None) when neither source provides both,
    or when extra positional arguments are given (mirrors the original
    exact-argc CLI contract).
    """
    if len(argv) > 3:
        return None, None
    user = argv[1] if len(argv) > 1 else os.environ.get("NKU_USERNAME")
    password = argv[2] if len(argv) > 2 else os.environ.get("NKU_PASSWORD")
    return user, password


if __name__ == "__main__":
    username, password = cli_credentials(sys.argv)
    if not username or not password:
        print("Usage: python3 login.py <username> <password>")
        print("   or: NKU_USERNAME=... NKU_PASSWORD=... python3 login.py")
        sys.exit(1)
    sys.exit(login(username, password))
