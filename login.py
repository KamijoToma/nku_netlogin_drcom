#!/usr/bin/env python3
"""NKU campus network (Dr.COM ePortal) login tool.

Protocol verified live on the campus VLAN (LicheePi 4A, Aug 2026):

- Endpoint:  https://netauth.nankai.edu.cn:804/eportal/portal/login
- Every parameter value is XOR-119-hex encoded (key = 'd'^'r'^'c'^'o'^'m' = 0x77),
  followed by the plaintext suffix  encrypt=1&v=1234&lang=zh
- Success:   dr1003({"result":0,"msg":"Welcome to Drcom System:<nas>","ret_code":1});
- Failure:   msg "统一身份认证验证失败" (wrong password)
             or "无法获取用户认证账号!" (account not found / undecodable)
- The account is the plain student ID (e.g. 1234567890); email forms are rejected.
- Standard library only (no third-party dependencies).
"""

import json
import re
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

PORTAL_HOST = "netauth.nankai.edu.cn"
PORTAL_PORT = 804
LOGIN_URL = f"https://{PORTAL_HOST}:{PORTAL_PORT}/eportal/portal/login"
PROBE_URL = "http://www.baidu.com"

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


def probe_blocked():
    """True when the AC is intercepting (302) or black-holing traffic.

    False means the client is currently passed through (online).
    """
    opener = urllib.request.build_opener(_NoRedirect())
    req = urllib.request.Request(PROBE_URL, headers={"User-Agent": "curl/8.0"})
    try:
        opener.open(req, timeout=5)
        return False
    except urllib.error.HTTPError as e:
        return e.code == 302
    except (urllib.error.URLError, OSError):
        return True


def _read_mac(name):
    try:
        with open(f"/sys/class/net/{name}/address") as f:
            return f.read().strip()
    except OSError:
        return ""


def detect_network_info():
    """Detect local IP/MAC/IPv6 and whether we are in the unauthenticated state.

    Returns {"ip", "ipv6", "mac", "blocked"} or None if the IP could not be found.
    """
    info = {"ip": "", "ipv6": "", "mac": "", "blocked": None}

    # Source IPv4 of the interface reaching the campus portal (UDP connect trick:
    # no packets are actually sent).
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((PORTAL_HOST, PORTAL_PORT))
        info["ip"] = s.getsockname()[0]
        s.close()
    except OSError:
        pass
    if not info["ip"]:
        return None

    # MAC + global IPv6 from the OS (Linux /sys, graceful fallback).
    try:
        out = subprocess.run(["ip", "-o", "addr", "show"],
                             capture_output=True, text=True, timeout=3).stdout
        for line in out.splitlines():
            if " inet " in line and info["ip"] in line:
                info["mac"] = _read_mac(line.split()[1])
                break
        for line in out.splitlines():
            if " inet6 " in line:
                addr = line.split()[2].split("/")[0]
                if not addr.startswith("fe80"):
                    info["ipv6"] = addr
                    break
    except (OSError, subprocess.SubprocessError):
        pass
    if not info["mac"]:
        import uuid
        info["mac"] = "%012x" % uuid.getnode()
    info["mac"] = info["mac"].replace(":", "").lower()

    info["blocked"] = probe_blocked()
    return info


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
    url = LOGIN_URL + "?" + qs

    try:
        with urllib.request.urlopen(url, timeout=10, context=SSL_CTX) as r:
            body = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        print(f"Error: {e}")
        return 1

    data = jsonp_body(body)
    if data is None:
        print(f"Unexpected response: {body[:200]}")
        return 1
    msg = data.get("msg", "")
    print(f"Response: {msg}")
    if msg.startswith("Welcome to Drcom System"):
        print("Login succeeded.")
        return 0
    print("Login failed.")
    return 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 login.py <username> <password>")
        sys.exit(1)
    sys.exit(login(sys.argv[1], sys.argv[2]))
