#!/usr/bin/env python3
"""NKU campus network (Dr.COM ePortal) logout tool.

Protocol verified live on the campus VLAN (LicheePi 4A, Aug 2026):

- Endpoint:  https://netauth.nankai.edu.cn:804/eportal/portal/logout
- Same XOR-119-hex encoding as login, plaintext suffix encrypt=1&v=1234&lang=zh
- The REAL password is required (a dummy value does not terminate the session).
- Success:   dr1004({"result":1,"msg":"Radius注销成功！"});
- After a successful logout the AC black-holes the client's HTTP traffic
  (no more 302 to the portal), so the post-logout probe expects failure/302.
- Standard library only (no third-party dependencies).
"""

import sys
import urllib.error

from login import (PORTAL_PORT, detect_network_info, enc_pwd, get_key, http_get,
                   jsonp_body, portal_url, probe_blocked)

LOGOUT_PATH = "/eportal/portal/logout"


def logout(username, password):
    info = detect_network_info()
    if info is None:
        print("Error: could not determine local IP. Are you on the campus network?")
        return 1

    print(f"Detected: ip={info['ip']} mac={info['mac']} blocked={info['blocked']}")
    if info["blocked"]:
        print("Already unauthenticated; sending logout anyway (no-op safe).")

    key = get_key("drcom")  # 119
    params = [
        ("callback", "dr1004"),
        ("login_method", "1"),
        ("user_account", username),
        ("user_password", password),
        ("ac_logout", "1"),
        ("register_mode", "1"),
        ("wlan_user_ip", info["ip"]),
        ("wlan_user_ipv6", info["ipv6"]),
        ("wlan_vlan_id", "1"),
        ("wlan_user_mac", info["mac"]),
        ("wlan_ac_ip", ""),
        ("wlan_ac_name", ""),
        ("jsVersion", "4.3"),
    ]
    qs = "&".join(f"{k}={enc_pwd(v, key)}" for k, v in params) + "&encrypt=1&v=1234&lang=zh"
    url = portal_url(LOGOUT_PATH, qs)
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
    if data.get("result") == 1 and "注销成功" in msg:
        print("Logout succeeded.")
        if probe_blocked():
            print("Verified: traffic is no longer passed through.")
        else:
            print("Warning: traffic is still being passed through; "
                  "the AC may take a moment to apply the CoA.")
        return 0
    print("Logout failed (no active session or bad credentials).")
    return 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 logout.py <username> <password>")
        sys.exit(1)
    sys.exit(logout(sys.argv[1], sys.argv[2]))
