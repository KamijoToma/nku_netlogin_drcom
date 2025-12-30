
import requests
import hashlib
import sys
import time
import re
from urllib.parse import urlparse, parse_qs
import base64

def get_key(secret_key):
    ret = 0
    for char in secret_key:
        ret ^= ord(char)
    return ret

def enc_pwd(password, key):
    pass_out = ""
    if not password:
        return pass_out
    for char in str(password):
        ch = ord(char) ^ key
        hex_str = hex(ch)[2:]
        if len(hex_str) == 1:
            hex_str = "0" + hex_str
        pass_out += hex_str
    return pass_out

def calc_md5(password):
    pid = '1'
    calg = '12345678'
    tmp = pid + password + calg
    md5_hash = hashlib.md5(tmp.encode()).hexdigest()
    return md5_hash + calg + pid

def detect_network_info():
    print("Detecting network info...")
    try:
        # Use a non-HTTPS URL to trigger portal redirection
        response = requests.get("http://www.baidu.com", allow_redirects=False, timeout=5)
        if response.status_code == 302 and "Location" in response.headers:
            location = response.headers["Location"]
            print(f"Redirected to: {location}")
            parsed = urlparse(location)
            qs = parse_qs(parsed.query)
            
            info = {
                "wlan_user_ip": qs.get("wlanuserip", [""])[0],
                "wlan_ac_name": qs.get("wlanacname", [""])[0],
                "wlan_ac_ip": qs.get("nasip", [""])[0],
                "wlan_user_mac": qs.get("wlanusermac", ["000000000000"])[0] 
            }
            if not info["wlan_user_mac"]:
                 info["wlan_user_mac"] = "000000000000"
                 
            print(f"Detected info: {info}")
            return info
        else:
            print("No redirection detected. You might be already logged in or not connected to the campus network.")
            return None
    except Exception as e:
        print(f"Error detecting network info: {e}")
        return None

def login(username, password, enable_md5=False):
    info = detect_network_info()
    if not info:
        print("Using fallback values...")
        # NOTE: Fallback values - will be overridden if network redirection is detected
        ip = "0.0.0.0"
        mac = "000000000000"
        wlanacname = ""
    else:
        ip = info["wlan_user_ip"]
        mac = info["wlan_user_mac"]
        wlanacname = info["wlan_ac_name"]
    
    if enable_md5:
        upass = calc_md5(password)
        r2 = '1'
    else:
        upass = password
        r2 = ''

    url = "https://netauth.nankai.edu.cn:804/eportal/portal/login"
    
    params = {
        "callback": "dr" + str(int(time.time())),
        "DDDDD": username,
        "upass": upass,
        "0MKKey": "123456",
        "R1": "0",
        "R2": r2,
        "R3": "0",
        "R6": "0",
        "para": "00",
        "v6ip": "",
        "terminal_type": "1",
        "lang": "zh-cn",
        "jsVersion": "4.1",
        "v": str(int(time.time())),
    }
    
    extra_params = {
        "user_account": username,
        "user_password": password,
        "wlan_user_ip": ip,
        "wlan_user_ipv6": "",
        "wlan_user_mac": mac,
        "wlan_ac_ip": "", 
        "wlan_ac_name": wlanacname,
        "jsVersion": "4.1",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    params.update(extra_params)
    
    # Encryption logic
    secret_key = 'drcom'
    key = get_key(secret_key)
    
    encrypted_params = {}
    for k, v in params.items():
        if k == "callback" or k == "v": 
            pass
        encrypted_params[k] = enc_pwd(v, key)
        
    encrypted_params['encrypt'] = '1'
    
    final_params = encrypted_params
    final_params['v'] = str(int(time.time()))
    
    print(f"Logging in to {url} with user {username}...")
    try:
        response = requests.get(url, params=final_params, verify=False)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        
        if "result" in response.text:
             print("Login request sent.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python login.py <username> <password>")
        sys.exit(1)
    
    username = sys.argv[1]
    password = sys.argv[2]
    login(username, password)
