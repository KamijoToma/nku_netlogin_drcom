import requests
import time
import sys
import re
from urllib.parse import urlparse, parse_qs
from login import detect_network_info

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

def logout():
    # 1. Get Network Info
    info = detect_network_info()
    
    ip = ""
    mac = ""
    uid = "drcom" # Default
    
    if not info:
        print("Redirection not detected. Trying to fetch account page to get info...")
        try:
            resp = requests.get("https://netauth.nankai.edu.cn/", verify=False, timeout=10)
            content = resp.text
            
            ip_match = re.search(r"v4ip='([^']+)'", content)
            uid_match = re.search(r"uid='([^']+)'", content)
            
            if ip_match:
                ip = ip_match.group(1)
                print(f"Found IP from account page: {ip}")
            
            if uid_match:
                uid = uid_match.group(1)
                print(f"Found UID (Username) from account page: {uid}")
                
        except Exception as e:
            print(f"Error fetching account page: {e}")
    else:
        ip = info["wlan_user_ip"]
        mac = info["wlan_user_mac"]
        # If we are redirected, we are not logged in, so logout is moot, but maybe we want to clear session?
        pass

    if not ip:
        print("Error: Could not determine IP address. Logout might fail.")
    
    if not mac:
        mac = "000000000000"

    # 2. Prepare Params
    # Based on logout.sh analysis
    
    # Key for encryption
    secret_key = 'drcom'
    key = get_key(secret_key) # 119
    
    raw_params = {
        "callback": "dr1004",
        "login_method": "1",
        "user_account": uid, 
        "user_password": "123", # Dummy password
        "ac_logout": "1",
        "register_mode": "1",
        "wlan_user_ip": ip,
        "wlan_user_ipv6": "",
        "wlan_vlan_id": "1",
        "wlan_user_mac": mac,
        "wlan_ac_ip": "",
        "wlan_ac_name": "",
        "jsVersion": "4.3"
    }
    
    encrypted_params = {}
    for k, v in raw_params.items():
        encrypted_params[k] = enc_pwd(v, key)
        
    # Add non-encrypted params
    encrypted_params["encrypt"] = "1"
    encrypted_params["v"] = str(int(time.time())) 
    encrypted_params["lang"] = "zh"
    
    url = "https://netauth.nankai.edu.cn:804/eportal/portal/logout"
    
    print(f"Sending logout request to {url}...")
    print(f"User: {uid}, IP: {ip}, MAC: {mac}")
    
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Referer": "https://netauth.nankai.edu.cn/"
        }
        response = requests.get(url, params=encrypted_params, headers=headers, verify=False, timeout=10)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        
        if "result" in response.text or response.status_code == 200:
             print("Logout request sent.")
             
    except Exception as e:
        print(f"Error during logout: {e}")

    # Verify
    print("Verifying logout...")
    try:
        check = requests.get("http://www.baidu.com", allow_redirects=False, timeout=5)
        if check.status_code == 302:
            print("Logout verified: Redirect detected.")
        else:
            print("Logout verification failed: No redirect detected.")
    except Exception as e:
        print(f"Verification error: {e}")

if __name__ == "__main__":
    logout()
