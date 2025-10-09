"""
@author: Duy Vuong & Skochilov Ignat
wifi_connect.py

Windows-only: scan Wi-Fi networks and connect to a given SSID using netsh.

Usage examples:
  python wifi_windows.py --scan
  python wifi_windows.py --connect --ssid MyNetwork --password MyPass
"""

import subprocess
import shlex
import re
import tempfile
import os
import time
import argparse
from typing import List, Dict, Optional
from xml.sax.saxutils import escape


def run(cmd: str, timeout: int = 20) -> subprocess.CompletedProcess:
    """Run a command and return CompletedProcess (text mode)."""
    # Use shell=False via shlex.split for safety
    return subprocess.run(shlex.split(cmd), capture_output=True, text=True, errors="replace", timeout=timeout)

def parse_netsh_networks(output: str, patern: str) -> List[Dict[str, str]]:
    """
    Parse output of `netsh wlan show networks mode=Bssid` (English format expected).
    Returns list of dicts: {"ssid":..., "signal":..., "authentication":...}
    """
    networks = []
    current = None

    # Split lines and process; handle inconsistent whitespace/locale by heuristics
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue

        # SSID line, e.g. "SSID 1 : MyNetwork"
        m = re.match(r"^SSID\s+\d+\s*:\s*(.+)$", line, flags=re.IGNORECASE)
        if m:
            ssid = m.group(1).strip()
            # Start a new network entry
            if patern is None:
                current = {"ssid": escape(ssid), "signal": "", "authentication": ""}
                networks.append(current)
            elif patern and ssid.startswith(patern):
                current = {"ssid": escape(ssid), "signal": "", "authentication": ""}
                networks.append(current)
            else:
                current = None
                continue

        # Signal line, e.g. "Signal : 88%"
        m = re.match(r"^Signal\s*:\s*(.+)$", line, flags=re.IGNORECASE)
        if m and current is not None:
            current["signal"] = m.group(1).strip()
            continue

        # Authentication line, e.g. "Authentication : WPA2-Personal"
        m = re.match(r"^Authentication\s*:\s*(.+)$", line, flags=re.IGNORECASE)
        if m and current is not None:
            current["authentication"] = m.group(1).strip()
            continue

        # Fallback: some localized outputs don't use English keys.
        # If line contains ":" we attempt to map by proximity: if current exists and values empty, try fill.
        if ":" in line and current is not None:
            key, val = [p.strip() for p in line.split(":", 1)]
            # Heuristic: if key looks numeric or starts with "SSID", skip
            if re.search(r"ssid", key, flags=re.IGNORECASE):
                continue
            # Try guess: if value contains '%' -> signal
            if "%" in val and not current.get("signal"):
                current["signal"] = val
            # If value contains "WPA" or "Personal" or "WEP" etc -> authentication
            elif re.search(r"wpa|wep|open|personal|enterprise", val, flags=re.IGNORECASE) and not current.get("authentication"):
                current["authentication"] = val

    return networks

def scan_networks_windows(patern: str=None) -> List[Dict[str, str]]:
    """Run netsh and parse available networks."""
    try:
        cp = run('netsh wlan show networks mode=Bssid')
    except subprocess.TimeoutExpired:
        raise RuntimeError("netsh timed out")
    if cp.returncode != 0:
        raise RuntimeError(f"netsh returned error: {cp.stderr.strip() or cp.stdout.strip()}")

    out = cp.stdout
    networks = parse_netsh_networks(out, patern)
    for network in networks:
        if network['signal'] == '100%':
            return [network]
   # return networks

def list_interfaces() -> list[dict]:
    cp = run("netsh interface show interface")
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr or cp.stdout)
    lines = cp.stdout.splitlines()
    items = []
    for ln in lines[3:]:
        if not ln.strip():
            continue
        parts = [p for p in re.split(r"\s{2,}", ln.strip()) if p]
        if len(parts) >= 4:
            items.append({"admin_state": parts[0], "state": parts[1], "type": parts[2], "name": parts[3]})
    return items

def guess_wifi_interface_name() -> str | None:
    for it in list_interfaces():
        n = it["name"]
        if re.search(r"wi-?fi|wlan|wireless", n, re.IGNORECASE):
            return n
    return None

def verify_connected(ssid: str, iface: str | None = None) -> bool:
    # Đọc trạng thái interface để chắc chắn đang "Connected" vào đúng SSID
    cmd = "netsh wlan show interfaces"
    if iface:
        cmd += f' interface="{iface}"'
    cp = run(cmd)
    if cp.returncode != 0:
        return False
    txt = cp.stdout
    # print(txt)
    # State : connected  AND  SSID : <name>
    state_ok = re.search(r"^\s*State\s*:\s*connected\b", txt, re.IGNORECASE | re.MULTILINE)
    ssid_ok = re.search(rf"^\s*SSID\s*:\s*{re.escape(ssid)}\b", txt, re.IGNORECASE | re.MULTILINE)
    if (state_ok and ssid_ok):
        return True
    return False

def add_temp_profile_xml(ssid: str, password: str) -> str:
    # Tạo profile WPA2-Personal tạm (plaintext passphrase trong XML tạm)
    safe_ssid = escape(ssid)
    safe_pass = escape(password)
    profile_xml = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{safe_ssid}</name>
  <SSIDConfig>
    <SSID><name>{safe_ssid}</name></SSID>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM>
    <security>
      <authEncryption>
        <authentication>WPA2PSK</authentication>
        <encryption>AES</encryption>
        <useOneX>false</useOneX>
      </authEncryption>
      <sharedKey>
        <keyType>passPhrase</keyType>
        <protected>false</protected>
        <keyMaterial>{safe_pass}</keyMaterial>
      </sharedKey>
    </security>
  </MSM>
</WLANProfile>"""
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".xml", encoding="utf-8") as f:
        f.write(profile_xml)
        return f.name

def profile_exists(ssid: str) -> bool:
    cp = run("netsh wlan show profiles")
    if cp.returncode != 0:
        raise RuntimeError(cp.stderr or cp.stdout)
    return bool(re.search(rf'All User Profile\s*:\s*{re.escape(ssid)}\s*$', cp.stdout, re.MULTILINE))

def connect_network_windows(ssid: str, password: Optional[str] = None, save_on_success=False) -> bool:
    """
    Attempt to connect to SSID.
    - Tries `netsh wlan connect name="<ssid>" ssid="<ssid>"` first (works if there is a profile).
    - If that fails and password provided, create a WPA2-Personal profile XML, add it and connect.
    Returns True on success, raises RuntimeError on failure.
    """
    iface = guess_wifi_interface_name()

    # 1) Try direct connect (if profile exists)
    if profile_exists(ssid):
        print(iface)
        cp = run(f'netsh wlan connect name="{ssid}" ssid="{ssid}"')
        time.sleep(0.5)
        if cp.returncode == 0 and verify_connected(ssid, iface):
            # print("Connected using existing profile.")
            return True
        else:
            # print('Failed to connect using existing profile (wrong password?)')
            return False

    # 2) If profile not found and password provided, create profile XML (WPA2-Personal)
    if not password:
        return False

    xml_path = add_temp_profile_xml(ssid, password)
    try:
        cp_add = run(f'netsh wlan add profile filename="{xml_path}" user=all')
        if cp_add.returncode != 0:
            # print(f'Failed to add temporary profile: {cp_add.stderr.strip() or cp_add.stdout.strip()}')
            return False

        cp_conn = run(f'netsh wlan connect name="{ssid}" ssid="{ssid}" interface="{iface}"')
        time.sleep(0.5)  # wait a bit for connection to establish
        out2 = (cp_conn.stdout or "") + (cp_conn.stderr or "")

        # XÁC MINH THỰC SỰ ĐÃ KẾT NỐI
        if cp_conn.returncode == 0 and verify_connected(ssid, iface):
            # Kết nối ok. Nếu không muốn lưu, xóa profile ngay.
            # if not save_on_success:
            #     run(f'netsh wlan delete profile name="{ssid}"')
            return True
        else:
            # Kết nối không thành công ⇒ xóa profile tạm để không lưu mật khẩu
            run(f'netsh wlan delete profile name="{ssid}"')
            # print('Failed to connect using existing profile (wrong password?)')
            return False
    finally:
        # Xóa file XML tạm (không ảnh hưởng profile đã add)
        try:
            os.remove(xml_path)
        except Exception:
            pass


def get_default_gateway() -> str|None:
    """
    Получает полную информацию о конкретном интерфейсе
    """
    try:
        interface = guess_wifi_interface_name()
        result = run(f"netsh interface ip show config name={interface}")

        if result.returncode != 0:
            print(f"Ошибка: Интерфейс '{interface}' не найден")
            return None

        lines = result.stdout.split('\n')
        for line in lines:
            if 'основной шлюз' in line.lower() or 'default gateway' in line.lower():
                # Ищем IP-адрес в строке
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    return ip_match.group(1)

        return None

    except Exception as e:
        print(f"Ошибка: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(prog="wifi_windows.py")
    parser.add_argument("--scan", action="store_true", help="Scan available Wi-Fi networks")
    parser.add_argument("--patern", default=None, help="Pattern to match Wi-Fi networks")
    parser.add_argument("--connect", action="store_true", help="Connect to a network")
    parser.add_argument("--ssid", type=str, help="SSID to connect")
    parser.add_argument("--password", type=str, help="Password for the SSID (WPA2)")
    args = parser.parse_args()

    if args.scan:
        try:
            nets = scan_networks_windows(args.patern)
            if not nets:
                print("No networks found (parsed). You may need to run command prompt as Administrator or use English locale for accurate parsing.")
            for i, n in enumerate(nets, 1):
                print(f"{i}. SSID: {n['ssid']!s} | Signal: {n.get('signal','')} | Authentication: {n.get('authentication','')}")
        except Exception as e:
            print("Scan failed:", e)

    elif args.connect:
        if not args.ssid:
            parser.error("--connect requires --ssid")
        try:
            ok = connect_network_windows(args.ssid, password=args.password)
            print("Connected successfully." if ok else "Failed to connect.")
        except Exception as e:
            print("Connect failed:", e)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
    # verify_connected("Redmi Note 11", "Wi-Fi")
    # res = scan_networks_windows("Redmi")
    # print(res)