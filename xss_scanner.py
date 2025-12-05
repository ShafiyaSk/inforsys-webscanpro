import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class XSSScanner:

    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.tested_urls = []
        self.vulnerable_urls = []

        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>"
        ]

    # ---------------- LOGIN DVWA ----------------
    def login_dvwa(self):
        login_url = "http://localhost:8080/login.php"

        data = {
            "username": "admin",
            "password": "password",
            "Login": "Login"
        }

        r = self.session.post(login_url, data=data)

        if "Login failed" not in r.text:
            print("[✅] DVWA Login Successful")
            return True
        return False

    # ---------------- FIND FORM ----------------
    def discover_forms(self):
        print("[*] Discovering forms...")

        r = self.session.get(self.base_url)
        soup = BeautifulSoup(r.text, "html.parser")

        forms = soup.find_all("form")

        print(f"[+] {len(forms)} form(s) found ✅")
        return forms

    # ---------------- TEST XSS ----------------
    def test_xss(self, forms):
        print("\n[*] Starting XSS Testing...\n")

        for form in forms:
            action = form.get("action")
            target = urljoin(self.base_url, action)
            method = form.get("method", "post")

            print(f"[*] Testing → {target}")

            inputs = form.find_all("input")

            for payload in self.payloads:
                data = {}

                for i in inputs:
                    name = i.get("name")
                    if name:
                        data[name] = payload

                if method.lower() == "post":
                    r = self.session.post(target, data=data)
                else:
                    r = self.session.get(target, params=data)

                self.tested_urls.append(target)

                # ✅ Check if payload is reflected
                if payload in r.text:
                    print(f"\n🔥 XSS VULNERABLE FOUND!")
                    print(f"Payload: {payload}")
                    print(f"URL: {target}\n")

                    self.vulnerable_urls.append(target)
                    return

        print("✅ No XSS detected.")

    # ---------------- REPORT ----------------
    def report(self):
        print("\n━━━━━━━━━━━━━━━━ REPORT ━━━━━━━━━━━━━━━━\n")
        print(f"✅ Pages Tested : {len(self.tested_urls)}")

        if self.vulnerable_urls:
            print(f"🔥 Vulnerabilities Found : {len(self.vulnerable_urls)}")
            for url in self.vulnerable_urls:
                print(f"⚠ {url}")
        else:
            print("🛡 No vulnerabilities detected")


# ---------------- MAIN ----------------
if __name__ == "__main__":

    print("\n[*] Starting XSS Scanner...\n")

    # THIS IS THE CORRECT URL
    target = "http://localhost:8080/vulnerabilities/xss_s/"

    scanner = XSSScanner(target)

    if scanner.login_dvwa():
        forms = scanner.discover_forms()
        scanner.test_xss(forms)
        scanner.report()
