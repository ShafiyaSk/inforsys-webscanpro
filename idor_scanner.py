import re
import time
import requests
from urllib.parse import urlparse, parse_qs
import json
import os

def get_session():
    s = requests.Session()
    s.headers.update({"User-Agent": "IDOR-Scanner/1.0"})
    return s

class IDORScanner:
    def __init__(self, session=None, timeout=10):
        self.session = session or get_session()
        self.timeout = timeout
        self.findings = []

    def find_numeric_params(self, url):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        params = {}
        for key, value in query.items():
            if value and re.match(r'^\d+$', value[0]):
                params[key] = int(value[0])
        return params

    def test_url_numeric_ids(self, url):
        params = self.find_numeric_params(url)
        if not params:
            return
        base = url.split('?')[0]
        for name, orig in params.items():
            for candidate in [orig - 1, orig + 1, orig + 2, orig + 10]:
                if candidate <= 0:
                    continue
                new_params = params.copy()
                new_params[name] = candidate
                try:
                    r = self.session.get(base, params=new_params, timeout=self.timeout)
                    if r.status_code == 200 and len(r.text) > 50:
                        self.findings.append({
                            "tested_url": base,
                            "parameter": name,
                            "tested_value": candidate,
                            "status": f"HTTP 200 | Content length: {len(r.text)}"
                        })
                except Exception as e:
                    print(f"[!] Error testing {url}: {e}")
                time.sleep(0.1)

    def run(self, pages, forms):
        self.findings = []
        for url in pages.keys():
            self.test_url_numeric_ids(url)
        return self.findings

if __name__ == "__main__":
    scanner = IDORScanner()

    pages = {
        "http://localhost:8080/DVWA/vulnerabilities/idor/?id=1": "",
        "http://localhost:8080/DVWA/vulnerabilities/view_source.php?id=5": ""
    }

    results = scanner.run(pages, {})

    # Save JSON
    with open("idor_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\n✅ SCAN COMPLETE")
    print("📝 IDOR results saved to idor_results.json")
