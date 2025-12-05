import time
from urllib.parse import urlparse, urljoin, urldefrag, parse_qs
from bs4 import BeautifulSoup
import requests


# =====================================
# Helper Utilities (Originally in utils.py)
# =====================================

class Utils:
    """Utility class for handling sessions, links, forms, and URLs."""

    @staticmethod
    def get_session():
        """Creates and returns a configured requests.Session()."""
        session = requests.Session()
        session.headers.update({
            "User-Agent": "DBWA-Crawler/1.0"
        })
        return session

    @staticmethod
    def extract_links(html, base_url):
        """Extract all <a href> links from a webpage."""
        soup = BeautifulSoup(html, "html.parser")
        links = []

        for tag in soup.find_all("a", href=True):
            full_url = urljoin(base_url, tag["href"])
            links.append(full_url)

        return links

    @staticmethod
    def extract_forms(html, base_url):
        """Extract all forms from a webpage."""
        soup = BeautifulSoup(html, "html.parser")
        forms = []

        for form in soup.find_all("form"):
            form_data = {
                "action": urljoin(base_url, form.get("action", "")),
                "method": form.get("method", "get").lower(),
                "inputs": []
            }

            for inp in form.find_all(["input", "select", "textarea"]):
                form_data["inputs"].append({
                    "name": inp.get("name"),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", "")
                })

            forms.append(form_data)

        return forms

    @staticmethod
    def normalize_url(url):
        """Remove trailing slash to standardize URL."""
        return url.rstrip('/')

    @staticmethod
    def is_same_domain(base, url):
        """Check if the URL belongs to same domain."""
        return urlparse(base).netloc == urlparse(url).netloc


# =====================================
# Main Crawler Class
# =====================================

class Crawler:
    """Web crawler for DBWA (same-domain with form extraction)."""

    def __init__(self, base_url, max_pages=200, delay=0.2, session=None):

        self.base = base_url.rstrip('/')
        self.max_pages = max_pages
        self.delay = delay
        self.session = session or Utils.get_session()

        self.visited = set()
        self.queue = [self.base]
        self.pages = {}
        self.forms = {}

    def crawl(self):

        print(f"\n[*] Starting crawl at: {self.base}\n")

        while self.queue and len(self.visited) < self.max_pages:

            # 1️⃣ Get next URL
            url = self.queue.pop(0).rstrip('/')

            # 2️⃣ Skip duplicates & external domains
            if url in self.visited:
                continue
            if not Utils.is_same_domain(self.base, url):
                continue

            # 3️⃣ Fetch page
            try:
                r = self.session.get(url, timeout=10, allow_redirects=True)
                html = r.text
            except Exception as e:
                print(f"[!] Failed to fetch {url}: {e}")
                self.visited.add(url)
                continue

            # 4️⃣ Store page & extract forms
            self.pages[url] = html
            forms = Utils.extract_forms(html, url)

            if forms:
                self.forms[url] = forms

            # 5️⃣ Extract & enqueue new links
            links = Utils.extract_links(html, url)

            for link in links:
                if not link:
                    continue

                link = urldefrag(link)[0].rstrip('/')

                if link not in self.visited and link not in self.queue:
                    if Utils.is_same_domain(self.base, link):
                        self.queue.append(link)

            # 6️⃣ Mark as visited & delay
            self.visited.add(url)
            time.sleep(self.delay)

        # 7️⃣ Return result
        return {
            "pages": self.pages,
            "forms": self.forms
        }


# =====================================
# Example Usage (DBWA)
# =====================================

if __name__ == "__main__":

    base_url = "http://localhost:8080"   
    crawler = Crawler(base_url, max_pages=20, delay=0.5)

    result = crawler.crawl()

    print("\n========== CRAWLED PAGES ==========")
    for page in result["pages"]:
        print(page)

    print("\n========== EXTRACTED FORMS ==========")
    for url, forms in result["forms"].items():
        print(f"\nURL: {url}")
        for form in forms:
            print(form)
