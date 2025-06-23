import requests
from bs4 import BeautifulSoup
import re
import json
from urllib.parse import urlparse
import sys

class AnomalyScanner:
    def __init__(self, url):
        self.url = url
        self.findings = []
        self.total_score = 0

    def fetch_page(self):
        try:
            response = requests.get(self.url, timeout=15)
            response.raise_for_status()
            return response.text
        except Exception as e:
            print(f"❌ Error fetching {self.url}: {e}")
            return None

    def log(self, severity, description, context):
        risk_score = {"Low": 1, "Medium": 5, "High": 10}
        self.findings.append({
            "severity": severity,
            "description": description,
            "context": context.strip()[:150]
        })
        self.total_score += risk_score[severity]

    def scan(self, html):
        soup = BeautifulSoup(html, "html.parser")

        # Inline JS detection
        for tag in soup.find_all(True):
            for attr, val in tag.attrs.items():
                if attr.startswith("on"):
                    self.log("Medium", f"Inline JS event handler: `{attr}`", str(tag))

        # Obfuscated JS
        for script in soup.find_all("script"):
            code = script.string or ""
            if re.search(r"eval\s*\(", code):
                self.log("High", "Use of eval() in <script>", code)
            if re.search(r"fromCharCode|atob|btoa", code):
                self.log("Medium", "Obfuscation function used in <script>", code)

        # Hidden elements
        for tag in soup.find_all(True):
            style = tag.get("style", "")
            if "display:none" in style or "visibility:hidden" in style:
                self.log("Low", "Hidden element via CSS", str(tag))

        # Iframes
        for iframe in soup.find_all("iframe"):
            src = iframe.get("src", "")
            if any(word in src for word in ["ads", "tracker", "base64"]):
                self.log("Medium", "Suspicious iframe source", src)

        # External JS (suspicious domains)
        for script in soup.find_all("script", src=True):
            src = script['src']
            parsed = urlparse(src)
            if parsed.netloc and "trusted" not in parsed.netloc:
                self.log("High", f"External JS from: {src}", src)

    def report(self):
        print(f"🔍 Scan of {self.url}")
        print(f"🧮 Risk Score: {self.total_score}/100\n")
        for finding in self.findings:
            print(f"[{finding['severity']}] {finding['description']}")
            print(f" ↪ {finding['context']}\n")

    def export_json(self, filename="scan_report.json"):
        with open(filename, "w") as f:
            json.dump(self.findings, f, indent=2)
        print(f"📁 Results exported to {filename}")

# Entry point
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python anomaly_scanner.py <URL>")
        sys.exit(1)

    url = sys.argv[1]
    scanner = AnomalyScanner(url)
    html = scanner.fetch_page()

    if html:
        scanner.scan(html)
        scanner.report()
        scanner.export_json()
