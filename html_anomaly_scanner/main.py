import requests
from bs4 import BeautifulSoup
import re
import sys

def fetch_html(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"❌ Error fetching {url}: {e}")
        return None

def scan_html_for_anomalies(html):
    soup = BeautifulSoup(html, "html.parser")
    findings = []

    # 1. Suspicious JavaScript patterns
    for script in soup.find_all("script"):
        if script.string:
            js_code = script.string.lower()
            if "eval(" in js_code:
                findings.append("🔴 High: Use of `eval()` in <script> tag")
            if "fromcharcode" in js_code:
                findings.append("🟠 Medium: Obfuscated JS using `fromCharCode` in <script>")
            if "atob(" in js_code or "btoa(" in js_code:
                findings.append("🟠 Medium: Base64 encode/decode found in JS")

    # 2. Inline JavaScript event handlers
    for tag in soup.find_all(True):  # All tags
        for attr in tag.attrs:
            if attr.startswith("on"):
                snippet = str(tag)[:100].replace("\n", " ")
                findings.append(f"🟠 Medium: Inline JS event `{attr}` found in tag: {snippet}...")

    # 3. Hidden content
    for tag in soup.find_all(True):
        style = tag.get("style", "")
        if "display:none" in style or "visibility:hidden" in style:
            findings.append(f"🟡 Low: Hidden content via CSS in tag: {str(tag)[:100]}...")

    # 4. Suspicious iframes
    for iframe in soup.find_all("iframe"):
        src = iframe.get("src", "")
        if "tracker" in src or "ads" in src or "base64" in src:
            findings.append(f"🟠 Medium: Suspicious iframe source: {src}")
        else:
            findings.append(f"🟡 Low: Iframe found: {src}")

    return findings

def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <URL>")
        return

    url = sys.argv[1]
    html = fetch_html(url)
    if not html:
        return

    print(f"🔎 Scanning: {url}")
    findings = scan_html_for_anomalies(html)
    if findings:
        for issue in findings:
            print(issue)
    else:
        print("✅ No obvious anomalies found.")

if __name__ == "__main__":
    main()
