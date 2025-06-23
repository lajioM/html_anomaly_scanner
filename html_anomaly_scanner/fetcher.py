import requests

def fetch_html(url):
    try:
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            return res.text
        else:
            print(f"Error: {res.status_code} on {url}")
            return ""
    except Exception as e:
        print(f"Failed to fetch {url}: {e}")
        return ""
