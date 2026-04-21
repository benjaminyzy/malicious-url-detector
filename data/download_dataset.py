import requests
import pandas as pd
import io
import os

RAW_DIR = os.path.join(os.path.dirname(__file__), "raw")
os.makedirs(RAW_DIR, exist_ok=True)

PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.csv"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
TRANCO_API_URL = "https://tranco-list.eu/api/lists/date/latest"
MAJESTIC_URL = "https://downloads.majestic.com/majestic_million.csv"
BENIGN_LIMIT = 5000

HEADERS = {"User-Agent": "malicious-url-detector/1.0 (research)"}


def download_phishing():
    print("Attempting PhishTank download...")
    try:
        resp = requests.get(PHISHTANK_URL, timeout=60, headers=HEADERS)
        resp.raise_for_status()
        df = pd.read_csv(io.StringIO(resp.text))
        urls = df["url"].dropna().drop_duplicates().reset_index(drop=True)
        print(f"  PhishTank: got {len(urls)} URLs")
    except Exception as e:
        print(f"  PhishTank unavailable ({e}), falling back to URLhaus...")
        resp = requests.get(URLHAUS_URL, timeout=60, headers=HEADERS)
        resp.raise_for_status()
        lines = [l for l in resp.text.splitlines() if not l.startswith("#")]
        df = pd.read_csv(io.StringIO("\n".join(lines)), header=0)
        url_col = [c for c in df.columns if "url" in c.lower()]
        if not url_col:
            raise ValueError(f"No URL column found in URLhaus data. Columns: {list(df.columns)}")
        urls = df[url_col[0]].dropna().drop_duplicates().reset_index(drop=True)
        print(f"  URLhaus: got {len(urls)} URLs")

    out = os.path.join(RAW_DIR, "phishing_urls.csv")
    urls.to_csv(out, index=False, header=["url"])
    print(f"  Saved to {out}")
    return urls


def download_benign():
    print("Downloading Tranco top sites list...")
    try:
        # Get latest list ID from Tranco API
        api_resp = requests.get(TRANCO_API_URL, timeout=30, headers=HEADERS)
        api_resp.raise_for_status()
        list_id = api_resp.json()["list_id"]
        download_url = f"https://tranco-list.eu/download/{list_id}/full"
        print(f"  Fetching Tranco list {list_id}...")
        resp = requests.get(download_url, timeout=120, headers=HEADERS)
        resp.raise_for_status()
        lines = resp.text.strip().splitlines()
        domains = []
        for line in lines:
            parts = line.split(",", 1)
            if len(parts) == 2:
                domains.append("http://" + parts[1].strip())
            if len(domains) >= BENIGN_LIMIT:
                break
        print(f"  Tranco: got {len(domains)} domains")
    except Exception as e:
        print(f"  Tranco unavailable ({e}), falling back to Majestic Million...")
        resp = requests.get(MAJESTIC_URL, timeout=120, headers=HEADERS)
        resp.raise_for_status()
        df = pd.read_csv(io.StringIO(resp.text))
        # Columns: GlobalRank, TldRank, Domain, TLD, RefSubNets, RefIPs, IDN_Domain, IDN_TLD, PrevGlobalRank, PrevTldRank, PrevRefSubNets, PrevRefIPs
        domains = ("http://" + df["Domain"].dropna()).tolist()[:BENIGN_LIMIT]
        print(f"  Majestic Million: got {len(domains)} domains")

    urls = pd.Series(domains, name="url")
    out = os.path.join(RAW_DIR, "benign_urls.csv")
    urls.to_csv(out, index=False, header=["url"])
    print(f"  Saved {len(urls)} benign URLs to {out}")
    return urls


def combine(phishing_urls, benign_urls):
    malicious = pd.DataFrame({"url": phishing_urls, "label": 1})
    benign = pd.DataFrame({"url": benign_urls, "label": 0})
    dataset = pd.concat([malicious, benign], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
    out = os.path.join(RAW_DIR, "dataset.csv")
    dataset.to_csv(out, index=False)
    print(f"\nDataset saved to {out}")
    return dataset


if __name__ == "__main__":
    phishing_urls = download_phishing()
    benign_urls = download_benign()
    dataset = combine(phishing_urls, benign_urls)
    print(f"  Malicious URLs : {(dataset['label'] == 1).sum()}")
    print(f"  Benign URLs    : {(dataset['label'] == 0).sum()}")
    print(f"  Total          : {len(dataset)}")
