import io
import os
import requests
import pandas as pd
from ucimlrepo import fetch_ucirepo

RAW_DIR  = os.path.join(os.path.dirname(__file__), "raw")
OUT_PATH = os.path.join(RAW_DIR, "dataset.csv")
os.makedirs(RAW_DIR, exist_ok=True)

URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
OPENPHISH_URL   = "https://openphish.com/feed.txt"
HEADERS         = {"User-Agent": "malicious-url-detector/1.0 (research)"}

UCI_PHISHING_SAMPLE  = 20_000
UCI_BENIGN_SAMPLE    = 20_000
URLHAUS_SAMPLE_LIMIT = 10_000


# ── 1. UCI PhiUSIIL ──────────────────────────────────────────────────────────

print("Fetching UCI PhiUSIIL dataset (id=967)...")
phiusiil = fetch_ucirepo(id=967)
X = phiusiil.data.features
y = phiusiil.data.targets

url_col   = [c for c in X.columns if c.lower() == "url"][0]
label_col = list(y.columns)[0]

uci = pd.DataFrame({"url": X[url_col].values, "label": y[label_col].values})

# Map: legitimate=0, phishing=1
unique = set(uci["label"].unique())
if unique <= {1, -1}:
    uci["label"] = uci["label"].map({1: 0, -1: 1})
# If already 0/1 no mapping needed

uci = uci.dropna(subset=["url"])
uci = uci[uci["url"].str.strip() != ""]
uci = uci.drop_duplicates(subset="url")

uci_phishing  = uci[uci["label"] == 1].sample(n=UCI_PHISHING_SAMPLE, random_state=42)
uci_benign    = uci[uci["label"] == 0].sample(n=UCI_BENIGN_SAMPLE,   random_state=42)
uci_sampled   = pd.concat([uci_phishing, uci_benign], ignore_index=True)
print(f"  UCI phishing  : {len(uci_phishing)}")
print(f"  UCI benign    : {len(uci_benign)}")


# ── 2. URLhaus ───────────────────────────────────────────────────────────────

print("Downloading URLhaus malicious URLs...")
try:
    resp = requests.get(URLHAUS_CSV_URL, timeout=60, headers=HEADERS)
    resp.raise_for_status()
    # Header line starts with '# id,dateadded,url,...' — strip leading '# '
    lines, header_found = [], False
    for line in resp.text.splitlines():
        if not header_found and line.startswith("#") and "id,dateadded,url" in line:
            lines.append(line.lstrip("# "))
            header_found = True
        elif not line.startswith("#"):
            lines.append(line)
    urlhaus_df = pd.read_csv(io.StringIO("\n".join(lines)))
    urlhaus_urls = (
        urlhaus_df["url"]
        .dropna()
        .drop_duplicates()
        .reset_index(drop=True)
    )
    urlhaus_sample = urlhaus_urls.sample(
        n=min(URLHAUS_SAMPLE_LIMIT, len(urlhaus_urls)), random_state=42
    )
    print(f"  URLhaus total : {len(urlhaus_urls)} -> sampled {len(urlhaus_sample)}")
except Exception as e:
    print(f"  URLhaus failed ({e}), skipping.")
    urlhaus_sample = pd.Series([], dtype=str)

urlhaus_df_out = pd.DataFrame({"url": urlhaus_sample, "label": 1})


# ── 3. OpenPhish ─────────────────────────────────────────────────────────────

print("Downloading OpenPhish URLs...")
try:
    resp = requests.get(OPENPHISH_URL, timeout=30, headers=HEADERS)
    resp.raise_for_status()
    openphish_urls = pd.Series(
        [l.strip() for l in resp.text.splitlines() if l.strip()],
        dtype=str,
    ).drop_duplicates().reset_index(drop=True)
    print(f"  OpenPhish     : {len(openphish_urls)}")
except Exception as e:
    print(f"  OpenPhish failed ({e}), skipping.")
    openphish_urls = pd.Series([], dtype=str)

openphish_df = pd.DataFrame({"url": openphish_urls, "label": 1})


# ── 4. Combine, dedup, shuffle ───────────────────────────────────────────────

dataset = (
    pd.concat([uci_sampled, urlhaus_df_out, openphish_df], ignore_index=True)
    .drop_duplicates(subset="url")
    .sample(frac=1, random_state=42)
    .reset_index(drop=True)
)

dataset.to_csv(OUT_PATH, index=False)

print(f"\nSource breakdown:")
print(f"  UCI phishing   : {len(uci_phishing)}")
print(f"  UCI benign     : {len(uci_benign)}")
print(f"  URLhaus        : {len(urlhaus_df_out)}")
print(f"  OpenPhish      : {len(openphish_df)}")
print(f"\nFinal dataset (after dedup):")
print(f"  Total          : {len(dataset)}")
print(f"  Malicious (1)  : {(dataset['label'] == 1).sum()}")
print(f"  Benign    (0)  : {(dataset['label'] == 0).sum()}")
print(f"\nSaved to {OUT_PATH}")
