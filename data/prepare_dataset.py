import io
import os
import requests
import pandas as pd
from ucimlrepo import fetch_ucirepo

RAW_DIR  = os.path.join(os.path.dirname(__file__), "raw")
OUT_PATH = os.path.join(RAW_DIR, "dataset.csv")
PHISHSTORM_CSV = os.path.join(RAW_DIR, "phishstorm", "urlset.csv")
os.makedirs(RAW_DIR, exist_ok=True)

URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
OPENPHISH_URL   = "https://openphish.com/feed.txt"
HEADERS         = {"User-Agent": "malicious-url-detector/1.0 (research)"}

# Composition (~50,300 total, ~balanced):
#   Benign (0)   : PhishStorm legitimate (path-rich) + PhiUSIIL legit (bare-domain)
#   Malicious (1): PhiUSIIL phishing + URLhaus + OpenPhish
# PhiUSIIL's legitimate URLs are 100% bare domains; on their own they make any
# URL with a path look malicious. PhishStorm (Marchal et al., IEEE TNSM 2014)
# supplies path-rich legitimate URLs to remove that structural bias. A small
# slice of PhiUSIIL legit is retained so the benign class still covers bare
# homepages too.
UCI_PHISHING_SAMPLE     = 15_000
UCI_BENIGN_SAMPLE       = 3_000
PHISHSTORM_LEGIT_SAMPLE = 22_000
URLHAUS_SAMPLE_LIMIT    = 10_000


# ── 1. UCI PhiUSIIL ──────────────────────────────────────────────────────────

print("Fetching UCI PhiUSIIL dataset (id=967)...")
phiusiil = fetch_ucirepo(id=967)
X = phiusiil.data.features
y = phiusiil.data.targets

url_col   = [c for c in X.columns if c.lower() == "url"][0]
label_col = list(y.columns)[0]

uci = pd.DataFrame({"url": X[url_col].values, "label": y[label_col].values})

# PhiUSIIL convention: label 1 = legitimate, 0 (or -1) = phishing.
# Project convention: 1 = malicious (phishing), 0 = benign (legitimate).
unique = set(uci["label"].unique())
if unique == {1, -1}:
    # 1=legitimate -> 0=benign, -1=phishing -> 1=malicious
    uci["label"] = uci["label"].map({1: 0, -1: 1})
elif unique <= {0, 1}:
    # PhiUSIIL's 0/1 is INVERTED vs ours: 0=phishing, 1=legitimate.
    uci["label"] = uci["label"].map({0: 1, 1: 0})
else:
    raise ValueError(f"Unexpected PhiUSIIL label values: {sorted(unique)}")

uci = uci.dropna(subset=["url"])
uci = uci[uci["url"].str.strip() != ""]
uci = uci.drop_duplicates(subset="url")

uci_phishing = uci[uci["label"] == 1].sample(n=UCI_PHISHING_SAMPLE, random_state=42)
uci_benign   = uci[uci["label"] == 0].sample(n=UCI_BENIGN_SAMPLE,   random_state=42)
print(f"  UCI phishing (bare/mixed) : {len(uci_phishing)}")
print(f"  UCI benign   (bare domain): {len(uci_benign)}")


# ── 2. PhishStorm legitimate (path-rich benign) ──────────────────────────────

print("Loading PhishStorm legitimate URLs...")
if not os.path.exists(PHISHSTORM_CSV):
    raise FileNotFoundError(
        f"PhishStorm file not found at {PHISHSTORM_CSV}. Download urlset.csv "
        "from https://research.aalto.fi/en/datasets/"
        "phishstorm-phishing-legitimate-url-dataset/ and place it there."
    )
ps = pd.read_csv(PHISHSTORM_CSV, encoding="latin-1",
                 on_bad_lines="skip", low_memory=False)
ps_url_col = [c for c in ps.columns if c.lower() in ("domain", "url")][0]
ps_lab_col = [c for c in ps.columns if c.lower() == "label"][0]
ps["_lab"] = pd.to_numeric(ps[ps_lab_col], errors="coerce")
ps = ps.dropna(subset=[ps_url_col, "_lab"])

# PhishStorm stores scheme-less URLs (e.g. "www.sec.gov/edgar.shtml").
# Prepend a uniform http:// so the feature extractor can parse them. The
# has_https feature is excluded from the ML feature set (model_trainer.py)
# precisely because this prepend would otherwise be a data-source artifact.
def _with_scheme(u):
    u = str(u).strip()
    return u if "://" in u else "http://" + u

ps_legit = ps[ps["_lab"] == 0][ps_url_col].map(_with_scheme)
ps_legit = ps_legit.drop_duplicates()
phishstorm_benign = pd.DataFrame({
    "url": ps_legit.sample(
        n=min(PHISHSTORM_LEGIT_SAMPLE, len(ps_legit)), random_state=42
    ),
    "label": 0,
})
print(f"  PhishStorm legit total {len(ps_legit)} -> "
      f"sampled {len(phishstorm_benign)}")


# ── 3. URLhaus ───────────────────────────────────────────────────────────────

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


# ── 4. OpenPhish ─────────────────────────────────────────────────────────────

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


# ── 5. Combine, dedup, shuffle ───────────────────────────────────────────────

dataset = (
    pd.concat(
        [uci_phishing[["url", "label"]], uci_benign[["url", "label"]],
         phishstorm_benign, urlhaus_df_out, openphish_df],
        ignore_index=True,
    )
    .drop_duplicates(subset="url")
    .sample(frac=1, random_state=42)
    .reset_index(drop=True)
)

dataset.to_csv(OUT_PATH, index=False)

print(f"\nSource breakdown:")
print(f"  PhishStorm benign (path-rich) : {len(phishstorm_benign)}")
print(f"  UCI benign  (bare domain)     : {len(uci_benign)}")
print(f"  UCI phishing                  : {len(uci_phishing)}")
print(f"  URLhaus                       : {len(urlhaus_df_out)}")
print(f"  OpenPhish                     : {len(openphish_df)}")
print(f"\nFinal dataset (after dedup):")
print(f"  Total          : {len(dataset)}")
print(f"  Malicious (1)  : {(dataset['label'] == 1).sum()}")
print(f"  Benign    (0)  : {(dataset['label'] == 0).sum()}")
print(f"\nSaved to {OUT_PATH}")
