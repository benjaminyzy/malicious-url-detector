import re
import math
import os
from urllib.parse import urlparse
import pandas as pd

SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly"}
SUSPICIOUS_WORDS = re.compile(
    r"login|verify|secure|account|update|banking|confirm|password|signin",
    re.IGNORECASE,
)
IP_PATTERN = re.compile(
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
)


def _entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc or ""
    # Strip port from domain
    domain_no_port = domain.split(":")[0]
    path = parsed.path or ""

    # Subdomain count: parts minus the registered domain (last 2 labels)
    labels = [p for p in domain_no_port.split(".") if p]
    num_subdomains = max(len(labels) - 2, 0)

    letters = [c for c in url if c.isalpha()]
    digits = [c for c in url if c.isdigit()]
    digit_to_letter_ratio = len(digits) / len(letters) if letters else 0.0

    return {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_at_symbols": url.count("@"),
        "num_question_marks": url.count("?"),
        "num_equal_signs": url.count("="),
        "num_digits": len(digits),
        "has_ip_address": int(bool(IP_PATTERN.search(domain_no_port))),
        "has_https": int(url.startswith("https")),
        "domain_length": len(domain_no_port),
        "num_subdomains": num_subdomains,
        "is_shortened": int(domain_no_port.lower() in SHORTENERS),
        "path_length": len(path),
        "has_suspicious_words": int(bool(SUSPICIOUS_WORDS.search(url))),
        "digit_to_letter_ratio": round(digit_to_letter_ratio, 6),
        "url_entropy": round(_entropy(url), 6),
    }


def extract_features_batch(df):
    feature_rows = []
    total = len(df)
    for i, url in enumerate(df["url"]):
        feature_rows.append(extract_features(str(url)))
        if (i + 1) % 5000 == 0:
            print(f"  Processed {i + 1}/{total} URLs...")
    features_df = pd.DataFrame(feature_rows)
    return pd.concat([df.reset_index(drop=True), features_df], axis=1)


if __name__ == "__main__":
    base = os.path.dirname(os.path.dirname(__file__))
    input_path = os.path.join(base, "data", "raw", "dataset.csv")
    output_path = os.path.join(base, "data", "raw", "dataset_features.csv")

    print(f"Loading {input_path}...")
    df = pd.read_csv(input_path)
    print(f"Extracting features for {len(df)} URLs...")

    result = extract_features_batch(df)
    print(f"  Processed {len(result)}/{len(result)} URLs...")

    result.to_csv(output_path, index=False)
    print(f"\nSaved {len(result)} rows with {len(result.columns)} columns to {output_path}")
    print(f"Features: {[c for c in result.columns if c not in ('url', 'label')]}")
