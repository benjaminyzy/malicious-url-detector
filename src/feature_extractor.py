"""URL feature extraction. Lexical and statistical features only (no network calls)."""

import math
import os
import re
import sys
from urllib.parse import urlparse

import pandas as pd
import tldextract

sys.path.insert(0, os.path.dirname(__file__))
from keywords import (
    SUSPICIOUS_KEYWORDS, BRAND_KEYWORDS,
    SHORTENER_DOMAINS, SUSPICIOUS_TLDS,
)

_SUSPICIOUS_RE = re.compile(
    r"\b(" + "|".join(map(re.escape, SUSPICIOUS_KEYWORDS)) + r")\b",
    re.IGNORECASE,
)
_BRAND_RE = re.compile(
    r"\b(" + "|".join(map(re.escape, BRAND_KEYWORDS)) + r")\b",
    re.IGNORECASE,
)
_IP_RE = re.compile(
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
)

# Use bundled Public Suffix List snapshot, do not fetch updates at runtime
_extractor = tldextract.TLDExtract(suffix_list_urls=())


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
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc or ""
    domain_no_port = netloc.split("@")[-1].split(":")[0]
    path = parsed.path or ""

    ext = _extractor(url)
    subdomain = ext.subdomain or ""
    registered_domain = ext.domain or ""
    tld = ext.suffix or ""

    num_subdomains = len([p for p in subdomain.split(".") if p])

    letters = sum(1 for c in url if c.isalpha())
    digits = sum(1 for c in url if c.isdigit())
    digit_to_letter_ratio = digits / letters if letters else 0.0

    # Brand-in-subdomain phishing signature:
    # paypal.attacker.com -> brand in subdomain, attacker is registered (PHISH)
    # paypal.com -> brand IS the registered domain (LEGIT)
    brand_in_sub = bool(_BRAND_RE.search(subdomain))
    brand_in_reg = bool(_BRAND_RE.search(registered_domain))
    brand_in_subdomain_not_domain = int(brand_in_sub and not brand_in_reg)

    return {
        "url_length": len(url),
        "domain_length": len(domain_no_port),
        "subdomain_length": len(subdomain),
        "tld_length": len(tld),
        "path_length": len(path),
        "num_dots": url.count("."),
        "num_at_symbols": url.count("@"),
        "num_question_marks": url.count("?"),
        "num_digits": digits,
        "num_subdomains": num_subdomains,
        "domain_hyphen_count": registered_domain.count("-"),
        "is_suspicious_tld": int(tld.lower() in SUSPICIOUS_TLDS),
        "has_https": int(scheme == "https"),
        "has_ip_address": int(bool(_IP_RE.search(domain_no_port))),
        "is_shortened": int(domain_no_port.lower() in SHORTENER_DOMAINS),
        "has_punycode": int("xn--" in domain_no_port.lower()),
        "has_suspicious_words": int(bool(_SUSPICIOUS_RE.search(url))),
        "brand_in_subdomain_not_domain": brand_in_subdomain_not_domain,
        "digit_to_letter_ratio": round(digit_to_letter_ratio, 6),
        "url_entropy": round(_entropy(url), 6),
        "domain_entropy": round(_entropy(domain_no_port), 6),
    }


def extract_features_batch(df):
    rows = []
    total = len(df)
    for i, url in enumerate(df["url"]):
        rows.append(extract_features(str(url)))
        if (i + 1) % 5000 == 0:
            print(f"  Processed {i + 1}/{total} URLs...")
    features_df = pd.DataFrame(rows)
    return pd.concat([df.reset_index(drop=True), features_df], axis=1)


if __name__ == "__main__":
    base = os.path.dirname(os.path.dirname(__file__))
    input_path = os.path.join(base, "data", "raw", "dataset.csv")
    output_path = os.path.join(base, "data", "raw", "dataset_features.csv")

    print(f"Loading {input_path}...")
    df = pd.read_csv(input_path)
    print(f"Extracting features for {len(df)} URLs...")
    result = extract_features_batch(df)
    result.to_csv(output_path, index=False)
    print(f"Saved {len(result)} rows, {len(result.columns)} columns to {output_path}")
    feature_cols = [c for c in result.columns if c not in ("url", "label")]
    print(f"Features ({len(feature_cols)}): {feature_cols}")
