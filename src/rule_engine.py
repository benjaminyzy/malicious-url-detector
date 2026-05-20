# Rule-based URL classifier. Third voter in the majority-voting ensemble.

import re

import tldextract

from keywords import BRAND_KEYWORDS, PRIZE_KEYWORDS, SUSPICIOUS_KEYWORDS

_BRAND_RE = re.compile(
    r"\b(" + "|".join(map(re.escape, BRAND_KEYWORDS)) + r")\b",
    re.IGNORECASE,
)
_SUSPICIOUS_RE = re.compile(
    r"\b(" + "|".join(map(re.escape, SUSPICIOUS_KEYWORDS)) + r")\b",
    re.IGNORECASE,
)
_PRIZE_RE = re.compile(
    r"\b(" + "|".join(map(re.escape, PRIZE_KEYWORDS)) + r")\b",
    re.IGNORECASE,
)

_extractor = tldextract.TLDExtract(suffix_list_urls=())
_BRAND_LOWER = {b.lower() for b in BRAND_KEYWORDS}


def _suspicious_domain_pattern(url, f):
    ext = _extractor(url)
    registered = (ext.domain or "").lower()
    subdomain = (ext.subdomain or "").lower()
    if registered in _BRAND_LOWER:
        return False
    has_hyphens = registered.count("-") >= 2
    brand_present = bool(_BRAND_RE.search(registered) or _BRAND_RE.search(subdomain))
    return has_hyphens and brand_present


def _brand_in_subdomain_phishing(url, f):
    return f.get("brand_in_subdomain_not_domain", 0) == 1


def _prize_scam_with_signal(url, f):
    if not _PRIZE_RE.search(url):
        return False
    return (
        f.get("is_shortened", 0) == 1
        or f.get("has_https", 0) == 0
        or f.get("is_suspicious_tld", 0) == 1
    )


RULES = [
    ("has_ip_address",
     lambda url, f: f["has_ip_address"] == 1,
     "URL uses a raw IP address instead of a domain name"),
    ("suspicious_words_no_https",
     lambda url, f: f["has_suspicious_words"] == 1 and f["has_https"] == 0,
     "URL contains credential-related keywords and does not use HTTPS"),
    ("url_too_long",
     lambda url, f: f["url_length"] > 200 and (
         f.get("has_suspicious_words", 0) == 1
         or f.get("has_ip_address", 0) == 1
         or f.get("is_suspicious_tld", 0) == 1
         or f.get("num_subdomains", 0) > 3
     ),
     "URL is unusually long and contains another risk signal"),
    ("has_at_symbol",
     lambda url, f: f["num_at_symbols"] > 0,
     "URL contains @ symbol (credential-injection technique)"),
    ("shortened_url",
     lambda url, f: f["is_shortened"] == 1,
     "URL uses a known URL-shortening service"),
    ("high_digit_ratio",
     lambda url, f: f["digit_to_letter_ratio"] > 1.5,
     "Digit-to-letter ratio is unusually high"),
    ("too_many_subdomains",
     lambda url, f: f["num_subdomains"] > 4,
     "URL has an unusually deep subdomain hierarchy"),
    ("suspicious_domain_pattern",
     _suspicious_domain_pattern,
     "Registered domain contains multiple hyphens plus a brand keyword"),
    ("brand_in_subdomain_phishing",
     _brand_in_subdomain_phishing,
     "Brand name appears in subdomain of an unrelated registered domain"),
    ("prize_scam_pattern",
     _prize_scam_with_signal,
     "URL contains prize/scam-bait keywords alongside another risk signal"),
    ("punycode_domain",
     lambda url, f: f.get("has_punycode", 0) == 1,
     "Domain uses Punycode encoding (possible homograph attack)"),
    ("suspicious_tld",
     lambda url, f: f.get("is_suspicious_tld", 0) == 1,
     "URL uses a TLD frequently abused for phishing or malware"),
]

_DYNAMIC_DESCRIPTIONS = {
    "high_digit_ratio": lambda f: (
        f"Digit-to-letter ratio is unusually high (ratio={f['digit_to_letter_ratio']:.2f})"
    ),
    "too_many_subdomains": lambda f: (
        f"URL has an unusually deep subdomain hierarchy (count={f['num_subdomains']})"
    ),
}


def get_triggered_rules(url, features):
    triggered = []
    for name, condition, description in RULES:
        if condition(url, features):
            if name in _DYNAMIC_DESCRIPTIONS:
                triggered.append(_DYNAMIC_DESCRIPTIONS[name](features))
            else:
                triggered.append(description)
    return triggered


def rule_based_classify(url, features):
    for _, condition, _ in RULES:
        if condition(url, features):
            return 1
    return 0


if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    from feature_extractor import extract_features

    tests = [
        ("http://192.168.1.1/admin/login.php", 1, "Raw IP + login"),
        ("http://paypal-secure-verify.com/update", 1, "Multi-hyphen brand"),
        ("https://paypal.attacker.com/login", 1, "Brand in subdomain"),
        ("https://bit.ly/free-prize-click", 1, "Shortener + prize"),
        ("https://google.com", 0, "Benign Google"),
        ("https://github.com/user/repo", 0, "Benign GitHub"),
        ("https://developer.apple.com/documentation/security", 0,
         "Apple docs (no FP)"),
        ("https://www.gnu.org/philosophy/free-sw.html", 0,
         "GNU 'free' page (no FP)"),
    ]

    all_pass = True
    for url, expected, desc in tests:
        feats = extract_features(url)
        got = rule_based_classify(url, feats)
        rules = get_triggered_rules(url, feats)
        status = "PASS" if got == expected else "FAIL"
        if status == "FAIL":
            all_pass = False
        print(f"[{status}] {desc:30} expected={expected} got={got}")
        if rules:
            for r in rules:
                print(f"        - {r}")

    print("\nAll tests passed." if all_pass else "\nSome tests FAILED.")
