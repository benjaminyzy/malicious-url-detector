import re

_BRAND_WORDS = re.compile(
    r"verify|secure|update|account|login|signin|banking|confirm|password"
    r"|paypal|amazon|apple|microsoft|google|facebook",
    re.IGNORECASE,
)
_PRIZE_WORDS = re.compile(
    r"free-prize|free|prize|winner|claim|reward|lucky|congratulations"
    r"|you-won|click-here|limited-offer",
    re.IGNORECASE,
)
_SHORTENED_PRIZE_WORDS = re.compile(
    r"free|prize|click|win|reward|offer|lucky|claim",
    re.IGNORECASE,
)


def _suspicious_domain_pattern(url, f):
    from urllib.parse import urlparse
    domain = urlparse(url).netloc.split(":")[0]
    return domain.count("-") >= 2 and bool(_BRAND_WORDS.search(url))


RULES = [
    (
        "has_ip_address",
        lambda url, f: f["has_ip_address"] == 1,
        "URL uses a raw IP address instead of a domain name",
    ),
    (
        "suspicious_words_no_https",
        lambda url, f: f["has_suspicious_words"] == 1 and f["has_https"] == 0,
        "URL contains suspicious words and does not use HTTPS",
    ),
    (
        "url_too_long",
        lambda url, f: f["url_length"] > 200,
        "URL length exceeds 200 characters",
    ),
    (
        "has_at_symbol",
        lambda url, f: f["num_at_symbols"] > 0,
        "URL contains @ symbol (credential injection attempt)",
    ),
    (
        "shortened_url",
        lambda url, f: f["is_shortened"] == 1,
        "URL uses a known shortener service",
    ),
    (
        "high_digit_ratio",
        lambda url, f: f["digit_to_letter_ratio"] > 1.5,
        f"Digit-to-letter ratio exceeds 1.5 (ratio={'{digit_to_letter_ratio:.3f}'})",
    ),
    (
        "too_many_subdomains",
        lambda url, f: f["num_subdomains"] > 4,
        f"URL has more than 4 subdomains (count={'{num_subdomains}'})",
    ),
    (
        "suspicious_domain_pattern",
        _suspicious_domain_pattern,
        "Domain contains multiple hyphens with a brand/sensitive keyword",
    ),
    (
        "prize_scam_pattern",
        lambda url, f: bool(_PRIZE_WORDS.search(url)),
        "URL contains prize-scam keywords (free-prize, winner, claim, etc.)",
    ),
    (
        "shortened_with_prize_words",
        lambda url, f: f["is_shortened"] == 1 and bool(_SHORTENED_PRIZE_WORDS.search(url)),
        "URL uses a shortener and contains prize/scam-bait words",
    ),
]

# Rule descriptions that embed feature values at call time
_DYNAMIC_DESCRIPTIONS = {
    "high_digit_ratio": lambda f: f"Digit-to-letter ratio exceeds 1.5 (ratio={f['digit_to_letter_ratio']:.3f})",
    "too_many_subdomains": lambda f: f"URL has more than 4 subdomains (count={f['num_subdomains']})",
}


def get_triggered_rules(url, features):
    triggered = []
    for name, condition, description in RULES:
        if condition(url, features):
            desc = _DYNAMIC_DESCRIPTIONS[name](features) if name in _DYNAMIC_DESCRIPTIONS else description
            triggered.append(desc)
    return triggered


def rule_based_classify(url, features):
    for _, condition, _ in RULES:
        if condition(url, features):
            return 1
    return 0


if __name__ == "__main__":
    import sys
    import os
    sys.path.insert(0, os.path.dirname(__file__))
    from feature_extractor import extract_features

    test_cases = [
        # (url, expected_label, description)
        ("http://192.168.1.1/admin/login.php", 1, "Raw IP with login path"),
        ("http://paypa1-secure.verify-account.com/update", 1, "Suspicious words, no HTTPS"),
        ("http://" + "a" * 190 + ".com/path", 1, "Extremely long URL"),
        ("https://google.com", 0, "Benign — Google"),
        ("https://github.com/user/repo", 0, "Benign — GitHub"),
    ]

    print(f"{'URL':<55} {'Expected':>8} {'Got':>5}  Triggered Rules")
    print("-" * 110)
    all_passed = True
    for url, expected, desc in test_cases:
        features = extract_features(url)
        label = rule_based_classify(url, features)
        rules = get_triggered_rules(url, features)
        status = "PASS" if label == expected else "FAIL"
        if status == "FAIL":
            all_passed = False
        display_url = url if len(url) <= 52 else url[:49] + "..."
        rules_str = "; ".join(rules) if rules else "none"
        print(f"{display_url:<55} {expected:>8} {label:>5}  [{status}] {rules_str}")

    print()
    print("All tests passed." if all_passed else "Some tests FAILED.")
