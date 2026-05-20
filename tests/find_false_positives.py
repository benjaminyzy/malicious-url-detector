# Run a curated list of legitimate URLs and report any flagged as MALICIOUS.
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.voting_classifier import classify_url

# Curated legitimate URLs across several categories.
LEGITIMATE_URLS = [
    # Search and social
    "https://www.google.com/search?q=phishing+detection",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://twitter.com/elonmusk",
    "https://www.facebook.com/login.php",
    "https://www.reddit.com/r/Python/comments/abc123/title/",
    "https://www.instagram.com/explore/",
    "https://www.linkedin.com/in/user-profile/",

    # Naked apex domains (known limitation)
    "https://google.com",
    "https://github.com",
    "https://apple.com",
    "https://stackoverflow.com",
    "https://wikipedia.org",

    # Long paths and analytics-heavy URLs
    "https://www.amazon.com/dp/B08N5WRWNW/ref=sr_1_3?dchild=1&keywords=laptop",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://github.com/john-kurkowski/tldextract/blob/master/README.md",
    "https://stackoverflow.com/questions/12345/how-to-fix-error",
    "https://www.youtube.com/results?search_query=tutorial+python",

    # Banking and known brands (sensitive false-positive territory)
    "https://www.maybank2u.com.my/home/m2u/common/login.do",
    "https://www.paypal.com/myaccount/summary",
    "https://login.live.com",
    "https://accounts.google.com/signin",

    # Government and educational
    "https://www.gov.uk/government/organisations",
    "https://www.apu.edu.my/student-portal",
    "https://www.harvard.edu",
    "https://www.mit.edu/admissions",

    # Legitimate shorteners
    "https://t.co/abcd1234",
    "https://bit.ly/3xY8w2K",  # not necessarily malicious

    # International
    "https://www.bbc.co.uk/news",
    "https://www.lemonde.fr/economie/",
    "https://www.spiegel.de/wirtschaft/",
]


def main() -> None:
    print(f"Testing {len(LEGITIMATE_URLS)} legitimate URLs against the classifier")
    print()
    print(f"{'URL':<80} | {'Verdict':<10} | {'Conf':<8} | Rules")
    print("-" * 140)

    false_positives = []
    classification_errors = []

    for url in LEGITIMATE_URLS:
        try:
            result = classify_url(url)
        except Exception as e:
            classification_errors.append((url, str(e)))
            print(f"{url[:78]:<80} | {'ERROR':<10} | {'':<8} | {e}")
            continue

        final_label = result.get("final_label", -1)
        # confidence is already a 0-100 percentage from classify_url
        confidence = result.get("confidence", 0)
        triggered = result.get("triggered_rules", [])

        verdict = "MALICIOUS" if final_label == 1 else "BENIGN"
        conf_str = f"{confidence:5.1f}%" if confidence else "N/A"
        rules_short = ", ".join(triggered) if triggered else ""

        if final_label == 1:
            false_positives.append({
                "url": url,
                "confidence": confidence,
                "triggered_rules": triggered,
            })

        url_display = url[:78] if len(url) > 78 else url
        print(f"{url_display:<80} | {verdict:<10} | {conf_str:<8} | {rules_short[:50]}")

    print()
    print("=" * 60)
    print("FALSE POSITIVE SUMMARY")
    print("=" * 60)
    print(f"Total legitimate URLs tested: {len(LEGITIMATE_URLS)}")
    print(f"Classification errors: {len(classification_errors)}")
    print(f"False positives: {len(false_positives)}")
    if len(LEGITIMATE_URLS) - len(classification_errors) > 0:
        fp_rate = len(false_positives) / (len(LEGITIMATE_URLS) - len(classification_errors))
        print(f"False positive rate: {fp_rate * 100:.2f}%")
    print("=" * 60)

    if false_positives:
        print("\nFalse positive details:")
        for fp in false_positives:
            print(f"  URL: {fp['url']}")
            print(f"    Confidence: {fp['confidence']:.1f}%")
            print(f"    Triggered rules: {fp['triggered_rules']}")
            print()


if __name__ == "__main__":
    main()
