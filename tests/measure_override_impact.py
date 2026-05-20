# Measure how often the high-precision override fires on the held-out test set.
import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.voting_classifier import classify_url

DATA_PATH = PROJECT_ROOT / "data" / "raw" / "dataset_features.csv"
OUTPUT_CSV = PROJECT_ROOT / "models" / "override_impact.csv"


def _proba_keys(result):
    # Resolve the two '<model>_proba' keys dynamically.
    return sorted(k for k in result if k.endswith("_proba"))


def main() -> None:
    print("Loading dataset...")
    df = pd.read_csv(DATA_PATH)

    if "url" not in df.columns:
        print("ERROR: dataset_features.csv does not contain a 'url' column.")
        print("This script requires raw URL strings to pass through classify_url().")
        return

    # Same train/test split as model training.
    from sklearn.model_selection import train_test_split
    df_train, df_test = train_test_split(
        df, test_size=0.2, stratify=df["label"], random_state=42
    )

    test_urls = df_test["url"].tolist()
    true_labels = df_test["label"].values
    total_test = len(test_urls)

    print(f"Test set size: {total_test} URLs")
    print("Running classifications...")

    override_fired_count = 0
    override_correct = 0  # fired on a truly malicious URL
    override_incorrect = 0  # fired on a truly benign URL
    classification_errors = 0

    override_records = []

    for i, url in enumerate(test_urls):
        if (i + 1) % 1000 == 0:
            print(f"  Processed {i + 1}/{total_test}...")

        try:
            result = classify_url(url)
        except Exception:
            classification_errors += 1
            continue

        if result.get("override_applied"):
            override_fired_count += 1
            true_label = int(true_labels[i])
            if true_label == 1:
                override_correct += 1
                outcome = "correct_save"
            else:
                override_incorrect += 1
                outcome = "false_positive"

            pk = _proba_keys(result)
            override_records.append({
                "url": url,
                "true_label": true_label,
                "final_label": result.get("final_label"),
                "confidence": result.get("confidence"),
                pk[0]: result.get(pk[0]) if len(pk) > 0 else None,
                pk[1]: result.get(pk[1]) if len(pk) > 1 else None,
                "triggered_rules": result.get("triggered_rules"),
                "outcome": outcome,
            })

    print()
    print("=" * 60)
    print("OVERRIDE IMPACT SUMMARY")
    print("=" * 60)
    print(f"Total test URLs: {total_test}")
    print(f"Classification errors: {classification_errors}")
    print(f"Override fired: {override_fired_count}")
    print(f"  Correctly saved FNs: {override_correct}")
    print(f"  False positives created: {override_incorrect}")

    if override_fired_count > 0:
        precision = override_correct / override_fired_count
        print(f"Override precision: {precision:.4f}")
    else:
        print("Override precision: N/A (override never fired)")
    print("=" * 60)

    if override_records:
        out_df = pd.DataFrame(override_records)
        out_df.to_csv(OUTPUT_CSV, index=False)
        print(f"\nDetailed override records saved to: {OUTPUT_CSV}")
        print("First few records:")
        print(out_df.head(5).to_string())
    else:
        print("\nNo override events to save. CSV not written.")


if __name__ == "__main__":
    main()
