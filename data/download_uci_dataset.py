import os
import pandas as pd
from ucimlrepo import fetch_ucirepo

RAW_DIR = os.path.join(os.path.dirname(__file__), "raw")
os.makedirs(RAW_DIR, exist_ok=True)

OUT_PATH = os.path.join(RAW_DIR, "uci_phishing.csv")

print("Fetching PhiUSIIL Phishing URL dataset (UCI id=967)...")
phiusiil = fetch_ucirepo(id=967)

X = phiusiil.data.features
y = phiusiil.data.targets

print(f"  Features shape : {X.shape}")
print(f"  Targets shape  : {y.shape}")
print(f"  Feature columns: {list(X.columns)}")
print(f"  Target columns : {list(y.columns)}")

# Identify URL and label columns
url_col = [c for c in X.columns if c.lower() == "url"]
label_col = list(y.columns)

if not url_col:
    raise ValueError(f"No URL column found in features. Available: {list(X.columns)}")

df = pd.DataFrame({
    "url": X[url_col[0]],
    "label": y[label_col[0]].values,
})

# Map labels: legitimate=0, phishing=1
unique_labels = df["label"].unique()
print(f"  Raw label values: {sorted(unique_labels)}")

# UCI PhiUSIIL uses 1=legitimate, -1=phishing (or 1/0 depending on version)
# Normalise to: phishing=1, legitimate=0
if set(unique_labels) == {1, -1}:
    df["label"] = df["label"].map({1: 0, -1: 1})
elif set(unique_labels) <= {0, 1}:
    pass  # already correct
else:
    # Fallback: treat the minority class as phishing
    minority = df["label"].value_counts().idxmin()
    df["label"] = (df["label"] == minority).astype(int)
    print(f"  Warning: unexpected labels — treated {minority} as phishing (1)")

df = df.dropna(subset=["url"]).drop_duplicates(subset="url").reset_index(drop=True)

df.to_csv(OUT_PATH, index=False)
print(f"\nSaved {len(df)} rows to {OUT_PATH}")
print(f"  Phishing (1)   : {(df['label'] == 1).sum()}")
print(f"  Legitimate (0) : {(df['label'] == 0).sum()}")

print("\nSample URLs:")
for _, row in df.sample(5, random_state=42).iterrows():
    label_str = "phishing" if row["label"] == 1 else "legitimate"
    print(f"  [{label_str}] {row['url']}")
