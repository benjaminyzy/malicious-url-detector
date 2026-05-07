import os
import pandas as pd

RAW_DIR = os.path.join(os.path.dirname(__file__), "raw")
IN_PATH  = os.path.join(RAW_DIR, "uci_phishing.csv")
OUT_PATH = os.path.join(RAW_DIR, "dataset.csv")

print(f"Loading {IN_PATH}...")
df = pd.read_csv(IN_PATH, usecols=["url", "label"])
print(f"  Loaded       : {len(df)} rows")

df = df[df["url"].notna() & (df["url"].str.strip() != "")]
print(f"  After null/empty drop : {len(df)} rows")

df = df.drop_duplicates(subset="url")
print(f"  After dedup           : {len(df)} rows")

df = df.sample(frac=1, random_state=42).reset_index(drop=True)

df.to_csv(OUT_PATH, index=False)
print(f"\nSaved to {OUT_PATH}")
print(f"  Total      : {len(df)}")
print(f"  Malicious  : {(df['label'] == 1).sum()}")
print(f"  Benign     : {(df['label'] == 0).sum()}")
