# Generate model_comparison.png and feature_importance.png in models/plots/.
import pickle
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models"
DATA_PATH = PROJECT_ROOT / "data" / "raw" / "dataset_features.csv"
OUT_DIR = MODELS_DIR / "plots"
OUT_DIR.mkdir(parents=True, exist_ok=True)


# Five-model F1+MCC bar chart. Values from models/_training_log.txt.
models = ["Logistic Regression", "KNN", "Decision Tree", "Random Forest", "XGBoost"]
f1_scores = [0.8192, 0.9568, 0.9572, 0.9676, 0.9730]
mcc_scores = [0.6781, 0.9153, 0.9144, 0.9352, 0.9463]

x = np.arange(len(models))
width = 0.35
fig, ax = plt.subplots(figsize=(11, 6))
bars1 = ax.bar(x - width / 2, f1_scores, width, label="F1 Score", color="#3b82f6")
bars2 = ax.bar(x + width / 2, mcc_scores, width, label="MCC", color="#22c55e")

ax.set_ylabel("Score", fontsize=12)
ax.set_title("Model Comparison: F1 Score and Matthews Correlation Coefficient",
             fontsize=13, pad=15)
ax.set_xticks(x)
ax.set_xticklabels(models, rotation=15, ha="right")
ax.set_ylim(0, 1.05)
ax.legend(loc="lower right")
ax.grid(axis="y", alpha=0.3)

for bar in list(bars1) + list(bars2):
    height = bar.get_height()
    ax.text(bar.get_x() + bar.get_width() / 2, height + 0.01,
            f"{height:.4f}", ha="center", va="bottom", fontsize=9)

plt.tight_layout()
plt.savefig(OUT_DIR / "model_comparison.png", dpi=150)
plt.close()
print(f"Saved {OUT_DIR / 'model_comparison.png'}")


# Load feature names and the top two models for feature importance.
df = pd.read_csv(DATA_PATH)

# Same EXCLUDED_FEATURES as src/model_trainer.py.
EXCLUDED = ("url", "label", "has_https")
feature_cols = [c for c in df.columns if c not in EXCLUDED]

# best_model_1 = XGBoost, best_model_2 = Random Forest
with open(MODELS_DIR / "best_model_1.pkl", "rb") as f:
    model_xgb = pickle.load(f)
with open(MODELS_DIR / "best_model_2.pkl", "rb") as f:
    model_rf = pickle.load(f)


# Feature importance for the top two models.
xgb_importance = model_xgb.feature_importances_
rf_importance = model_rf.feature_importances_

xgb_idx = np.argsort(xgb_importance)[-15:]
rf_idx = np.argsort(rf_importance)[-15:]

fig, axes = plt.subplots(1, 2, figsize=(15, 7))

axes[0].barh(range(len(xgb_idx)), xgb_importance[xgb_idx], color="#3b82f6")
axes[0].set_yticks(range(len(xgb_idx)))
axes[0].set_yticklabels([feature_cols[i] for i in xgb_idx], fontsize=10)
axes[0].set_xlabel("Importance", fontsize=12)
axes[0].set_title("XGBoost: Top 15 Features", fontsize=13, pad=15)
axes[0].grid(axis="x", alpha=0.3)

axes[1].barh(range(len(rf_idx)), rf_importance[rf_idx], color="#22c55e")
axes[1].set_yticks(range(len(rf_idx)))
axes[1].set_yticklabels([feature_cols[i] for i in rf_idx], fontsize=10)
axes[1].set_xlabel("Importance", fontsize=12)
axes[1].set_title("Random Forest: Top 15 Features", fontsize=13, pad=15)
axes[1].grid(axis="x", alpha=0.3)

plt.tight_layout()
plt.savefig(OUT_DIR / "feature_importance.png", dpi=150)
plt.close()
print(f"Saved {OUT_DIR / 'feature_importance.png'}")
print(f"\nAll plots saved to {OUT_DIR}")
