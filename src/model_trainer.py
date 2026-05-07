import os
import pickle
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, matthews_corrcoef, confusion_matrix,
)
from xgboost import XGBClassifier

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DATA_PATH = os.path.join(BASE_DIR, "data", "raw", "dataset_features.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(MODELS_DIR, exist_ok=True)


def load_data():
    print(f"Loading {DATA_PATH}...")
    df = pd.read_csv(DATA_PATH)
    feature_cols = [c for c in df.columns if c not in ("url", "label")]
    X = df[feature_cols]
    y = df["label"]
    print(f"  {len(df)} rows | {len(feature_cols)} features | "
          f"malicious={y.sum()} benign={(y == 0).sum()}")
    return X, y, feature_cols


def evaluate(model, X_test, y_test):
    y_pred = model.predict(X_test)
    return {
        "accuracy":  round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall":    round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1":        round(f1_score(y_test, y_pred, zero_division=0), 4),
        "mcc":       round(matthews_corrcoef(y_test, y_pred), 4),
    }, model.predict(X_test)


def save_confusion_matrix(y_test, y_pred, model_name):
    cm = confusion_matrix(y_test, y_pred)
    _, ax = plt.subplots(figsize=(6, 5))
    im = ax.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    plt.colorbar(im, ax=ax)
    ax.set_title(f"Confusion Matrix — {model_name}", fontsize=13, fontweight="bold")
    ax.set_xlabel("Predicted Label", fontsize=11)
    ax.set_ylabel("Actual Label", fontsize=11)
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Benign (0)", "Malicious (1)"])
    ax.set_yticklabels(["Benign (0)", "Malicious (1)"])
    thresh = cm.max() / 2
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, format(cm[i, j], "d"),
                    ha="center", va="center", fontsize=14,
                    color="white" if cm[i, j] > thresh else "black")
    plt.tight_layout()
    safe_name = model_name.lower().replace(" ", "_")
    out = os.path.join(MODELS_DIR, f"confusion_matrix_{safe_name}.png")
    plt.savefig(out, dpi=100)
    plt.close()
    print(f"  Saved confusion matrix -> {out}")


def build_model_configs(scale_pos_weight):
    return {
        "Logistic Regression": (
            LogisticRegression(class_weight="balanced", random_state=42),
            {
                "C": [0.01, 0.1, 1, 10],
                "max_iter": [500, 1000, 2000],
                "solver": ["lbfgs", "liblinear"],
            },
        ),
        "Random Forest": (
            RandomForestClassifier(class_weight="balanced", random_state=42),
            {
                "n_estimators": [50, 100, 200],
                "max_depth": [None, 10, 20],
                "min_samples_split": [2, 5],
            },
        ),
        "XGBoost": (
            XGBClassifier(
                scale_pos_weight=scale_pos_weight,
                random_state=42,
                eval_metric="logloss",
                verbosity=0,
            ),
            {
                "n_estimators": [50, 100, 200],
                "max_depth": [3, 6, 9],
                "learning_rate": [0.01, 0.1, 0.3],
                "subsample": [0.8, 1.0],
            },
        ),
        "Decision Tree": (
            DecisionTreeClassifier(class_weight="balanced", random_state=42),
            {
                "max_depth": [None, 10, 20, 30],
                "min_samples_split": [2, 5, 10],
                "criterion": ["gini", "entropy"],
            },
        ),
        "KNN": (
            KNeighborsClassifier(),
            {
                "n_neighbors": [3, 5, 7, 11],
                "weights": ["uniform", "distance"],
                "metric": ["euclidean", "manhattan"],
            },
        ),
    }


def print_comparison(results):
    col_w = 22
    metrics = ["accuracy", "precision", "recall", "f1", "mcc"]
    names = list(results.keys())
    header = f"{'Metric':<12}" + "".join(f"{n:>{col_w}}" for n in names)
    sep = "=" * len(header)
    print(f"\n{sep}\n{header}\n{sep}")
    for m in metrics:
        row = f"{m:<12}" + "".join(f"{results[n]['metrics'][m]:>{col_w}.4f}" for n in names)
        print(row)
    print(sep)
    print("\nBest hyperparameters:")
    for name, data in results.items():
        print(f"  {name}: {data['best_params']}")


if __name__ == "__main__":
    X, y, feature_cols = load_data()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train: {len(X_train)} | Test: {len(X_test)}")

    scale_pos_weight = (y_train == 0).sum() / (y_train == 1).sum()
    print(f"XGBoost scale_pos_weight: {scale_pos_weight:.4f}")

    model_configs = build_model_configs(scale_pos_weight)
    results = {}

    for name, (estimator, param_grid) in model_configs.items():
        total_fits = 5 * sum(
            len(v) for v in param_grid.values()
        )  # rough estimate for display
        candidates = 1
        for v in param_grid.values():
            candidates *= len(v)
        print(f"\nTuning {name} — {candidates} candidates × 5 folds = {candidates * 5} fits...")
        gs = GridSearchCV(
            estimator, param_grid, cv=5, scoring="f1", n_jobs=-1, verbose=1
        )
        gs.fit(X_train, y_train)
        best = gs.best_estimator_
        print(f"  Best params: {gs.best_params_}")

        metrics, y_pred = evaluate(best, X_test, y_test)
        save_confusion_matrix(y_test, y_pred, name)

        results[name] = {
            "model": best,
            "metrics": metrics,
            "best_params": gs.best_params_,
        }

    print_comparison(results)

    # Top 2 by F1
    ranked = sorted(results.items(), key=lambda x: x[1]["metrics"]["f1"], reverse=True)
    top2 = ranked[:2]

    print(f"\nTop 2 models by F1:")
    for i, (name, data) in enumerate(top2, 1):
        print(f"  #{i}: {name} — F1={data['metrics']['f1']:.4f} | "
              f"Best params: {data['best_params']}")

    # Save top 2 models
    for i, (name, data) in enumerate(top2, 1):
        path = os.path.join(MODELS_DIR, f"best_model_{i}.pkl")
        with open(path, "wb") as f:
            pickle.dump(data["model"], f)
        print(f"  Saved best_model_{i}.pkl ({name})")

    with open(os.path.join(MODELS_DIR, "best_model_names.pkl"), "wb") as f:
        pickle.dump([name for name, _ in top2], f)

    with open(os.path.join(MODELS_DIR, "feature_names.pkl"), "wb") as f:
        pickle.dump(feature_cols, f)

    print("\nAll models and feature names saved to models/")
