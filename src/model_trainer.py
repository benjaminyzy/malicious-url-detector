import os
import pickle
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

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
    print(f"  {len(df)} rows, {len(feature_cols)} features")
    return X, y, feature_cols


def evaluate(model, X_test, y_test):
    y_pred = model.predict(X_test)
    return {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_test, y_pred, zero_division=0), 4),
    }


def tune_logistic_regression(X_train, y_train):
    print("\nTuning Logistic Regression (GridSearchCV cv=5)...")
    param_grid = {"C": [0.01, 0.1, 1, 10], "max_iter": [500, 1000]}
    gs = GridSearchCV(
        LogisticRegression(class_weight="balanced", random_state=42, solver="lbfgs"),
        param_grid, cv=5, scoring="f1", n_jobs=-1, verbose=1,
    )
    gs.fit(X_train, y_train)
    print(f"  Best params: {gs.best_params_}")
    return gs.best_estimator_


def tune_random_forest(X_train, y_train):
    print("\nTuning Random Forest (GridSearchCV cv=5)...")
    param_grid = {"n_estimators": [50, 100], "max_depth": [None, 10, 20]}
    gs = GridSearchCV(
        RandomForestClassifier(class_weight="balanced", random_state=42),
        param_grid, cv=5, scoring="f1", n_jobs=-1, verbose=1,
    )
    gs.fit(X_train, y_train)
    print(f"  Best params: {gs.best_params_}")
    return gs.best_estimator_


def print_comparison(lr_metrics, rf_metrics):
    header = f"{'Metric':<12} {'Logistic Regression':>20} {'Random Forest':>15}"
    print("\n" + "=" * len(header))
    print(header)
    print("=" * len(header))
    for metric in ("accuracy", "precision", "recall", "f1"):
        print(f"{metric:<12} {lr_metrics[metric]:>20.4f} {rf_metrics[metric]:>15.4f}")
    print("=" * len(header))


if __name__ == "__main__":
    X, y, feature_cols = load_data()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain: {len(X_train)} samples | Test: {len(X_test)} samples")

    lr_model = tune_logistic_regression(X_train, y_train)
    rf_model = tune_random_forest(X_train, y_train)

    print("\nEvaluating on test set...")
    lr_metrics = evaluate(lr_model, X_test, y_test)
    rf_metrics = evaluate(rf_model, X_test, y_test)

    print_comparison(lr_metrics, rf_metrics)

    with open(os.path.join(MODELS_DIR, "logistic_regression.pkl"), "wb") as f:
        pickle.dump(lr_model, f)
    with open(os.path.join(MODELS_DIR, "random_forest.pkl"), "wb") as f:
        pickle.dump(rf_model, f)
    with open(os.path.join(MODELS_DIR, "feature_names.pkl"), "wb") as f:
        pickle.dump(feature_cols, f)
    print("\nModels saved to models/")

    winner = "Logistic Regression" if lr_metrics["f1"] >= rf_metrics["f1"] else "Random Forest"
    print(f"Best model by F1-score: {winner} "
          f"(F1={max(lr_metrics['f1'], rf_metrics['f1']):.4f})")
