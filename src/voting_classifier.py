import os
import sys
import pickle
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(__file__))

from feature_extractor import extract_features
from rule_engine import rule_based_classify, get_triggered_rules

MODELS_DIR = os.path.join(BASE_DIR, "models")


def _load_models():
    def load(name):
        with open(os.path.join(MODELS_DIR, name), "rb") as f:
            return pickle.load(f)
    return load("logistic_regression.pkl"), load("random_forest.pkl"), load("feature_names.pkl")


_lr_model, _rf_model, _feature_names = None, None, None


def _ensure_loaded():
    global _lr_model, _rf_model, _feature_names
    if _lr_model is None:
        _lr_model, _rf_model, _feature_names = _load_models()


def classify_url(url):
    _ensure_loaded()

    features = extract_features(url)
    feature_vector = pd.DataFrame([{name: features[name] for name in _feature_names}])

    lr_pred = int(_lr_model.predict(feature_vector)[0])
    rf_pred = int(_rf_model.predict(feature_vector)[0])
    rule_pred = rule_based_classify(url, features)
    triggered_rules = get_triggered_rules(url, features)

    votes_for_malicious = lr_pred + rf_pred + rule_pred
    final_label = 1 if votes_for_malicious >= 2 else 0

    return {
        "url": url,
        "final_label": final_label,
        "final_result": "MALICIOUS" if final_label == 1 else "BENIGN",
        "lr_prediction": lr_pred,
        "rf_prediction": rf_pred,
        "rule_prediction": rule_pred,
        "votes_for_malicious": votes_for_malicious,
        "confidence": round(votes_for_malicious / 3 * 100, 1),
        "triggered_rules": triggered_rules,
    }


if __name__ == "__main__":
    test_urls = [
        "http://192.168.1.1/login/verify",
        "https://google.com",
        "http://paypal-secure-verify.com/account/update",
    ]

    for url in test_urls:
        result = classify_url(url)
        print(f"\nURL: {result['url']}")
        print(f"  Final result      : {result['final_result']} (label={result['final_label']})")
        print(f"  Confidence        : {result['confidence']}%")
        print(f"  Votes (malicious) : {result['votes_for_malicious']}/3")
        print(f"  LR prediction     : {result['lr_prediction']}")
        print(f"  RF prediction     : {result['rf_prediction']}")
        print(f"  Rule prediction   : {result['rule_prediction']}")
        print(f"  Triggered rules   : {result['triggered_rules'] or ['none']}")
