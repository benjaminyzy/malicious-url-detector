"""Majority-voting ensemble with high-precision rule overrides.

Standard majority voting between 2 ML models + rule engine. Additionally,
a curated set of high-precision rules can override the majority vote and
force a MALICIOUS classification. This addresses cases where the ML models
are overconfident on phishing patterns underrepresented in training data.
"""

import os
import pickle
import sys

import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(__file__))

from feature_extractor import extract_features
from rule_engine import RULES, get_triggered_rules, rule_based_classify

MODELS_DIR = os.path.join(BASE_DIR, "models")
PROBA_THRESHOLD = 0.5

# Rules with near-zero false-positive rates. If any of these fire, the
# ensemble forces a MALICIOUS classification regardless of ML votes.
HIGH_PRECISION_RULES = {
    "has_ip_address",
    "brand_in_subdomain_phishing",
    "punycode_domain",
    "prize_scam_pattern",
    "suspicious_domain_pattern",
}

OVERRIDE_MIN_CONFIDENCE = 75.0

_model1 = None
_model2 = None
_model_names = None
_feature_names = None


def _load_pickle(path):
    with open(path, "rb") as f:
        return pickle.load(f)


def _ensure_loaded():
    global _model1, _model2, _model_names, _feature_names
    if _model1 is None:
        _model1 = _load_pickle(os.path.join(MODELS_DIR, "best_model_1.pkl"))
        _model2 = _load_pickle(os.path.join(MODELS_DIR, "best_model_2.pkl"))
        _model_names = _load_pickle(os.path.join(MODELS_DIR, "best_model_names.pkl"))
        _feature_names = _load_pickle(os.path.join(MODELS_DIR, "feature_names.pkl"))


def _proba_of_malicious(model, X):
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        classes = list(model.classes_)
        if 1 in classes:
            return float(proba[0][classes.index(1)])
        return float(proba[0][-1])
    return float(model.predict(X)[0])


def _name_key(model_name):
    return model_name.lower().replace(" ", "_")


def _get_triggered_rule_names(url, features):
    return [name for name, condition, _ in RULES if condition(url, features)]


def classify_url(url):
    _ensure_loaded()

    features = extract_features(url)
    feature_vector = pd.DataFrame(
        [{name: features.get(name, 0) for name in _feature_names}]
    )

    proba1 = _proba_of_malicious(_model1, feature_vector)
    proba2 = _proba_of_malicious(_model2, feature_vector)

    pred1 = int(proba1 >= PROBA_THRESHOLD)
    pred2 = int(proba2 >= PROBA_THRESHOLD)
    rule_pred = rule_based_classify(url, features)
    triggered_rules = get_triggered_rules(url, features)
    triggered_names = _get_triggered_rule_names(url, features)

    votes_for_malicious = pred1 + pred2 + rule_pred
    majority_label = 1 if votes_for_malicious >= 2 else 0

    # Check if any high-precision rule fired -> override the majority vote
    high_precision_fired = bool(
        set(triggered_names) & HIGH_PRECISION_RULES
    )
    override_applied = high_precision_fired and majority_label == 0
    final_label = 1 if (majority_label == 1 or high_precision_fired) else 0

    rule_proba = float(rule_pred)
    avg_proba_malicious = (proba1 + proba2 + rule_proba) / 3

    if final_label == 1:
        if override_applied:
            # Override case: confidence reflects rule strength.
            # Use the max of (rule-based floor, averaged probability).
            confidence = round(max(OVERRIDE_MIN_CONFIDENCE,
                                   avg_proba_malicious * 100), 1)
        else:
            confidence = round(avg_proba_malicious * 100, 1)
    else:
        confidence = round((1 - avg_proba_malicious) * 100, 1)

    key1 = _name_key(_model_names[0])
    key2 = _name_key(_model_names[1])

    return {
        "url": url,
        "final_label": final_label,
        "final_result": "MALICIOUS" if final_label == 1 else "BENIGN",
        f"{key1}_prediction": pred1,
        f"{key2}_prediction": pred2,
        f"{key1}_proba": round(proba1, 4),
        f"{key2}_proba": round(proba2, 4),
        "rule_prediction": rule_pred,
        "votes_for_malicious": votes_for_malicious,
        "majority_label": majority_label,
        "override_applied": override_applied,
        "confidence": confidence,
        "triggered_rules": triggered_rules,
    }


if __name__ == "__main__":
    _ensure_loaded()
    print(f"Loaded: {_model_names[0]} (best_model_1) | "
          f"{_model_names[1]} (best_model_2)\n")

    test_urls = [
        "http://192.168.1.1/login/verify",
        "https://google.com",
        "http://paypal-secure-verify.com/account/update",
        "https://paypal.attacker.com/login",
        "https://bit.ly/free-prize-click",
        "https://www.gnu.org/philosophy/free-sw.html",
        "https://developer.apple.com/documentation/security",
    ]

    for url in test_urls:
        result = classify_url(url)
        key1 = _name_key(_model_names[0])
        key2 = _name_key(_model_names[1])

        override_tag = " [OVERRIDE]" if result["override_applied"] else ""
        print(f"URL: {result['url']}")
        print(f"  Result    : {result['final_result']} "
              f"(confidence={result['confidence']}%){override_tag}")
        print(f"  Majority  : {'MALICIOUS' if result['majority_label']==1 else 'BENIGN'} "
              f"(votes={result['votes_for_malicious']}/3)")
        print(f"  {_model_names[0]:<15}: pred={result[f'{key1}_prediction']} "
              f"P(mal)={result[f'{key1}_proba']}")
        print(f"  {_model_names[1]:<15}: pred={result[f'{key2}_prediction']} "
              f"P(mal)={result[f'{key2}_proba']}")
        print(f"  Rule          : {result['rule_prediction']}")
        if result['triggered_rules']:
            print(f"  Triggered     : {result['triggered_rules']}")
        print()
