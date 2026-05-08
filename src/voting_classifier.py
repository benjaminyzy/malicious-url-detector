import os
import sys
import pickle
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(__file__))

from feature_extractor import extract_features
from rule_engine import rule_based_classify, get_triggered_rules

MODELS_DIR = os.path.join(BASE_DIR, "models")

_model1 = None
_model2 = None
_model_names = None
_feature_names = None


def _load_models():
    def load(path):
        with open(path, "rb") as f:
            return pickle.load(f)

    model1       = load(os.path.join(MODELS_DIR, "best_model_1.pkl"))
    model2       = load(os.path.join(MODELS_DIR, "best_model_2.pkl"))
    model_names  = load(os.path.join(MODELS_DIR, "best_model_names.pkl"))
    feature_names = load(os.path.join(MODELS_DIR, "feature_names.pkl"))
    return model1, model2, model_names, feature_names


def _ensure_loaded():
    global _model1, _model2, _model_names, _feature_names
    if _model1 is None:
        _model1, _model2, _model_names, _feature_names = _load_models()


def classify_url(url):
    _ensure_loaded()

    features = extract_features(url)
    feature_vector = pd.DataFrame([{name: features[name] for name in _feature_names}])

    pred1 = int(_model1.predict(feature_vector)[0])
    pred2 = int(_model2.predict(feature_vector)[0])
    rule_pred = rule_based_classify(url, features)
    triggered_rules = get_triggered_rules(url, features)

    votes_for_malicious = pred1 + pred2 + rule_pred
    final_label = 1 if votes_for_malicious >= 2 else 0

    key1 = _model_names[0].lower().replace(" ", "_") + "_prediction"
    key2 = _model_names[1].lower().replace(" ", "_") + "_prediction"

    return {
        "url": url,
        "final_label": final_label,
        "final_result": "MALICIOUS" if final_label == 1 else "BENIGN",
        key1: pred1,
        key2: pred2,
        "rule_prediction": rule_pred,
        "votes_for_malicious": votes_for_malicious,
        "confidence": round(votes_for_malicious / 3 * 100, 1),
        "triggered_rules": triggered_rules,
    }


if __name__ == "__main__":
    _ensure_loaded()
    print(f"Loaded models: {_model_names[0]} (best_model_1) | {_model_names[1]} (best_model_2)\n")

    test_urls = [
        "http://192.168.1.1/login/verify",
        "https://google.com",
        "http://paypal-secure-verify.com/account/update",
    ]

    for url in test_urls:
        result = classify_url(url)
        key1 = _model_names[0].lower().replace(" ", "_") + "_prediction"
        key2 = _model_names[1].lower().replace(" ", "_") + "_prediction"
        print(f"URL: {result['url']}")
        print(f"  Final result      : {result['final_result']} (label={result['final_label']})")
        print(f"  Confidence        : {result['confidence']}%")
        print(f"  Votes (malicious) : {result['votes_for_malicious']}/3")
        print(f"  {_model_names[0]:<22}: {result[key1]}")
        print(f"  {_model_names[1]:<22}: {result[key2]}")
        print(f"  Rule Engine       : {result['rule_prediction']}")
        print(f"  Triggered rules   : {result['triggered_rules'] or ['none']}")
        print()
