
from pathlib import Path


DATA_DIR = Path("data/processed")
TRAIN_FILE = DATA_DIR / "train.csv"
TEST_FILE = DATA_DIR / "test.csv"

FEATURES = [
    "prefix_length",
    "ip_version",
    "rov_valid",
    "rov_invalid",
    "rov_notfound",
    "origin_mismatch",
    "max_length_exceeded",
    "has_observed_parent_prefix",
    "has_observed_more_specific",
]

def train_model(train_file=TRAIN_FILE, test_file=TEST_FILE):
    import pandas as pd
    from xgboost import XGBClassifier
    from sklearn.metrics import (
        classification_report,
        confusion_matrix,
        accuracy_score,
        roc_auc_score,
    )

    train = pd.read_csv(train_file)
    test = pd.read_csv(test_file)
    required = set(FEATURES) | {"label"}
    for name, frame in (("train", train), ("test", test)):
        missing = required - set(frame.columns)
        if missing:
            raise ValueError(f"{name} dataset missing columns: {sorted(missing)}")
    X_train = train[FEATURES].fillna(0)
    y_train = train["label"].astype(int)
    X_test = test[FEATURES].fillna(0)
    y_test = test["label"].astype(int)
    if set(y_train.unique()) != {0, 1}:
        raise ValueError("Training labels must contain both 0 and 1")
    model = XGBClassifier(
        n_estimators=200, max_depth=4, learning_rate=0.05,
        subsample=0.9, colsample_bytree=0.9,
        objective="binary:logistic", eval_metric="logloss", random_state=42,
    )
    model.fit(X_train, y_train)
    probabilities = model.predict_proba(X_test)[:, 1]
    predictions = (probabilities >= 0.5).astype(int)
    print("\nAccuracy:", round(accuracy_score(y_test, predictions), 4))
    if len(set(y_test)) == 2:
        print("ROC-AUC:", round(roc_auc_score(y_test, probabilities), 4))
    print("\nClassification report:")
    print(classification_report(
        y_test, predictions, target_names=["Control", "Injected anomaly"],
        digits=4, zero_division=0,
    ))
    print("\nConfusion matrix [ [TN, FP], [FN, TP] ]:")
    print(confusion_matrix(y_test, predictions))

    test_results = test.copy()
    test_results["actual"] = y_test.to_numpy()
    test_results["predicted"] = predictions
    test_results["probability"] = probabilities

    for anomaly_type in ["R1_unexpected_origin", "R2_suspicious_more_specific"]:
        if "anomaly_type" not in test_results:
            break
        subset = test_results[
            (test_results["anomaly_type"] == anomaly_type)
            & (test_results["actual"] == 1)
        ]

        if subset.empty:
            print(f"\n{anomaly_type}: No test examples found.")
            continue

        detected = int((subset["predicted"] == 1).sum())
        missed = int((subset["predicted"] == 0).sum())
        recall = float((subset["predicted"] == 1).mean())

        print(f"\n{anomaly_type}")
        print(f"  Test examples: {len(subset)}")
        print(f"  Detected: {detected}")
        print(f"  Missed: {missed}")
        print(f"  Recall: {recall:.4f}")

    model_dir = Path("models")
    model_dir.mkdir(exist_ok=True)

    model.save_model(model_dir / "bgp_sentinel_xgboost.json")

    importance = pd.DataFrame({
        "feature": FEATURES,
        "importance": model.feature_importances_,
    }).sort_values("importance", ascending=False)

    importance.to_csv(model_dir / "feature_importance.csv", index=False)

    print("\nSaved model: models/bgp_sentinel_xgboost.json")
    print("\nFeature importance:")
    print(importance.to_string(index=False))
    return model


if __name__ == "__main__":
    train_model()
