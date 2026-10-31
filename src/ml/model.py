
from pathlib import Path
import os


# Load the trained model stored beside this file.
MODEL_PATH = Path(os.getenv(
    "BGP_MODEL_PATH",
    Path(__file__).resolve().parents[2] / "models" / "bgp_sentinel_xgboost.json",
))

# These names and their order must match the training pipeline.
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


_model = None


def load_model():
    """Load the trained XGBoost model once."""
    global _model

    if _model is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Trained model not found: {MODEL_PATH}"
            )

        from xgboost import XGBClassifier

        _model = XGBClassifier()
        _model.load_model(str(MODEL_PATH))

    return _model


def model_status() -> dict:
    """Return model availability without loading optional ML dependencies."""
    return {
        "path": str(MODEL_PATH),
        "available": MODEL_PATH.exists(),
    }


def predict_anomaly(features: dict) -> dict:
    """
    Predict whether a BGP announcement resembles an
    injected anomaly in the controlled training dataset.

    Args:
        features: Dictionary containing all nine model features.

    Returns:
        Prediction label and anomaly probability.
    """
    missing = [name for name in FEATURES if name not in features]

    if missing:
        raise ValueError(
            f"Missing required features: {', '.join(missing)}"
        )

    # Preserve the exact feature order used during training.
    import pandas as pd

    input_data = pd.DataFrame(
        [[features[name] for name in FEATURES]],
        columns=FEATURES,
    )

    model = load_model()

    probability = float(model.predict_proba(input_data)[0][1])
    prediction = int(probability >= 0.5)

    return {
        "prediction": prediction,
        "result": (
            "Suspicious - ML flag"
            if prediction == 1
            else "Not flagged by ML"
        ),
        "anomaly_probability": round(probability, 4),
    }
