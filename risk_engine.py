import os
import joblib
import pandas as pd

from xgboost import XGBRegressor


MODEL_PATH = "models/xgboost_risk_model.json"
ENCODER_PATH = "models/cwe_target_encoder.joblib"

BASE_FEATURES = [
    "cwe_graph_depth",
    "cwe_num_related",
    "code_length",
    "has_dangerous_pattern",
    "severity_encoded",
    "severity_known",
]


class RiskEngine:

    def __init__(self):
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Risk model not found: {MODEL_PATH}"
            )

        if not os.path.exists(ENCODER_PATH):
            raise FileNotFoundError(
                f"CWE encoder not found: {ENCODER_PATH}"
            )

        self.model = XGBRegressor()
        self.model.load_model(MODEL_PATH)

        self.encoder = joblib.load(ENCODER_PATH)

    def predict(
        self,
        cwe_id,
        cwe_graph_depth,
        cwe_num_related,
        code_length,
        has_dangerous_pattern,
        severity_encoded,
        severity_known,
    ):

        base_features = pd.DataFrame([{
            "cwe_graph_depth": cwe_graph_depth,
            "cwe_num_related": cwe_num_related,
            "code_length": code_length,
            "has_dangerous_pattern": has_dangerous_pattern,
            "severity_encoded": severity_encoded,
            "severity_known": severity_known,
        }])

        cwe_data = pd.DataFrame([{
            "cwe_id": str(cwe_id) if cwe_id is not None else "UNKNOWN"
        }])

        cwe_encoded = self.encoder.transform(cwe_data)

        features = pd.concat(
            [
                base_features.reset_index(drop=True),
                cwe_encoded.reset_index(drop=True)
            ],
            axis=1
        )

        prediction = float(
            self.model.predict(features)[0]
        )

        # Keep the externally reported score inside 0–100.
        prediction = max(0.0, min(100.0, prediction))

        return prediction