import pandas as pd
import numpy as np
import shap
from xgboost import XGBRegressor
from category_encoders import TargetEncoder

df = pd.read_csv("data/features.csv")

BASE_FEATURES = ["cwe_graph_depth", "cwe_num_related", "code_length", "has_dangerous_pattern",
                  "severity_encoded", "severity_known"]
TARGET = "risk_score"

X_base = df[BASE_FEATURES]
cwe = df[["cwe_id"]].astype(str)
y = df[TARGET]

encoder = TargetEncoder(cols=["cwe_id"])
cwe_encoded = encoder.fit_transform(cwe, y)

X_full = pd.concat([X_base.reset_index(drop=True), cwe_encoded.reset_index(drop=True)], axis=1)

model = XGBRegressor(n_estimators=100, max_depth=4, random_state=42, objective="reg:absoluteerror")
model.fit(X_full, y)

explainer = shap.TreeExplainer(model)
shap_values = explainer.shap_values(X_full)

print("Base value (average predicted risk score across all data):", explainer.expected_value)
print()

for i in [0, 1, 2]:
    print(f"--- Row {i} (CVE: {df.iloc[i]['cve_id']}, CWE-{df.iloc[i]['cwe_id']}) ---")
    print(f"Actual risk_score: {y.iloc[i]}")
    print(f"Predicted risk_score: {model.predict(X_full.iloc[[i]])[0]:.2f}")
    print("SHAP contributions:")
    for feat, val in zip(X_full.columns, shap_values[i]):
        print(f"  {feat}: {val:+.2f}")
    print()
