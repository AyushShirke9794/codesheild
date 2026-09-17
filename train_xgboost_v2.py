import pandas as pd
import numpy as np
from xgboost import XGBRegressor
from sklearn.model_selection import KFold
from category_encoders import TargetEncoder

df = pd.read_csv("data/features.csv")

BASE_FEATURES = ["cwe_graph_depth", "cwe_num_related", "code_length", "has_dangerous_pattern", "severity_encoded", "severity_known"]
TARGET = "risk_score"

X_base = df[BASE_FEATURES]
cwe = df[["cwe_id"]].astype(str)
y = df[TARGET]

kfold = KFold(n_splits=5, shuffle=True, random_state=42)
fold_maes = []

for fold_num, (train_idx, val_idx) in enumerate(kfold.split(X_base), start=1):
    X_train_base, X_val_base = X_base.iloc[train_idx], X_base.iloc[val_idx]
    cwe_train, cwe_val = cwe.iloc[train_idx], cwe.iloc[val_idx]
    y_train, y_val = y.iloc[train_idx], y.iloc[val_idx]

    encoder = TargetEncoder(cols=["cwe_id"])
    cwe_encoded_train = encoder.fit_transform(cwe_train, y_train)
    cwe_encoded_val = encoder.transform(cwe_val)

    X_train = pd.concat([X_train_base.reset_index(drop=True),
                          cwe_encoded_train.reset_index(drop=True)], axis=1)
    X_val = pd.concat([X_val_base.reset_index(drop=True),
                        cwe_encoded_val.reset_index(drop=True)], axis=1)

    model = XGBRegressor(n_estimators=100, max_depth=4, random_state=42)
    model.fit(X_train, y_train)
    preds = model.predict(X_val)
    mae = np.mean(np.abs(preds - y_val.values))
    fold_maes.append(mae)
    print(f"Fold {fold_num} MAE: {mae:.2f}")

fold_maes = np.array(fold_maes)
print()
print(f"Mean MAE (with CWE target encoding): {fold_maes.mean():.2f} (+/- {fold_maes.std():.2f})")

baseline_mae = np.mean(np.abs(y - y.mean()))
print(f"Naive baseline MAE: {baseline_mae:.2f}")
print(f"Previous model (no CWE encoding) MAE: 12.91")

full_encoder = TargetEncoder(cols=["cwe_id"])
cwe_encoded_full = full_encoder.fit_transform(cwe, y)
X_full = pd.concat([X_base.reset_index(drop=True), cwe_encoded_full.reset_index(drop=True)], axis=1)
final_model = XGBRegressor(n_estimators=100, max_depth=4, random_state=42)
final_model.fit(X_full, y)

print()
print("Feature importances (trained on full data):")
importances = dict(zip(X_full.columns, final_model.feature_importances_))
for feat, imp in sorted(importances.items(), key=lambda x: -x[1]):
    print(f"  {feat}: {imp:.3f}")
