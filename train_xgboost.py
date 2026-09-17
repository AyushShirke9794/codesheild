import pandas as pd
from xgboost import XGBRegressor
from sklearn.model_selection import cross_val_score, KFold
from sklearn.metrics import mean_absolute_error
import numpy as np

df = pd.read_csv("data/features.csv")

FEATURES = ["cwe_graph_depth", "cwe_num_related", "code_length", "has_dangerous_pattern"]
TARGET = "risk_score"

X = df[FEATURES]
y = df[TARGET]

model = XGBRegressor(n_estimators=100, max_depth=4, random_state=42)

kfold = KFold(n_splits=5, shuffle=True, random_state=42)
mae_scores = -cross_val_score(model, X, y, cv=kfold, scoring="neg_mean_absolute_error")

mae_scores = -cross_val_score(model, X, y, cv=kfold, scoring="neg_mean_absolute_error")

print("Per-fold MAE:", mae_scores)
print(f"Mean MAE: {mae_scores.mean():.2f} (+/- {mae_scores.std():.2f})")

baseline_mae = np.mean(np.abs(y - y.mean()))
print(f"Naive baseline MAE (always predict mean): {baseline_mae:.2f}")

print()
print(f"Target range: {y.min()} to {y.max()}, mean {y.mean():.2f}")

model.fit(X, y)
importances = dict(zip(FEATURES, model.feature_importances_))
print()
print("Feature importances (trained on full data):")
for feat, imp in sorted(importances.items(), key=lambda x: -x[1]):
    print(f"  {feat}: {imp:.3f}")
