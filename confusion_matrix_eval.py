import pandas as pd
import numpy as np
from xgboost import XGBRegressor
from sklearn.model_selection import KFold
from sklearn.metrics import confusion_matrix, classification_report
from category_encoders import TargetEncoder

df = pd.read_csv("data/features.csv")

BASE_FEATURES = ["cwe_graph_depth", "cwe_num_related", "code_length", "has_dangerous_pattern",
                  "severity_encoded", "severity_known"]
TARGET = "risk_score"

X_base = df[BASE_FEATURES]
cwe = df[["cwe_id"]].astype(str)
y = df[TARGET]

def bucket(score):
    if score < 40:
        return "Low"
    elif score < 70:
        return "Medium"
    else:
        return "High"

kfold = KFold(n_splits=5, shuffle=True, random_state=42)
all_preds = np.zeros(len(df))

for train_idx, val_idx in kfold.split(X_base):
    X_train_base, X_val_base = X_base.iloc[train_idx], X_base.iloc[val_idx]
    cwe_train, cwe_val = cwe.iloc[train_idx], cwe.iloc[val_idx]
    y_train = y.iloc[train_idx]

    encoder = TargetEncoder(cols=["cwe_id"])
    cwe_encoded_train = encoder.fit_transform(cwe_train, y_train)
    cwe_encoded_val = encoder.transform(cwe_val)

    X_train = pd.concat([X_train_base.reset_index(drop=True),
                          cwe_encoded_train.reset_index(drop=True)], axis=1)
    X_val = pd.concat([X_val_base.reset_index(drop=True),
                        cwe_encoded_val.reset_index(drop=True)], axis=1)

    model = XGBRegressor(n_estimators=100, max_depth=4, random_state=42, objective="reg:absoluteerror")
    model.fit(X_train, y_train)
    all_preds[val_idx] = model.predict(X_val)

actual_classes = [bucket(s) for s in y]
predicted_classes = [bucket(s) for s in all_preds]

labels = ["Low", "Medium", "High"]
cm = confusion_matrix(actual_classes, predicted_classes, labels=labels)

print("Confusion Matrix (rows = actual, columns = predicted)")
print("Labels order:", labels)
print(cm)
print()
print("Classification Report:")
print(classification_report(actual_classes, predicted_classes, labels=labels))