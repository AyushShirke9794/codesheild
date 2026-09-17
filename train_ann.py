import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from sklearn.model_selection import KFold
from sklearn.preprocessing import StandardScaler
from category_encoders import TargetEncoder

df = pd.read_csv("data/features.csv")

BASE_FEATURES = ["cwe_graph_depth", "cwe_num_related", "code_length", "has_dangerous_pattern",
                  "severity_encoded", "severity_known"]
TARGET = "risk_score"

X_base = df[BASE_FEATURES]
cwe = df[["cwe_id"]].astype(str)
y = df[TARGET].values.astype(np.float32)

class RiskNet(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Linear(8, 1),
        )

    def forward(self, x):
        return self.net(x)


def train_one_fold(X_train, y_train, X_val, y_val, epochs=200):
    torch.manual_seed(42)
    model = RiskNet(X_train.shape[1])
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01)
    loss_fn = nn.L1Loss()  # L1 = Mean Absolute Error, matches our evaluation metric

    X_train_t = torch.tensor(X_train, dtype=torch.float32)
    y_train_t = torch.tensor(y_train, dtype=torch.float32).unsqueeze(1)
    X_val_t = torch.tensor(X_val, dtype=torch.float32)

    for epoch in range(epochs):
        model.train()
        optimizer.zero_grad()
        preds = model(X_train_t)
        loss = loss_fn(preds, y_train_t)
        loss.backward()
        optimizer.step()

    model.eval()
    with torch.no_grad():
        val_preds = model(X_val_t).squeeze().numpy()
    return np.mean(np.abs(val_preds - y_val))


kfold = KFold(n_splits=5, shuffle=True, random_state=42)
fold_maes = []

for fold_num, (train_idx, val_idx) in enumerate(kfold.split(X_base), start=1):
    X_train_base, X_val_base = X_base.iloc[train_idx], X_base.iloc[val_idx]
    cwe_train, cwe_val = cwe.iloc[train_idx], cwe.iloc[val_idx]
    y_train, y_val = y[train_idx], y[val_idx]

    encoder = TargetEncoder(cols=["cwe_id"])
    cwe_encoded_train = encoder.fit_transform(cwe_train, y_train)
    cwe_encoded_val = encoder.transform(cwe_val)

    X_train = pd.concat([X_train_base.reset_index(drop=True),
                          cwe_encoded_train.reset_index(drop=True)], axis=1).values
    X_val = pd.concat([X_val_base.reset_index(drop=True),
                        cwe_encoded_val.reset_index(drop=True)], axis=1).values

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)

    mae = train_one_fold(X_train_scaled, y_train, X_val_scaled, y_val)
    fold_maes.append(mae)
    print(f"Fold {fold_num} MAE: {mae:.2f}")

fold_maes = np.array(fold_maes)
print()
print(f"Mean MAE (ANN): {fold_maes.mean():.2f} (+/- {fold_maes.std():.2f})")
print()
print("For comparison:")
print("  Naive baseline MAE: 13.51")
print("  XGBoost (structural features only) MAE: 12.91")
print("  XGBoost (+ CWE encoding + severity) MAE: 10.18")
