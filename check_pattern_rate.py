import pandas as pd
df = pd.read_csv("data/features.csv")
print("has_dangerous_pattern rate:", df["has_dangerous_pattern"].mean())
print("Count of 1s:", df["has_dangerous_pattern"].sum(), "out of", len(df))
