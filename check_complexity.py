import pandas as pd
df = pd.read_csv("data/features.csv")
print(df["cyclomatic_complexity"].describe())
print()
print("Rows with complexity 0:", (df["cyclomatic_complexity"] == 0).sum(), "out of", len(df))
