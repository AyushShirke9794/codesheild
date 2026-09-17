import pandas as pd
import ast

df_raw = pd.read_csv("data/features.csv")
from datasets import load_dataset
ds = load_dataset("hitoshura25/cvefixes")["train"]
python_rows = ds.filter(lambda r: r["language"] == "Python")

sample = python_rows[0]
code = sample["vulnerable_code"]
print("--- Raw code sample ---")
print(repr(code[:300]))
print()

try:
    ast.parse(code)
    print("Parsed successfully")
except SyntaxError as e:
    print("SyntaxError:", e)
