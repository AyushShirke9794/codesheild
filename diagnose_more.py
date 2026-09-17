from datasets import load_dataset
ds = load_dataset("hitoshura25/cvefixes")["train"]
python_rows = ds.filter(lambda r: r["language"] == "Python")

for i in [1, 5, 10, 50]:
    print(f"--- Sample {i} ---")
    print(repr(python_rows[i]["vulnerable_code"][:200]))
    print()
