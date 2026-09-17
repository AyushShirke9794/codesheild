from datasets import load_dataset
from collections import Counter

ds = load_dataset("hitoshura25/cvefixes")["train"]
python_rows = ds.filter(lambda row: row["language"] == "Python")

real_cwe_rows = python_rows.filter(
    lambda row: row["cwe_id"] not in ("NVD-CWE-noinfo", "NVD-CWE-Other", None)
)
print("Python rows with a real CWE:", len(real_cwe_rows))
print()

severity_counts = Counter(real_cwe_rows["severity"])
print("Severity value distribution:")
for val, count in severity_counts.most_common(20):
    print(f"  {repr(val)}: {count}")

print()
cvss3_missing = sum(1 for v in real_cwe_rows["cvss3_base_score"] if v is None)
cvss2_missing = sum(1 for v in real_cwe_rows["cvss2_base_score"] if v is None)
print(f"Missing cvss3_base_score: {cvss3_missing} / {len(real_cwe_rows)}")
print(f"Missing cvss2_base_score: {cvss2_missing} / {len(real_cwe_rows)}")
