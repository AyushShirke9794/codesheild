import pandas as pd
import networkx as nx

df = pd.read_csv("data/features.csv")
graph = nx.read_graphml("data/cwe_graph.graphml")

distinct_cwes = df["cwe_id"].astype(str).unique()
missing = [c for c in distinct_cwes if c not in graph]

print(f"Distinct CWEs in features: {len(distinct_cwes)}")
print(f"CWEs missing from graph: {len(missing)}")
print("Missing CWE IDs:", missing)
print()

missing_rows = df[df["cwe_id"].astype(str).isin(missing)]
print(f"Rows affected by missing CWEs: {len(missing_rows)} / {len(df)}")
