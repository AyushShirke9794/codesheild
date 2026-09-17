from datasets import load_dataset
import networkx as nx
import pandas as pd
import re

DANGEROUS_PATTERNS = [
    r"eval\(", r"exec\(", r"os\.system\(", r"subprocess\.",
    r"pickle\.loads\(", r"shell=True", r"\.execute\(.*\+", r"%s.*%.*execute"
]

def has_dangerous_pattern(code: str) -> bool:
    return any(re.search(p, code) for p in DANGEROUS_PATTERNS)

def cwe_graph_features(cwe_num: str, graph: nx.DiGraph):
    if cwe_num not in graph:
        return 0, 0
    depth = 0
    current = cwe_num
    visited = set()
    while True:
        parents = [t for t in graph.successors(current)
                   if graph.get_edge_data(current, t).get("relation") == "ChildOf"]
        if not parents or current in visited:
            break
        visited.add(current)
        current = parents[0]
        depth += 1
    num_related = graph.in_degree(cwe_num) + graph.out_degree(cwe_num)
    return depth, num_related


def build_features():
    ds = load_dataset("hitoshura25/cvefixes")["train"]
    python_rows = ds.filter(lambda r: r["language"] == "Python")
    CATEGORY_ONLY_CWES = {"CWE-19", "CWE-21", "CWE-254", "CWE-255", "CWE-264"}

    valid_rows = python_rows.filter(
        lambda r: r["cwe_id"] not in ("NVD-CWE-noinfo", "NVD-CWE-Other", None)
        and r["cvss3_base_score"] is not None
        and r["cwe_id"] not in CATEGORY_ONLY_CWES
    )

    graph = nx.read_graphml("data/cwe_graph.graphml")

    records = []
    for row in valid_rows:
        cwe_num = row["cwe_id"].replace("CWE-", "")
        depth, num_related = cwe_graph_features(cwe_num, graph)
        vulnerable_code = row["vulnerable_code"] or ""

        records.append({
            "cve_id": row["cve_id"],
            "cwe_id": cwe_num,
            "cwe_graph_depth": depth,
            "cwe_num_related": num_related,
            "code_length": len(vulnerable_code.splitlines()),
            "has_dangerous_pattern": int(has_dangerous_pattern(vulnerable_code)),
            "risk_score": row["cvss3_base_score"] * 10,
        })

    return pd.DataFrame(records)


if __name__ == "__main__":
    df = build_features()
    print(f"Total rows: {len(df)}")
    print()
    print(df.describe())
    print()
    print(df.head(10))
    df.to_csv("data/features.csv", index=False)
    print()
    print("Saved to data/features.csv")
