import os
import re
import networkx as nx

from models import Finding


GRAPH_PATH = "data/cwe_graph.graphml"

DANGEROUS_PATTERNS = [
    # Command / code injection
    r"eval\(",
    r"exec\(",
    r"os\.system\(",
    r"subprocess\.",
    r"pickle\.loads\(",
    r"shell=True",

    # SQL injection
    r"\.execute\(.*\+",
    r"%s.*%.*execute",

    # XSS
    r"render_template_string\(",
    r"mark_safe\(",
    r"\|safe\b",
    r"innerHTML",

    # Path traversal
    r"os\.path\.join\(.*request",
    r"open\(.*request\.",

    # XXE
    r"resolve_entities\s*=\s*True",
    r"etree\.parse\((?!.*resolve_entities=False)",

    # Open redirect
    r"redirect\(.*request\.(GET|args|params)",
]


def has_dangerous_pattern(code: str) -> bool:
    return any(re.search(pattern, code) for pattern in DANGEROUS_PATTERNS)


def get_cwe_graph_features(cwe_id, graph):
    """
    Reproduce the same CWE graph feature logic
    used during Phase 3 model training.
    """

    if cwe_id is None:
        return 0, 0

    cwe_num = str(cwe_id).replace("CWE-", "")

    if cwe_num not in graph:
        return 0, 0

    depth = 0
    current = cwe_num
    visited = set()

    while True:
        parents = [
            target
            for target in graph.successors(current)
            if graph.get_edge_data(current, target).get("relation") == "ChildOf"
        ]

        if not parents or current in visited:
            break

        visited.add(current)
        current = parents[0]
        depth += 1

    num_related = (
        graph.in_degree(cwe_num)
        + graph.out_degree(cwe_num)
    )

    return depth, num_related


def encode_severity(severity_raw):
    """
    Same severity encoding used during Phase 3 training:

    LOW    -> 0
    MEDIUM -> 1
    HIGH   -> 2
    Unknown -> -1
    """

    if severity_raw is None:
        return -1, 0

    severity = str(severity_raw).upper()

    severity_map = {
        "LOW": 0,
        "MEDIUM": 1,
        "HIGH": 2,
    }

    if severity not in severity_map:
        return -1, 0

    return severity_map[severity], 1


def extract_features(finding: Finding, code: str):
    """
    Convert a live scanner Finding into the exact
    feature structure expected by RiskEngine.
    """

    if not os.path.exists(GRAPH_PATH):
        raise FileNotFoundError(
            f"CWE graph not found: {GRAPH_PATH}"
        )

    graph = nx.read_graphml(GRAPH_PATH)

    cwe_graph_depth, cwe_num_related = get_cwe_graph_features(
        finding.cwe_id,
        graph
    )

    severity_encoded, severity_known = encode_severity(
        finding.severity_raw
    )

    features = {
        "cwe_id": finding.cwe_id,
        "cwe_graph_depth": cwe_graph_depth,
        "cwe_num_related": cwe_num_related,
        "code_length": len(code.splitlines()),
        "has_dangerous_pattern": int(
            has_dangerous_pattern(code)
        ),
        "severity_encoded": severity_encoded,
        "severity_known": severity_known,
    }

    return features