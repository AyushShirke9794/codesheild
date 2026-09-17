import networkx as nx

g = nx.read_graphml("data/cwe_graph.graphml")

def describe(cwe_id: str):
    if cwe_id not in g:
        print(f"CWE-{cwe_id} not found in graph")
        return
    data = g.nodes[cwe_id]
    print(f"CWE-{cwe_id}: {data.get('name')} (Abstraction: {data.get('abstraction')})")
    print("  Outgoing relationships (this CWE -> others):")
    for target in g.successors(cwe_id):
        edge_data = g.get_edge_data(cwe_id, target)
        print(f"    {edge_data.get('relation')} -> CWE-{target} ({g.nodes[target].get('name')})")
    print("  Incoming relationships (others -> this CWE):")
    for source in g.predecessors(cwe_id):
        edge_data = g.get_edge_data(source, cwe_id)
        print(f"    CWE-{source} ({g.nodes[source].get('name')}) --{edge_data.get('relation')}--> here")
    print()

describe("89")
describe("78")
