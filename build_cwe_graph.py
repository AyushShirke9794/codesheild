import xml.etree.ElementTree as ET
import networkx as nx

NS = "{http://cwe.mitre.org/cwe-7}"

def build_graph(xml_path: str) -> nx.DiGraph:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    graph = nx.DiGraph()

    for weakness in root.iter(NS + "Weakness"):
        cwe_id = weakness.get("ID")
        graph.add_node(
            cwe_id,
            name=weakness.get("Name", ""),
            abstraction=weakness.get("Abstraction", ""),
        )

        related_container = weakness.find(NS + "Related_Weaknesses")
        if related_container is not None:
            for rel in related_container.findall(NS + "Related_Weakness"):
                target_id = rel.get("CWE_ID")
                nature = rel.get("Nature", "RelatedTo")
                if target_id:
                    graph.add_edge(cwe_id, target_id, relation=nature)

    return graph


if __name__ == "__main__":
    g = build_graph("data/cwec_v4.20.xml")
    print(f"Total nodes (CWEs): {g.number_of_nodes()}")
    print(f"Total edges (relationships): {g.number_of_edges()}")
    nx.write_graphml(g, "data/cwe_graph.graphml")
    print("Saved to data/cwe_graph.graphml")
