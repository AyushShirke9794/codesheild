import xml.etree.ElementTree as ET

tree = ET.parse("data/cwec_v4.20.xml")
root = tree.getroot()

NS = "{http://cwe.mitre.org/cwe-7}"

missing_ids = ["254", "19", "255", "264", "21"]

for cat in root.iter(NS + "Category"):
    if cat.get("ID") in missing_ids:
        print(f"CWE-{cat.get('ID')} found as Category:", cat.get("Name"))

for weak in root.iter(NS + "Weakness"):
    if weak.get("ID") in missing_ids:
        print(f"CWE-{weak.get('ID')} found as Weakness:", weak.get("Name"))
