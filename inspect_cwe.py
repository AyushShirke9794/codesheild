import xml.etree.ElementTree as ET

tree = ET.parse("data/cwec_v4.20.xml")
root = tree.getroot()

ns = "{http://cwe.mitre.org/cwe-7}"

for weakness in root.iter(ns + "Weakness"):
    if weakness.get("ID") == "89":
        print("Name:", weakness.get("Name"))
        print("Abstraction:", weakness.get("Abstraction"))
        print()
        print("--- Full XML structure for CWE-89 (first 3000 chars) ---")
        print(ET.tostring(weakness, encoding="unicode")[:3000])
        break
