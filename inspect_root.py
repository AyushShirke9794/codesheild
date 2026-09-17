import xml.etree.ElementTree as ET

tree = ET.parse("data/cwec_v4.20.xml")
root = tree.getroot()

print("Root tag:", root.tag)
print()
print("Root attributes:", root.attrib)
print()
print("Direct children of root (first 10):")
for child in list(root)[:10]:
    print(" -", child.tag)
