from parsers import parse_semgrep_output, parse_bandit_output

semgrep_findings = parse_semgrep_output("semgrep_output.json")
bandit_findings = parse_bandit_output("bandit_output.json")

print("=== SEMGREP FINDINGS ===")
for f in semgrep_findings:
    print(f.model_dump())

print()
print("=== BANDIT FINDINGS ===")
for f in bandit_findings:
    print(f.model_dump())

print()
print(f"Total findings: {len(semgrep_findings) + len(bandit_findings)}")
