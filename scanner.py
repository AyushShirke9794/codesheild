import json
import os
import subprocess
import tempfile
import time
from typing import List

from models import Finding
from parsers import parse_semgrep_output, parse_bandit_output
from devaic_parser import parse_devaic_output


DEVAIC_DIR = "/home/ayush/DeVAIC/version_2.0"


def windows_to_wsl_path(windows_path: str) -> str:
    """Convert a Windows path to a WSL /mnt path."""
    normalized = windows_path.replace("\\", "/")

    if len(normalized) >= 2 and normalized[1] == ":":
        drive = normalized[0].lower()
        return f"/mnt/{drive}{normalized[2:]}"

    raise ValueError(f"Unsupported Windows path: {windows_path}")


def run_devaic(
    code_path: str,
    filename: str,
    output_dir: str
) -> List[Finding]:
    """Run DeVAIC through WSL and return normalized findings."""

    safe_filename = os.path.basename(filename)

    # DeVAIC currently supports Python files.
    if not safe_filename.lower().endswith(".py"):
        return []

    safe_filename = safe_filename.replace(" ", "_")

    # Copy source file into DeVAIC's input directory.
    wsl_source_path = windows_to_wsl_path(code_path)

    devaic_input_path = f"{DEVAIC_DIR}/input/{safe_filename}"

    copy_command = (
        f"cp '{wsl_source_path}' "
        f"'{devaic_input_path}'"
    )

    copy_result = subprocess.run(
        ["wsl", "bash", "-lc", copy_command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )

    if copy_result.returncode != 0:
        print("DeVAIC input copy failed:")
        print(copy_result.stderr)
        return []

    # Remember when this scan started.
    started_at = time.time()

    # Run DeVAIC.
    devaic_command = (
        f"cd '{DEVAIC_DIR}' && "
        f"./devaic.sh './input/{safe_filename}' ."
    )

    result = subprocess.run(
        ["wsl", "bash", "-lc", devaic_command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )

    if result.returncode != 0:
        print("DeVAIC execution failed:")
        print(result.stderr)
        return []

    # Find the newest JSON file produced by DeVAIC.
    list_command = (
        f"cd '{DEVAIC_DIR}/results' && "
        "ls -1t *.json 2>/dev/null | head -1"
    )

    list_result = subprocess.run(
        ["wsl", "bash", "-lc", list_command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )

    result_filename = list_result.stdout.strip()

    if not result_filename:
        print("DeVAIC completed but no JSON result was found.")
        return []

    # Get result file modification time.
    stat_command = (
        f"stat -c %Y "
        f"'{DEVAIC_DIR}/results/{result_filename}'"
    )

    stat_result = subprocess.run(
        ["wsl", "bash", "-lc", stat_command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )

    try:
        result_timestamp = float(stat_result.stdout.strip())
    except ValueError:
        print("Could not determine DeVAIC result timestamp.")
        return []

    # Protect against accidentally reading an old result.
    if result_timestamp < started_at - 5:
        print("DeVAIC result appears to be stale.")
        return []

    # Copy result from WSL to the Windows temporary directory.
    windows_result_path = os.path.join(
        output_dir,
        "devaic_output.json"
    )

    wsl_windows_result_path = windows_to_wsl_path(
        windows_result_path
    )

    copy_result_command = (
        f"cp '{DEVAIC_DIR}/results/{result_filename}' "
        f"'{wsl_windows_result_path}'"
    )

    result_copy = subprocess.run(
        ["wsl", "bash", "-lc", copy_result_command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )

    if result_copy.returncode != 0:
        print("Could not copy DeVAIC result to Windows.")
        print(result_copy.stderr)
        return []

    if not os.path.exists(windows_result_path):
        print("DeVAIC result file was not created.")
        return []

    try:
        return parse_devaic_output(windows_result_path)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Could not parse DeVAIC result: {exc}")
        return []


def run_analysis(
    code: str,
    filename: str = "submitted_code.py"
) -> List[Finding]:

    with tempfile.TemporaryDirectory() as tmp_dir:

        # ---------------------------------------------------------
        # 1. Write submitted code
        # ---------------------------------------------------------

        code_path = os.path.join(tmp_dir, filename)

        parent_dir = os.path.dirname(code_path)

        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        with open(code_path, "w", encoding="utf-8") as f:
            f.write(code)

        # ---------------------------------------------------------
        # 2. Semgrep
        # ---------------------------------------------------------

        semgrep_json_path = os.path.join(
            tmp_dir,
            "semgrep_output.json"
        )

        subprocess.run(
            [
                "semgrep",
                "scan",
                "--config",
                "auto",
                "--json",
                "--output",
                semgrep_json_path,
                code_path,
            ],
            capture_output=True,
            timeout=60,
        )

        # ---------------------------------------------------------
        # 3. Bandit
        # ---------------------------------------------------------

        bandit_json_path = os.path.join(
            tmp_dir,
            "bandit_output.json"
        )

        subprocess.run(
            [
                "bandit",
                "-f",
                "json",
                "-o",
                bandit_json_path,
                code_path,
            ],
            capture_output=True,
            timeout=60,
        )

        # ---------------------------------------------------------
        # 4. Normalize Semgrep + Bandit
        # ---------------------------------------------------------

        findings: List[Finding] = []

        if os.path.exists(semgrep_json_path):
            findings.extend(
                parse_semgrep_output(semgrep_json_path)
            )

        if os.path.exists(bandit_json_path):
            findings.extend(
                parse_bandit_output(bandit_json_path)
            )

        # ---------------------------------------------------------
        # 5. DeVAIC
        # ---------------------------------------------------------

        if filename.lower().endswith(".py"):
            devaic_findings = run_devaic(
                code_path=code_path,
                filename=filename,
                output_dir=tmp_dir,
            )

            findings.extend(devaic_findings)

        # ---------------------------------------------------------
        # 6. Return unified findings
        # ---------------------------------------------------------

        return findings