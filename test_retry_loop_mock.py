from agents.orchestrator_agent import OrchestratorAgent
from agents.contracts import AgentResult

VULNERABLE_CODE = """import subprocess

def run(cmd):
    subprocess.call(cmd, shell=True)
"""

SECURE_CODE = """import subprocess

def run(cmd):
    subprocess.call(cmd, shell=False)
"""


def make_fake_remediation(fixed_code_by_attempt):
    call_count = {"n": 0}

    def fake_run(input_data):
        call_count["n"] += 1
        attempt = call_count["n"]
        fixed_code = fixed_code_by_attempt.get(
            attempt, fixed_code_by_attempt[max(fixed_code_by_attempt)]
        )
        return AgentResult(
            agent_name="RemediationAgent",
            success=True,
            data={
                "explanation": f"Mock remediation, attempt {attempt}",
                "secure_fix": "mock secure fix",
                "fixed_code": fixed_code,
                "finding": input_data["finding"],
            },
            message="Mocked remediation",
        ).__dict__

    return fake_run, call_count


def make_fake_verification(verified_by_attempt):
    call_count = {"n": 0}

    def fake_run(input_data):
        call_count["n"] += 1
        attempt = call_count["n"]
        verified = verified_by_attempt.get(
            attempt, verified_by_attempt[max(verified_by_attempt)]
        )
        original_finding = input_data["original_finding"]

        verification_data = {
            "verified": verified,
            "original_vulnerability_fixed": verified,
            "regression_detected": False,
            "functional_equivalent": True,
            "functional_tests_passed": 1 if verified else 0,
            "functional_tests_failed": 0 if verified else 1,
            "original_finding": original_finding,
            "remaining_findings": [],
            "new_findings": [],
            "status": "PASS" if verified else "FAIL",
        }

        return AgentResult(
            agent_name="VerificationAgent",
            success=True,
            data={"verification": verification_data},
            message="Mocked verification",
        ).__dict__

    return fake_run, call_count


def run_scenario(name, fixed_code_by_attempt, verified_by_attempt, max_attempts):
    print(f"\n=== {name} ===")

    orchestrator = OrchestratorAgent()
    fake_remediation, remediation_calls = make_fake_remediation(fixed_code_by_attempt)
    fake_verification, verification_calls = make_fake_verification(verified_by_attempt)

    orchestrator.remediation_agent.run = fake_remediation
    orchestrator.verification_agent.run = fake_verification

    output = orchestrator.run({
        "code": VULNERABLE_CODE,
        "filename": "mock_test.py",
        "max_attempts": max_attempts,
    })

    print("success:", output["success"])
    print("message:", output["message"])
    print("remediation attempts made:", remediation_calls["n"])
    print("verification attempts made:", verification_calls["n"])
    print("reanalysis calls made:", len(output["data"].get("reanalysis_history", [])))

    if "trust_gate" in output["data"]:
        tg = output["data"]["trust_gate"]
        decision = tg["data"]["decision"]
        print("trust gate decision:", decision.decision, "|", decision.reason)


# Scenario A: fails on attempt 1, succeeds on attempt 2.
run_scenario(
    "Scenario A: retry succeeds on attempt 2",
    fixed_code_by_attempt={1: VULNERABLE_CODE, 2: SECURE_CODE},
    verified_by_attempt={1: False, 2: True},
    max_attempts=2,
)

# Scenario B: fails on every attempt, max_attempts=2 should stop the loop.
run_scenario(
    "Scenario B: always fails, max_attempts=2 should stop the loop",
    fixed_code_by_attempt={1: VULNERABLE_CODE, 2: VULNERABLE_CODE},
    verified_by_attempt={1: False, 2: False},
    max_attempts=2,
)