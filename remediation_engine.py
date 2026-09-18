import os
import json
from dotenv import load_dotenv
from google import genai

from models import Finding


load_dotenv()


class RemediationEngine:

    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise RuntimeError(
                "GEMINI_API_KEY not found in environment."
            )

        self.client = genai.Client(api_key=api_key)
        self.model = "gemini-3.6-flash"

    def generate_fix(self, code: str, finding: Finding):

        prompt_parts = [
            "You are a senior application security engineer.",
            "",
            "Analyze the following security finding in Python code.",
            "",
            "VULNERABLE CODE:",
            "```python",
            code,
            "```",
            "",
            "SECURITY FINDING:",
            f"Tool: {finding.tool}",
            f"Rule ID: {finding.rule_id}",
            f"CWE: CWE-{finding.cwe_id}",
            f"Severity: {finding.severity_raw}",
            f"Confidence: {finding.confidence}",
            f"Message: {finding.message}",
            "",
            "Your task:",
            "1. Explain the vulnerability.",
            "2. Explain why the code is dangerous.",
            "3. Provide a secure remediation approach.",
            "4. Produce the complete corrected Python code.",
            "5. Do not introduce new security vulnerabilities.",
            "6. Preserve the original functionality as much as reasonably possible.",
            "",
            "Return ONLY valid JSON with exactly these fields:",
            "{",
            '    "explanation": "...",',
            '    "secure_fix": "...",',
            '    "fixed_code": "..."',
            "}"
        ]

        prompt = "\n".join(prompt_parts)

        # Use Google's current Interactions API
        interaction = self.client.interactions.create(
            model=self.model,
            input=prompt
        )

        text = interaction.output_text.strip()

        # Remove Markdown code fences if Gemini adds them
        if text.startswith("```"):
            text = text.replace("```json", "")
            text = text.replace("```", "")
            text = text.strip()

        # Parse Gemini's JSON response
        try:
            result = json.loads(text)

        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"Gemini returned invalid JSON: {e}"
            )

        # Validate required response fields
        required_fields = {
            "explanation",
            "secure_fix",
            "fixed_code"
        }

        if not required_fields.issubset(result):
            raise RuntimeError(
                "Gemini response missing required fields."
            )

        return result