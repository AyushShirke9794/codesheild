import os
import json

from dotenv import load_dotenv
from google import genai
from google.genai import types

from models import Finding


load_dotenv()


class RemediationEngine:

    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise RuntimeError(
                "GEMINI_API_KEY not found in environment."
            )

        http_options = types.HttpOptions(
            timeout=60000,
            retry_options=types.HttpRetryOptions(
                attempts=3,
                initial_delay=1.0,
                max_delay=5.0,
                http_status_codes=[500, 502, 503, 504],
            ),
        )

        self.client = genai.Client(
            api_key=api_key,
            http_options=http_options
        )

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

        try:
            interaction = self.client.interactions.create(
                model=self.model,
                input=prompt
            )

        except Exception as e:
            error_text = str(e)

            if "429" in error_text:
                raise RuntimeError(
                    "Gemini API quota exhausted (HTTP 429). "
                    "Remediation is temporarily unavailable. "
                    "Try again after the quota resets."
                ) from e

            if "503" in error_text:
                raise RuntimeError(
                    "Gemini service temporarily unavailable (HTTP 503) "
                    "after the configured retries."
                ) from e

            raise RuntimeError(
                f"Gemini remediation request failed: {e}"
            ) from e

        text = interaction.output_text.strip()

        if not text:
            raise RuntimeError(
                "Gemini returned an empty response."
            )

        # Remove Markdown code fences if Gemini adds them.
        if text.startswith("```"):
            text = text.replace("```json", "")
            text = text.replace("```", "")
            text = text.strip()

        try:
            result = json.loads(text)

        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"Gemini returned invalid JSON: {e}"
            ) from e

        required_fields = {
            "explanation",
            "secure_fix",
            "fixed_code"
        }

        if not required_fields.issubset(result):
            missing = required_fields - set(result.keys())

            raise RuntimeError(
                f"Gemini response missing required fields: {missing}"
            )

        return result
