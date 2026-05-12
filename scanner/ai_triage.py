# scanner/ai_triage.py
# OpenAI NAHI — Ollama use karta hai (local, free)
# phi3:mini model se findings triage karta hai
# False positives reduce karta hai

import httpx
import json
from loguru import logger
from .scoring_engine import Finding, Severity


class AITriage:
    """
    Local Ollama se findings triage karta hai.
    
    Kya karta hai:
    - False positives identify karta hai
    - Findings ko plain English mein explain karta hai
    - Fix suggestions deta hai
    - Risk assessment karta hai
    
    Ollama locally run hota hai — koi data bahar nahi jata
    phi3:mini fast aur lightweight hai
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "phi3:mini",
    ):
        self.base_url = base_url
        self.model    = model
        self.api_url  = f"{base_url}/api/generate"

    def _is_ollama_running(self) -> bool:
        """Check karo Ollama chal raha hai ya nahi."""
        try:
            with httpx.Client(timeout=3) as c:
                r = c.get(f"{self.base_url}/api/tags")
                return r.status_code == 200
        except Exception:
            return False

    def _ask_ollama(self, prompt: str, max_tokens: int = 300) -> str:
        """
        Ollama API call karo.
        
        Ollama ka /api/generate endpoint use karta hai.
        stream=False matlab pura response ek baar mein aaye.
        """
        if not self._is_ollama_running():
            logger.warning("Ollama nahi chal raha — AI triage skip")
            return ""

        payload = {
            "model":  self.model,
            "prompt": prompt,
            "stream": False,           # Ek baar mein pura response
            "options": {
                "temperature": 0.1,    # Low temperature = consistent answers
                "num_predict": max_tokens,
            },
        }

        try:
            with httpx.Client(timeout=60) as c:
                response = c.post(self.api_url, json=payload)
                response.raise_for_status()
                data = response.json()
                return data.get("response", "").strip()
        except httpx.TimeoutException:
            logger.warning("Ollama timeout — phi3:mini slow ho sakta hai pehli baar")
            return ""
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            return ""

    def triage_finding(self, finding: Finding) -> dict:
        """
        Ek finding ko AI se analyze karao.
        
        Returns dict with:
        - is_false_positive: bool
        - confidence: float (0-1)
        - explanation: plain English
        - suggested_fix: specific fix
        - risk_context: why it matters
        """
        prompt = f"""You are a cybersecurity expert. Analyze this security finding briefly.

Finding:
- Type: {finding.vuln_type}
- Scanner: {finding.scanner}
- File: {finding.file_path}
- Line: {finding.line_number}
- Severity: {finding.severity.value}
- Description: {finding.description[:300]}

Answer in JSON only, no extra text:
{{
  "is_false_positive": true or false,
  "confidence": 0.0 to 1.0,
  "explanation": "one sentence plain English",
  "suggested_fix": "specific code fix",
  "risk_context": "why this is dangerous"
}}"""

        response = self._ask_ollama(prompt, max_tokens=400)

        if not response:
            return self._default_triage(finding)

        # JSON parse karo — Ollama kabhi kabhi extra text deta hai
        try:
            # JSON block dhundo response mein
            start = response.find("{")
            end   = response.rfind("}") + 1
            if start != -1 and end > start:
                json_str = response[start:end]
                result   = json.loads(json_str)

                return {
                    "is_false_positive": bool(result.get("is_false_positive", False)),
                    "confidence":        float(result.get("confidence", 0.5)),
                    "explanation":       str(result.get("explanation", "")),
                    "suggested_fix":     str(result.get("suggested_fix", "")),
                    "risk_context":      str(result.get("risk_context", "")),
                    "ai_model":          self.model,
                }
        except (json.JSONDecodeError, ValueError) as e:
            logger.debug(f"JSON parse error: {e}")

        return self._default_triage(finding)

    def _default_triage(self, finding: Finding) -> dict:
        """AI unavailable ho to default response."""
        return {
            "is_false_positive": False,
            "confidence":        0.5,
            "explanation":       f"{finding.vuln_type} detected by {finding.scanner}",
            "suggested_fix":     finding.remediation or "Review and fix manually",
            "risk_context":      f"Severity: {finding.severity.value}",
            "ai_model":          "unavailable",
        }

    def triage_batch(self, findings: list[Finding], max_findings: int = 10) -> list[dict]:
        """
        Multiple findings triage karo.
        
        Sirf top findings triage karo (zyada time laggta hai).
        Critical aur High ko priority dete hain.
        """
        if not self._is_ollama_running():
            logger.info("Ollama nahi chal raha — batch triage skip")
            return [self._default_triage(f) for f in findings[:max_findings]]

        # Critical aur High pehle sort karo
        sorted_findings = sorted(
            findings,
            key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
                f.severity.value, 4
            )
        )

        results = []
        # Sirf top N findings triage karo
        for finding in sorted_findings[:max_findings]:
            logger.debug(f"AI triage: {finding.vuln_type} in {finding.file_path}")
            result = self.triage_finding(finding)
            results.append(result)

        confirmed_real = sum(1 for r in results if not r["is_false_positive"])
        logger.info(
            f"AI triage complete: {len(results)} findings, "
            f"{confirmed_real} real, "
            f"{len(results)-confirmed_real} false positives"
        )

        return results

    def generate_scan_summary(self, findings: list[Finding], risk: dict) -> str:
        """
        Poori scan ka AI summary generate karo.
        Dashboard aur reports mein use hota hai.
        """
        if not self._is_ollama_running() or not findings:
            return "AI summary unavailable — Ollama nahi chal raha."

        counts = risk.get("counts", {})
        top_findings = [
            f"{f.vuln_type} ({f.severity.value}) in {f.file_path}"
            for f in sorted(
                findings,
                key=lambda x: x.cvss_score,
                reverse=True
            )[:5]
        ]

        prompt = f"""Security scan completed. Write a brief 3-sentence executive summary.

Results:
- Risk Level: {risk.get('risk_level')}
- Critical: {counts.get('critical', 0)}
- High: {counts.get('high', 0)}
- Medium: {counts.get('medium', 0)}
- Top issues: {', '.join(top_findings)}

Write plain English summary for a developer. Be specific and actionable. 3 sentences max."""

        summary = self._ask_ollama(prompt, max_tokens=200)
        return summary if summary else "Scan complete. Review findings above."