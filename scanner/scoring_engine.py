# scanner/scoring_engine.py
# This file calculates a risk score for each security finding
# CVSS = Common Vulnerability Scoring System — the industry standard for rating vulnerabilities

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# loguru gives us better formatted logs than Python's built-in logging
from loguru import logger


class Severity(Enum):
    """
    Enum = a set of named constants.
    We use an Enum here so severity can only be one of these exact values.
    If code tries to set severity="CRITAL" (typo), Python raises an error immediately.
    """
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """
    @dataclass automatically generates __init__, __repr__, __eq__ methods.
    This represents one security finding from any scanner.
    Using a dataclass means we get free constructor and string representation.
    """
    # The scanner that found this issue: "sast", "secret", "sca", "container", "dast"
    scanner: str

    # The type of vulnerability: "SQL Injection", "Hardcoded Secret", etc.
    vuln_type: str

    # Where it was found
    file_path: str
    line_number: Optional[int]  # Optional = might be None (container findings have no line number)

    # Description of what was found
    description: str

    # Severity will be set by the scoring engine below
    severity: Severity = Severity.INFO

    # CVSS score: 0.0 to 10.0
    # 0-3.9 = Low, 4.0-6.9 = Medium, 7.0-8.9 = High, 9.0-10.0 = Critical
    cvss_score: float = 0.0

    # Recommended fix
    remediation: str = ""

    # Raw output from the scanner tool (stored for reference)
    raw_output: dict = field(default_factory=dict)

    # Was this finding confirmed by AI triage? (reduces false positives)
    ai_confirmed: Optional[bool] = None

    # Unique identifier for deduplication
    finding_id: str = ""


class ScoringEngine:
    """
    The scoring engine takes raw findings from different scanners
    and normalizes them into a consistent severity + CVSS score.

    Why normalize? Each tool uses different scoring systems:
    - Bandit uses LOW/MEDIUM/HIGH
    - Semgrep uses ERROR/WARNING/INFO
    - Trivy uses CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN
    We need them all on the same scale.
    """

    # These CVSS mappings are based on the CVSS v3.1 base score ranges
    # Source: https://www.first.org/cvss/specification-document
    CVSS_RANGES = {
        Severity.CRITICAL: (9.0, 10.0),
        Severity.HIGH:     (7.0, 8.9),
        Severity.MEDIUM:   (4.0, 6.9),
        Severity.LOW:      (0.1, 3.9),
        Severity.INFO:     (0.0, 0.0),
    }

    # Vulnerability type weights — some vuln types are inherently more severe
    # These multipliers adjust the base score up or down
    VULN_TYPE_WEIGHTS = {
        "sql_injection":          1.0,   # Full weight — SQLi is critical
        "command_injection":      1.0,   # Full weight — RCE potential
        "hardcoded_secret":       0.95,  # Very high — immediate credential exposure
        "hardcoded_password":     0.95,
        "api_key_exposed":        0.95,
        "path_traversal":         0.85,
        "xxe":                    0.85,  # XML External Entity
        "deserialization":        0.9,
        "ssrf":                   0.85,  # Server-Side Request Forgery
        "xss":                    0.7,
        "open_redirect":          0.5,
        "weak_cryptography":      0.6,
        "insecure_random":        0.4,
        "missing_auth":           0.8,
        "broken_access_control":  0.85,
        "default":                0.5,   # Unknown vuln types get 50% weight
    }

    def calculate_score(self, finding: Finding) -> Finding:
        """
        Takes a raw Finding and assigns a severity and CVSS score.
        Returns the same Finding with severity and cvss_score set.
        """
        # Get the weight for this vulnerability type
        # .lower() converts to lowercase so "SQL_INJECTION" matches "sql_injection"
        # .get() returns the default value if the key doesn't exist in the dict
        vuln_key = finding.vuln_type.lower().replace(" ", "_").replace("-", "_")
        weight = self.VULN_TYPE_WEIGHTS.get(vuln_key, self.VULN_TYPE_WEIGHTS["default"])

        # Get the CVSS range for the reported severity
        low_range, high_range = self.CVSS_RANGES[finding.severity]

        # Calculate a score within the range based on the weight
        # If severity=HIGH (7.0-8.9) and weight=0.9:
        # score = 7.0 + (8.9 - 7.0) * 0.9 = 7.0 + 1.71 = 8.71
        if high_range > 0:
            score = low_range + (high_range - low_range) * weight
        else:
            score = 0.0

        # Round to 1 decimal place — CVSS standard format
        finding.cvss_score = round(score, 1)

        logger.debug(f"Scored finding: {finding.vuln_type} → {finding.severity.value} (CVSS: {finding.cvss_score})")
        return finding

    def normalize_bandit_severity(self, severity_str: str) -> Severity:
        """
        Bandit (Python SAST tool) uses: LOW, MEDIUM, HIGH
        Map these to our Severity enum.
        """
        mapping = {
            "HIGH":   Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW":    Severity.LOW,
        }
        # .upper() ensures case-insensitive matching
        # .get() with a default means unknown values become INFO
        return mapping.get(severity_str.upper(), Severity.INFO)

    def normalize_semgrep_severity(self, severity_str: str) -> Severity:
        """
        Semgrep uses: ERROR, WARNING, INFO
        """
        mapping = {
            "ERROR":   Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO":    Severity.LOW,
        }
        return mapping.get(severity_str.upper(), Severity.INFO)

    def normalize_trivy_severity(self, severity_str: str) -> Severity:
        """
        Trivy uses: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
        This maps cleanly to our Severity enum.
        """
        mapping = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH":     Severity.HIGH,
            "MEDIUM":   Severity.MEDIUM,
            "LOW":      Severity.LOW,
            "UNKNOWN":  Severity.INFO,
        }
        return mapping.get(severity_str.upper(), Severity.INFO)

    def calculate_pipeline_risk(self, findings: list[Finding]) -> dict:
        """
        Given all findings from a scan, calculate the overall pipeline risk.
        This determines whether the CI/CD pipeline should PASS or FAIL.

        Returns a dict with:
        - risk_level: "PASS", "WARN", or "FAIL"
        - summary: counts by severity
        - should_fail: boolean — whether to fail the build
        """
        # Count findings by severity using a dict comprehension
        # {severity: count for severity in all severities}
        counts = {
            "critical": 0,
            "high":     0,
            "medium":   0,
            "low":      0,
            "info":     0,
        }

        for finding in findings:
            # .value gives us the string from the enum: Severity.HIGH → "high"
            severity_key = finding.severity.value
            counts[severity_key] += 1

        # Calculate the total weighted risk score
        # Critical findings weigh 10x, High 5x, Medium 2x, Low 1x
        risk_score = (
            counts["critical"] * 10 +
            counts["high"] * 5 +
            counts["medium"] * 2 +
            counts["low"] * 1
        )

        # Determine pass/fail based on thresholds
        # These mirror what you set in your .env file
        should_fail = counts["critical"] >= 1 or counts["high"] >= 5

        if counts["critical"] >= 1:
            risk_level = "FAIL"
            reason = f"Found {counts['critical']} critical vulnerability/vulnerabilities"
        elif counts["high"] >= 5:
            risk_level = "FAIL"
            reason = f"Found {counts['high']} high-severity findings (threshold: 5)"
        elif counts["high"] >= 1 or counts["medium"] >= 10:
            risk_level = "WARN"
            reason = "High or numerous medium findings detected"
        else:
            risk_level = "PASS"
            reason = "No critical or blocking findings"

        logger.info(f"Pipeline risk assessment: {risk_level} — {reason}")

        return {
            "risk_level":   risk_level,
            "should_fail":  should_fail,
            "reason":       reason,
            "risk_score":   risk_score,
            "counts":       counts,
            "total":        sum(counts.values()),
        }