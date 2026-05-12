# scanner/sast_scanner.py
# SAST = Static Application Security Testing
# "Static" means we analyze the SOURCE CODE without running it
# This is like a grammar checker but for security vulnerabilities

import json
import subprocess  # Lets us run shell commands from Python
import sys
from pathlib import Path  # Better than os.path for file operations
from typing import Optional

from loguru import logger

from .scoring_engine import Finding, Severity, ScoringEngine


class SASTScanner:
    """
    Runs two SAST tools:
    1. Semgrep — rule-based scanner with thousands of community rules
    2. Bandit — Python-specific security linter

    Why two tools?
    - Semgrep has broader language support and rule library
    - Bandit is deeper for Python-specific patterns
    - Using both reduces false negatives (missed vulnerabilities)
    """

    def __init__(self):
        # Initialize the scoring engine — we'll use it to normalize findings
        self.scoring_engine = ScoringEngine()

    def _run_command(self, command: list[str]) -> tuple[str, str, int]:
        """
        Runs a shell command safely and returns its output.

        command: list of strings — e.g. ["semgrep", "--json", "src/"]
        Returns: (stdout, stderr, return_code)

        Why use subprocess instead of os.system()?
        - subprocess gives us the output as a Python string
        - os.system() just prints to the terminal and returns a number
        - subprocess is more secure — avoids shell injection vulnerabilities
        """
        try:
            # subprocess.run() runs the command and waits for it to finish
            # capture_output=True: capture stdout and stderr as strings
            # text=True: decode bytes to string automatically
            # timeout: kill the process if it takes too long
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minutes maximum
            )
            return result.stdout, result.stderr, result.returncode

        except subprocess.TimeoutExpired:
            logger.warning(f"Command timed out: {' '.join(command)}")
            return "", "Timeout", 1

        except FileNotFoundError:
            # This happens if the tool isn't installed
            tool_name = command[0]
            logger.error(f"Tool not found: {tool_name}. Is it installed?")
            return "", f"{tool_name} not found", 1

    def run_semgrep(self, target_path: str) -> list[Finding]:
        """
        Runs Semgrep on the target path and parses its JSON output.

        target_path: directory or file to scan
        Returns: list of Finding objects
        """
        logger.info(f"Starting Semgrep scan on: {target_path}")

        # Build the Semgrep command
        # --config=auto: use Semgrep's auto-detection of which rules to apply
        # --json: output results as JSON (easier to parse than plain text)
        # --no-git-ignore: scan all files even if they're in .gitignore
        # --quiet: don't print progress to stdout (we want only JSON)
        command = [
            "semgrep",
            "--config=auto",    # Use community rules + detect language automatically
            "--json",           # JSON output for programmatic parsing
            "--no-git-ignore",  # Scan everything
            "--quiet",
            target_path,        # What to scan
        ]

        stdout, stderr, return_code = self._run_command(command)

        # Semgrep returns 0 for clean, 1 for findings, other codes for errors
        if return_code not in [0, 1]:
            logger.error(f"Semgrep error: {stderr}")
            return []

        # Parse the JSON output
        # If stdout is empty, return an empty list
        if not stdout.strip():
            return []

        try:
            # json.loads() converts a JSON string into a Python dict
            semgrep_output = json.loads(stdout)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep JSON: {e}")
            return []

        findings = []

        # semgrep_output["results"] is a list of finding dicts
        # Each dict has: check_id, path, start, extra (message, severity, metadata)
        for result in semgrep_output.get("results", []):
            # Extract fields from the Semgrep result dict
            # .get() safely handles missing keys — returns None if key doesn't exist
            vuln_type = result.get("check_id", "unknown").split(".")[-1]
            file_path = result.get("path", "unknown")
            line_number = result.get("start", {}).get("line")
            description = result.get("extra", {}).get("message", "")

            # Semgrep puts severity in extra.severity
            raw_severity = result.get("extra", {}).get("severity", "INFO")
            severity = self.scoring_engine.normalize_semgrep_severity(raw_severity)

            # Get CWE and OWASP metadata if available
            metadata = result.get("extra", {}).get("metadata", {})
            cwe = metadata.get("cwe", [])
            owasp = metadata.get("owasp", [])

            # Build the remediation message from metadata
            fix = metadata.get("fix", "Review and remediate according to OWASP guidelines")

            # Create a Finding object
            finding = Finding(
                scanner="semgrep",
                vuln_type=vuln_type,
                file_path=file_path,
                line_number=line_number,
                description=description,
                severity=severity,
                remediation=fix,
                raw_output=result,
            )

            # Score it — sets cvss_score
            finding = self.scoring_engine.calculate_score(finding)

            # Generate a unique ID for deduplication
            # We hash the file+line+type so the same finding across runs is the same ID
            import hashlib
            finding.finding_id = hashlib.md5(
                f"{file_path}{line_number}{vuln_type}".encode()
            ).hexdigest()[:12]

            findings.append(finding)

        logger.info(f"Semgrep found {len(findings)} findings")
        return findings

    def run_bandit(self, target_path: str) -> list[Finding]:
        """
        Runs Bandit on Python code specifically.
        Bandit understands Python's AST (Abstract Syntax Tree)
        and can detect Python-specific security issues.
        """
        logger.info(f"Starting Bandit scan on: {target_path}")

        command = [
            "bandit",
            "-r",       # -r = recursive (scan all .py files in subdirectories)
            "-f", "json",  # Output format: JSON
            "-q",          # Quiet mode
            target_path,
        ]

        stdout, stderr, return_code = self._run_command(command)

        # Bandit returns 1 if findings are found — that's normal, not an error
        if return_code not in [0, 1]:
            logger.error(f"Bandit error: {stderr}")
            return []

        if not stdout.strip():
            return []

        try:
            bandit_output = json.loads(stdout)
        except json.JSONDecodeError:
            return []

        findings = []

        # Bandit results are in bandit_output["results"]
        # Each result has: filename, line_number, test_id, issue_text, 
        #                  issue_severity, issue_confidence
        for result in bandit_output.get("results", []):
            raw_severity = result.get("issue_severity", "LOW")
            severity = self.scoring_engine.normalize_bandit_severity(raw_severity)

            # Bandit gives us a "test_id" like "B608" (SQL injection)
            # We use this as the vulnerability type
            test_id = result.get("test_id", "unknown")
            test_name = result.get("test_name", "unknown")

            finding = Finding(
                scanner="bandit",
                vuln_type=f"{test_id}_{test_name}",
                file_path=result.get("filename", ""),
                line_number=result.get("line_number"),
                description=result.get("issue_text", ""),
                severity=severity,
                remediation=f"See https://bandit.readthedocs.io/en/latest/plugins/{test_id.lower()}.html",
                raw_output=result,
            )

            finding = self.scoring_engine.calculate_score(finding)
            findings.append(finding)

        logger.info(f"Bandit found {len(findings)} findings")
        return findings

    def scan(self, target_path: str) -> dict:
        """
        Main method — runs both Semgrep and Bandit and combines results.
        
        Returns a dict with:
        - findings: all Finding objects
        - summary: counts by severity
        - passed: whether this scan should pass
        """
        # Run both scanners
        semgrep_findings = self.run_semgrep(target_path)
        bandit_findings = self.run_bandit(target_path)

        # Combine all findings
        all_findings = semgrep_findings + bandit_findings

        # Calculate overall risk
        risk = self.scoring_engine.calculate_pipeline_risk(all_findings)

        return {
            "scanner": "sast",
            "findings": all_findings,
            "risk": risk,
            "tool_counts": {
                "semgrep": len(semgrep_findings),
                "bandit":  len(bandit_findings),
            }
        }