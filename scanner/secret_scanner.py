# scanner/secret_scanner.py
# Secret scanning = code mein chupi hui API keys, passwords, tokens dhundna
# Gitleaks aur trufflehog dono use karte hain — zyada coverage ke liye

import json
import subprocess
import os
import hashlib
from pathlib import Path
from typing import Optional
from loguru import logger

from .scoring_engine import Finding, Severity, ScoringEngine


class SecretScanner:
    """
    Do tools use karta hai:
    1. Gitleaks — git history + current files scan karta hai
    2. trufflehog — entropy analysis + regex patterns use karta hai
    
    Entropy analysis kya hai?
    Agar koi string bahut "random" lagti hai (jaise API key),
    uski Shannon entropy high hoti hai — tool yeh detect karta hai
    """

    def __init__(self):
        self.scoring_engine = ScoringEngine()

    def _run_command(self, command: list[str], timeout: int = 120) -> tuple[str, str, int]:
        """Shell command run karta hai aur output return karta hai."""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            logger.warning(f"Command timeout: {' '.join(command)}")
            return "", "Timeout", 1
        except FileNotFoundError:
            logger.error(f"Tool not found: {command[0]} — please install it")
            return "", f"{command[0]} not found", 127

    def run_gitleaks(self, target_path: str) -> list[Finding]:
        """
        Gitleaks run karta hai.
        
        Gitleaks kya karta hai:
        - Git commits history scan karta hai
        - 150+ secret patterns check karta hai (AWS keys, GitHub tokens, etc.)
        - SARIF ya JSON format mein output deta hai
        """
        logger.info(f"Gitleaks scan shuru: {target_path}")

        # Output file path
        output_file = "/tmp/gitleaks-output.json"

        command = [
            "gitleaks",
            "detect",                    # "detect" mode = scan karo
            "--source", target_path,     # Kahan scan karna hai
            "--report-format", "json",   # JSON output chahiye
            "--report-path", output_file,# Output file
            "--no-banner",               # Logo mat print karo
            "--exit-code", "0",          # Findings pe bhi exit 0 do
        ]

        stdout, stderr, return_code = self._run_command(command)

        # Output file padhte hain
        findings = []
        try:
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    content = f.read().strip()
                    if not content or content == "null":
                        logger.info("Gitleaks: koi secrets nahi mile")
                        return []
                    gitleaks_data = json.loads(content)
            else:
                logger.warning("Gitleaks output file nahi mili")
                return []
        except json.JSONDecodeError as e:
            logger.error(f"Gitleaks JSON parse error: {e}")
            return []

        # Har finding ko process karo
        for result in gitleaks_data if isinstance(gitleaks_data, list) else []:
            # Gitleaks fields:
            # RuleID: kis pattern ne match kiya (e.g., "aws-access-token")
            # File: kahan mila
            # StartLine: kis line pe
            # Secret: actual leaked value (hum ise mask karte hain)
            # Description: kya mila

            rule_id = result.get("RuleID", "unknown")
            secret_value = result.get("Secret", "")
            
            # Secret ko mask karo — full value log mein mat daalo
            # Pehle 4 aur aakhri 4 characters dikhao, baaki asterisk
            if len(secret_value) > 8:
                masked_secret = secret_value[:4] + "****" + secret_value[-4:]
            else:
                masked_secret = "****"

            finding = Finding(
                scanner="gitleaks",
                vuln_type=f"exposed_secret_{rule_id}",
                file_path=result.get("File", "unknown"),
                line_number=result.get("StartLine"),
                description=f"Secret detected: {result.get('Description', rule_id)} — Value: {masked_secret}",
                severity=Severity.CRITICAL,  # Har secret CRITICAL hai — immediate action chahiye
                remediation=(
                    f"1. Yeh secret TURANT revoke karo\n"
                    f"2. Code se remove karo\n"
                    f"3. .env file mein daalo\n"
                    f"4. git filter-repo se history se bhi hatao\n"
                    f"5. Naya secret generate karo"
                ),
                raw_output=result,
            )

            finding = self.scoring_engine.calculate_score(finding)
            
            # Unique ID — same finding ko dobara count nahi karna
            finding.finding_id = hashlib.md5(
                f"{finding.file_path}{finding.line_number}{rule_id}".encode()
            ).hexdigest()[:12]

            findings.append(finding)
            logger.warning(f"SECRET MILA: {rule_id} in {finding.file_path}:{finding.line_number}")

        logger.info(f"Gitleaks total: {len(findings)} secrets mile")
        return findings

    def run_trufflehog(self, target_path: str) -> list[Finding]:
        """
        trufflehog v3 run karta hai.
        
        trufflehog ki khaasiyat:
        - Entropy analysis — random-looking strings detect karta hai
        - 700+ detectors — specific service patterns jaanta hai
        - Verified secrets — actually check karta hai ke secret valid hai ya nahi
        """
        logger.info(f"trufflehog scan shuru: {target_path}")

        command = [
            "trufflehog",
            "filesystem",           # Filesystem scan karo (git ke alawa bhi)
            target_path,
            "--json",               # JSON output
            "--no-update",          # Update check mat karo
        ]

        stdout, stderr, return_code = self._run_command(command, timeout=180)

        findings = []
        
        if not stdout.strip():
            return []

        # trufflehog har finding ko alag JSON line pe output karta hai (JSONL format)
        # Yeh normal JSON se different hai — har line ek complete JSON object hai
        for line in stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                continue

            # trufflehog fields:
            # DetectorName: kis service ka secret hai (AWS, GitHub, Slack, etc.)
            # Verified: kya yeh actually valid hai?
            # Raw: actual secret value
            # SourceMetadata: file aur line info

            detector = result.get("DetectorName", "unknown")
            verified = result.get("Verified", False)
            
            # Verified secrets zyada critical hain
            severity = Severity.CRITICAL if verified else Severity.HIGH

            source_meta = result.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
            file_path = source_meta.get("file", "unknown")
            line_num = source_meta.get("line")

            raw_secret = result.get("Raw", "")
            masked = raw_secret[:4] + "****" if len(raw_secret) > 4 else "****"

            finding = Finding(
                scanner="trufflehog",
                vuln_type=f"credential_leak_{detector.lower()}",
                file_path=file_path,
                line_number=line_num,
                description=(
                    f"{detector} credential exposed. "
                    f"Verified: {'YES — ACTIVE CREDENTIAL' if verified else 'Unverified'}. "
                    f"Value: {masked}"
                ),
                severity=severity,
                remediation=(
                    f"1. {detector} credential TURANT revoke karo\n"
                    f"2. Code se remove karo, .env mein daalo\n"
                    f"3. Git history clean karo: git filter-repo\n"
                    f"4. Naya credential generate karo"
                ),
                raw_output=result,
            )

            finding = self.scoring_engine.calculate_score(finding)
            findings.append(finding)

        logger.info(f"trufflehog total: {len(findings)} findings")
        return findings

    def scan(self, target_path: str) -> dict:
        """
        Dono tools run karo aur results combine karo.
        Duplicates bhi remove karo — agar dono tools same secret pakdein.
        """
        gitleaks_findings = self.run_gitleaks(target_path)
        trufflehog_findings = self.run_trufflehog(target_path)

        all_findings = gitleaks_findings + trufflehog_findings

        # Deduplication — same file+line+type ke findings merge karo
        seen = set()
        unique_findings = []
        for f in all_findings:
            key = f"{f.file_path}:{f.line_number}:{f.vuln_type}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        risk = self.scoring_engine.calculate_pipeline_risk(unique_findings)

        return {
            "scanner": "secret",
            "findings": unique_findings,
            "risk": risk,
            "tool_counts": {
                "gitleaks": len(gitleaks_findings),
                "trufflehog": len(trufflehog_findings),
                "after_dedup": len(unique_findings),
            }
        }