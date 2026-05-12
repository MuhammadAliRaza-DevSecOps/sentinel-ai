# scanner/sca_scanner.py
# SCA = Software Composition Analysis
# Aapke project ki dependencies mein CVE (vulnerabilities) dhundta hai
# Jaise: requests==2.25.0 mein ek known SQLi vulnerability ho sakti hai

import json
import subprocess
from loguru import logger
from .scoring_engine import Finding, Severity, ScoringEngine


class SCAScanner:
    """
    Dependencies ki vulnerabilities scan karta hai.
    
    Tools:
    1. safety — PyUp.io ka database use karta hai
    2. pip-audit — Google ka tool, PyPI advisory database use karta hai
    
    Dono kyun?
    - Alag databases hain — ek jo nahi pakdega doosra pakdega
    - pip-audit zyada up-to-date hai
    - safety ka database larger hai
    """

    def __init__(self):
        self.scoring_engine = ScoringEngine()

    def _run_command(self, command: list[str]) -> tuple[str, str, int]:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=180)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Timeout", 1
        except FileNotFoundError:
            return "", f"{command[0]} not found", 127

    def run_safety(self, requirements_file: str = "requirements.txt") -> list[Finding]:
        """
        Safety check run karta hai.
        Safety har dependency ko PyUp.io CVE database se match karta hai.
        """
        logger.info(f"Safety check: {requirements_file}")

        command = [
            "safety",
            "check",
            "--file", requirements_file,
            "--json",
            "--full-report",    # Zyada detail
        ]

        stdout, stderr, return_code = self._run_command(command)

        findings = []

        if not stdout.strip():
            return []

        try:
            safety_data = json.loads(stdout)
        except json.JSONDecodeError:
            logger.error("Safety JSON parse error")
            return []

        # Safety output format:
        # List of [package_name, affected_version, installed_version, 
        #          vulnerability_id, advisory, cvss_score]
        vulnerabilities = safety_data.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
            package_name     = vuln.get("package_name", "unknown")
            installed_ver    = vuln.get("analyzed_version", "unknown")
            vulnerability_id = vuln.get("vulnerability_id", "unknown")
            advisory         = vuln.get("advisory", "")
            cvss             = vuln.get("cvss", {})
            cvss_score       = cvss.get("cvssv3", {}).get("base_score", 0.0)

            # CVSS score se severity decide karo
            if cvss_score >= 9.0:
                severity = Severity.CRITICAL
            elif cvss_score >= 7.0:
                severity = Severity.HIGH
            elif cvss_score >= 4.0:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

            finding = Finding(
                scanner="safety",
                vuln_type=f"vulnerable_dependency",
                file_path=requirements_file,
                line_number=None,   # Dependency files mein exact line nahi hoti
                description=(
                    f"Package '{package_name}' version {installed_ver} "
                    f"mein vulnerability hai: {vulnerability_id}. "
                    f"{advisory[:200]}"  # Advisory ke pehle 200 characters
                ),
                severity=severity,
                remediation=(
                    f"'pip install {package_name} --upgrade' run karo "
                    f"ya requirements.txt mein patched version pin karo"
                ),
                raw_output=vuln,
            )

            # CVSS score directly set karo (safety ne already calculate kiya)
            if cvss_score > 0:
                finding.cvss_score = cvss_score
            else:
                finding = self.scoring_engine.calculate_score(finding)

            findings.append(finding)

        logger.info(f"Safety: {len(findings)} vulnerable dependencies mili")
        return findings

    def run_pip_audit(self, requirements_file: str = "requirements.txt") -> list[Finding]:
        """
        pip-audit run karta hai.
        pip-audit PyPI Advisory Database (GHSA) use karta hai.
        """
        logger.info(f"pip-audit: {requirements_file}")

        command = [
            "pip-audit",
            "--requirement", requirements_file,
            "--format", "json",
            "--progress-spinner", "off",
        ]

        stdout, stderr, return_code = self._run_command(command)

        findings = []

        if not stdout.strip():
            return []

        try:
            audit_data = json.loads(stdout)
        except json.JSONDecodeError:
            return []

        # pip-audit output:
        # {"dependencies": [{"name": "package", "version": "x.y.z", 
        #                     "vulns": [{"id": "GHSA-...", "fix_versions": [...]}]}]}
        
        for dep in audit_data.get("dependencies", []):
            package_name = dep.get("name", "")
            installed_ver = dep.get("version", "")
            
            for vuln in dep.get("vulns", []):
                vuln_id = vuln.get("id", "unknown")
                description = vuln.get("description", "")
                fix_versions = vuln.get("fix_versions", [])
                aliases = vuln.get("aliases", [])  # CVE numbers

                # CVE se severity guess karo
                # GHSA IDs mein severity hoti hai: GHSA-xxxx-xxxx-HIGH
                severity = Severity.HIGH  # Default HIGH for unpatched deps

                finding = Finding(
                    scanner="pip_audit",
                    vuln_type="vulnerable_dependency",
                    file_path=requirements_file,
                    line_number=None,
                    description=(
                        f"{package_name}=={installed_ver}: {vuln_id}. "
                        f"CVEs: {', '.join(aliases)}. "
                        f"{description[:200]}"
                    ),
                    severity=severity,
                    remediation=(
                        f"Fix versions: {', '.join(fix_versions) if fix_versions else 'Latest version use karo'}. "
                        f"Command: pip install {package_name}>={fix_versions[0] if fix_versions else 'latest'}"
                    ),
                    raw_output=vuln,
                )

                finding = self.scoring_engine.calculate_score(finding)
                findings.append(finding)

        logger.info(f"pip-audit: {len(findings)} findings")
        return findings

    def scan(self, requirements_file: str = "requirements.txt") -> dict:
        """Dono tools run karo aur merge karo."""
        safety_findings  = self.run_safety(requirements_file)
        pip_audit_findings = self.run_pip_audit(requirements_file)

        all_findings = safety_findings + pip_audit_findings

        # Deduplication — same package ki same CVE ko ek baar count karo
        seen = set()
        unique = []
        for f in all_findings:
            # Package name + CVE ID se unique key banao
            key = f"{f.file_path}:{f.vuln_type}:{f.description[:50]}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        risk = self.scoring_engine.calculate_pipeline_risk(unique)

        return {
            "scanner": "sca",
            "findings": unique,
            "risk": risk,
            "tool_counts": {
                "safety": len(safety_findings),
                "pip_audit": len(pip_audit_findings),
            }
        }