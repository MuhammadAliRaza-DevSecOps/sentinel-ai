# scanner/container_scanner.py
# Docker images scan karta hai
# Trivy OS packages, Python packages, aur Dockerfile misconfigs check karta hai

import json
import subprocess
import hashlib
from loguru import logger
from .scoring_engine import Finding, Severity, ScoringEngine


class ContainerScanner:
    """
    Trivy se Docker images scan karta hai.
    
    Trivy kya check karta hai:
    1. OS packages — Ubuntu/Alpine packages mein CVEs
    2. Application packages — pip, npm, etc.
    3. Misconfigurations — Dockerfile best practices
    4. Secrets — image layers mein hidden secrets
    """

    def __init__(self):
        self.scoring_engine = ScoringEngine()

    def _run_command(self, command: list[str]) -> tuple[str, str, int]:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=600)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Timeout: image bahut bari hai", 1
        except FileNotFoundError:
            return "", "trivy not found — sudo apt install trivy", 127

    def scan_image(self, image_name: str) -> list[Finding]:
        """
        Docker image scan karta hai.
        
        image_name: "myapp:latest" ya "nginx:1.24" ya GHCR image
        """
        logger.info(f"Trivy image scan: {image_name}")

        command = [
            "trivy",
            "image",
            "--format", "json",
            "--quiet",
            "--timeout", "10m",
            # Severity filter — sirf yeh levels report karo
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            image_name,
        ]

        stdout, stderr, return_code = self._run_command(command)

        if not stdout.strip():
            logger.warning(f"Trivy output empty for {image_name}")
            return []

        try:
            trivy_data = json.loads(stdout)
        except json.JSONDecodeError as e:
            logger.error(f"Trivy JSON error: {e}")
            return []

        findings = []

        # Trivy output mein "Results" array hai
        # Har result ek layer ya package manager hai
        # Har result mein "Vulnerabilities" list hai
        for result in trivy_data.get("Results", []):
            target = result.get("Target", "")           # e.g., "python:3.11"
            result_type = result.get("Type", "")         # e.g., "python-pkg", "ubuntu"
            
            for vuln in result.get("Vulnerabilities", []) or []:
                cve_id        = vuln.get("VulnerabilityID", "unknown")
                pkg_name      = vuln.get("PkgName", "unknown")
                installed_ver = vuln.get("InstalledVersion", "unknown")
                fixed_ver     = vuln.get("FixedVersion", "No fix available")
                title         = vuln.get("Title", "")
                description   = vuln.get("Description", "")[:300]
                cvss_nvd      = vuln.get("CVSS", {}).get("nvd", {})
                cvss_score    = cvss_nvd.get("V3Score", 0.0)
                raw_severity  = vuln.get("Severity", "UNKNOWN")

                severity = self.scoring_engine.normalize_trivy_severity(raw_severity)

                finding = Finding(
                    scanner="trivy",
                    vuln_type=f"container_vulnerability_{result_type}",
                    file_path=f"image:{image_name} → {target}",
                    line_number=None,
                    description=(
                        f"{cve_id}: {pkg_name}=={installed_ver}. "
                        f"{title}. {description}"
                    ),
                    severity=severity,
                    remediation=(
                        f"Update {pkg_name} to {fixed_ver}. "
                        f"Dockerfile mein: RUN pip install {pkg_name}>={fixed_ver} "
                        f"ya base image update karo."
                    ),
                    raw_output=vuln,
                )

                if cvss_score > 0:
                    finding.cvss_score = cvss_score
                else:
                    finding = self.scoring_engine.calculate_score(finding)

                finding.finding_id = hashlib.md5(
                    f"{image_name}{cve_id}{pkg_name}".encode()
                ).hexdigest()[:12]

                findings.append(finding)

        logger.info(f"Trivy image scan: {len(findings)} vulnerabilities")
        return findings

    def scan_dockerfile(self, dockerfile_path: str) -> list[Finding]:
        """
        Dockerfile ki misconfigurations dhundta hai.
        
        Kya check karta hai:
        - Root user se running (security risk)
        - COPY . . (unnecessary files copy ho sakte hain)
        - No HEALTHCHECK
        - Latest tag use karna (unpinned versions)
        - Secrets in ENV variables
        """
        logger.info(f"Trivy Dockerfile scan: {dockerfile_path}")

        command = [
            "trivy",
            "config",
            "--format", "json",
            "--quiet",
            dockerfile_path,
        ]

        stdout, stderr, return_code = self._run_command(command)

        findings = []

        if not stdout.strip():
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return []

        for result in data.get("Results", []):
            for misconfig in result.get("Misconfigurations", []) or []:
                mis_id       = misconfig.get("ID", "unknown")
                mis_title    = misconfig.get("Title", "")
                mis_desc     = misconfig.get("Description", "")
                mis_severity = misconfig.get("Severity", "LOW")
                resolution   = misconfig.get("Resolution", "")

                severity = self.scoring_engine.normalize_trivy_severity(mis_severity)

                finding = Finding(
                    scanner="trivy_config",
                    vuln_type=f"dockerfile_misconfiguration",
                    file_path=dockerfile_path,
                    line_number=misconfig.get("CauseMetadata", {}).get("StartLine"),
                    description=f"{mis_id}: {mis_title}. {mis_desc}",
                    severity=severity,
                    remediation=resolution,
                    raw_output=misconfig,
                )

                finding = self.scoring_engine.calculate_score(finding)
                findings.append(finding)

        logger.info(f"Dockerfile misconfigs: {len(findings)}")
        return findings

    def scan(self, image_name: str, dockerfile_path: str = "docker/Dockerfile") -> dict:
        """Image aur Dockerfile dono scan karo."""
        image_findings      = self.scan_image(image_name)
        dockerfile_findings = self.scan_dockerfile(dockerfile_path)
        all_findings        = image_findings + dockerfile_findings
        risk                = self.scoring_engine.calculate_pipeline_risk(all_findings)

        return {
            "scanner": "container",
            "findings": all_findings,
            "risk": risk,
            "tool_counts": {
                "image_vulns":      len(image_findings),
                "dockerfile_issues": len(dockerfile_findings),
            }
        }