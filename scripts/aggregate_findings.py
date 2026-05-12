# scripts/aggregate_findings.py
# GitHub Actions mein use hota hai — saare scanner outputs combine karta hai
# python scripts/aggregate_findings.py --results-dir scan-results/ --output final-report.json

import argparse
import json
import os
import glob
from pathlib import Path
from datetime import datetime
import sys

# Project root ko Python path mein add karo
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.scoring_engine import ScoringEngine, Finding, Severity


def load_json_file(filepath: str) -> dict | list | None:
    """JSON file load karo, errors handle karo."""
    try:
        with open(filepath, "r") as f:
            content = f.read().strip()
            if not content or content == "null":
                return None
            return json.loads(content)
    except (json.JSONDecodeError, FileNotFoundError):
        return None


def parse_semgrep(data: dict) -> list[dict]:
    """Semgrep JSON se findings extract karo."""
    findings = []
    if not data or "results" not in data:
        return findings
    
    for result in data["results"]:
        findings.append({
            "scanner":    "semgrep",
            "vuln_type":  result.get("check_id", "unknown").split(".")[-1],
            "file_path":  result.get("path", ""),
            "line_number":result.get("start", {}).get("line"),
            "description":result.get("extra", {}).get("message", ""),
            "severity":   _map_semgrep_severity(result.get("extra", {}).get("severity", "INFO")),
            "cvss_score": 0.0,
            "remediation":"Review OWASP guidelines",
        })
    return findings


def parse_bandit(data: dict) -> list[dict]:
    """Bandit JSON se findings extract karo."""
    findings = []
    if not data or "results" not in data:
        return findings
    
    sev_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    for result in data["results"]:
        findings.append({
            "scanner":    "bandit",
            "vuln_type":  f"{result.get('test_id','')}_{result.get('test_name','')}",
            "file_path":  result.get("filename", ""),
            "line_number":result.get("line_number"),
            "description":result.get("issue_text", ""),
            "severity":   sev_map.get(result.get("issue_severity","LOW"), "low"),
            "cvss_score": 0.0,
            "remediation":"Bandit docs dekhein",
        })
    return findings


def parse_trivy(data: dict) -> list[dict]:
    """Trivy JSON se findings extract karo."""
    findings = []
    if not data or "Results" not in data:
        return findings
    
    sev_map = {
        "CRITICAL": "critical", "HIGH": "high",
        "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "info"
    }
    for result in data["Results"]:
        for vuln in result.get("Vulnerabilities") or []:
            raw_sev = vuln.get("Severity", "UNKNOWN")
            cvss = vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", 0.0)
            findings.append({
                "scanner":    "trivy",
                "vuln_type":  "container_vulnerability",
                "file_path":  f"image:{result.get('Target','')}",
                "line_number":None,
                "description":f"{vuln.get('VulnerabilityID')}: {vuln.get('PkgName')}=={vuln.get('InstalledVersion')} — {vuln.get('Title','')}",
                "severity":   sev_map.get(raw_sev, "info"),
                "cvss_score": cvss,
                "remediation":f"Update to: {vuln.get('FixedVersion','latest')}",
            })
    return findings


def _map_semgrep_severity(sev: str) -> str:
    return {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(sev.upper(), "info")


def calculate_cvss_scores(findings: list[dict]) -> list[dict]:
    """Findings jo missing CVSS hain unhe score karo."""
    engine = ScoringEngine()
    for f in findings:
        if f.get("cvss_score", 0) == 0:
            sev_map = {
                "critical": Severity.CRITICAL, "high": Severity.HIGH,
                "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO
            }
            severity = sev_map.get(f.get("severity", "info"), Severity.INFO)
            temp = Finding(
                scanner=f["scanner"], vuln_type=f["vuln_type"],
                file_path=f["file_path"], line_number=f["line_number"],
                description=f["description"], severity=severity,
            )
            scored = engine.calculate_score(temp)
            f["cvss_score"] = scored.cvss_score
    return findings


def main():
    parser = argparse.ArgumentParser(description="Security scan results aggregate karo")
    parser.add_argument("--results-dir", required=True, help="Scan results directory")
    parser.add_argument("--output", required=True, help="Output JSON file")
    parser.add_argument("--fail-on-critical", default="true")
    parser.add_argument("--fail-on-high-count", default="5", type=int)
    args = parser.parse_args()

    results_dir = Path(args.results_dir)
    all_findings = []

    print(f"📁 Results directory: {results_dir}")

    # Saare JSON files dhundo aur parse karo
    for json_file in results_dir.rglob("*.json"):
        print(f"  Processing: {json_file.name}")
        data = load_json_file(str(json_file))
        if not data:
            continue

        name = json_file.name.lower()
        
        if "semgrep" in name:
            all_findings.extend(parse_semgrep(data))
        elif "bandit" in name:
            all_findings.extend(parse_bandit(data))
        elif "trivy" in name and "dockerfile" not in name:
            all_findings.extend(parse_trivy(data))

    print(f"\n📊 Total raw findings: {len(all_findings)}")

    # CVSS scores calculate karo
    all_findings = calculate_cvss_scores(all_findings)

    # Count by severity
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1

    # Pass/Fail decision
    fail_on_critical = args.fail_on_critical.lower() == "true"
    should_fail = (
        (fail_on_critical and counts["critical"] >= 1) or
        counts["high"] >= args.fail_on_high_count
    )
    
    risk_level = "FAIL" if should_fail else ("WARN" if counts["high"] >= 1 else "PASS")
    risk_score = (
        counts["critical"] * 10 + counts["high"] * 5 +
        counts["medium"] * 2 + counts["low"] * 1
    )

    # Final report
    report = {
        "schema_version": "1.0",
        "generated_at":   datetime.utcnow().isoformat(),
        "risk_level":     risk_level,
        "should_fail":    should_fail,
        "risk_score":     risk_score,
        "counts":         counts,
        "total_findings": len(all_findings),
        "findings":       sorted(all_findings, key=lambda x: x.get("cvss_score", 0), reverse=True),
    }

    # File mein save karo
    output_path = Path(args.output)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"\n{'='*50}")
    print(f"🔴 Critical: {counts['critical']}")
    print(f"🟠 High:     {counts['high']}")
    print(f"🟡 Medium:   {counts['medium']}")
    print(f"🟢 Low:      {counts['low']}")
    print(f"{'='*50}")
    print(f"Result: {risk_level}")
    print(f"Report: {output_path}")

    # Exit code — 1 = fail karo, 0 = pass karo
    sys.exit(1 if should_fail else 0)


if __name__ == "__main__":
    main()