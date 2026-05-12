# tests/test_api.py
# FastAPI endpoints ke tests
# Run: pytest tests/test_api.py -v

import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, ASGITransport

# FastAPI test client import
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────
# App import — agar database nahi hai to mock karo
# ─────────────────────────────────────────────
@pytest.fixture
def mock_db_session():
    """Database session ko mock karo — real DB chahiye nahi tests ke liye."""
    session = AsyncMock()
    session.get = AsyncMock(return_value=None)
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.execute = AsyncMock()
    return session


@pytest.fixture
def sample_scan_result():
    """Test ke liye sample scan data."""
    return {
        "scan_id": "test-scan-123",
        "risk_level": "FAIL",
        "should_fail": True,
        "risk_score": 25,
        "counts": {
            "critical": 2,
            "high": 3,
            "medium": 5,
            "low": 10,
            "info": 2,
        },
        "findings": [
            {
                "finding_id": "abc123",
                "scanner": "semgrep",
                "vuln_type": "sql_injection",
                "file_path": "app/db.py",
                "line_number": 42,
                "description": "SQL injection vulnerability found",
                "severity": "critical",
                "cvss_score": 9.8,
                "remediation": "Use parameterized queries",
            }
        ],
        "branch": "main",
        "commit_sha": "abc1234567890",
        "duration_ms": 5000,
        "triggered_by": "test",
    }


@pytest.fixture
def sample_findings_list():
    """Multiple findings for testing."""
    return [
        {
            "finding_id": "001",
            "scanner": "bandit",
            "vuln_type": "hardcoded_password",
            "file_path": "config.py",
            "line_number": 10,
            "description": "Hardcoded password detected",
            "severity": "critical",
            "cvss_score": 9.5,
            "remediation": "Use environment variables",
        },
        {
            "finding_id": "002",
            "scanner": "trivy",
            "vuln_type": "container_vulnerability",
            "file_path": "image:myapp:latest",
            "line_number": None,
            "description": "CVE-2024-1234: requests==2.25.0",
            "severity": "high",
            "cvss_score": 7.5,
            "remediation": "Update requests to 2.32.0",
        },
        {
            "finding_id": "003",
            "scanner": "semgrep",
            "vuln_type": "xss",
            "file_path": "views/user.py",
            "line_number": 88,
            "description": "Cross-site scripting vulnerability",
            "severity": "medium",
            "cvss_score": 6.1,
            "remediation": "Sanitize user input",
        },
    ]


# ─────────────────────────────────────────────
# Scoring Engine Tests (no DB needed)
# ─────────────────────────────────────────────
class TestScoringEngineIntegration:
    """Integration tests for scoring engine with realistic data."""

    def test_full_scan_risk_calculation(self, sample_findings_list):
        """Real findings list se risk calculate karo."""
        from scanner.scoring_engine import ScoringEngine, Finding, Severity

        engine = ScoringEngine()

        findings = []
        for f in sample_findings_list:
            sev_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
            }
            finding = Finding(
                scanner=f["scanner"],
                vuln_type=f["vuln_type"],
                file_path=f["file_path"],
                line_number=f["line_number"],
                description=f["description"],
                severity=sev_map[f["severity"]],
            )
            findings.append(finding)

        result = engine.calculate_pipeline_risk(findings)

        # Critical findings hain to FAIL hona chahiye
        assert result["risk_level"] == "FAIL"
        assert result["should_fail"] is True
        assert result["counts"]["critical"] == 1
        assert result["counts"]["high"] == 1
        assert result["counts"]["medium"] == 1

    def test_risk_score_calculation(self):
        """Risk score correctly calculate hona chahiye."""
        from scanner.scoring_engine import ScoringEngine, Finding, Severity

        engine = ScoringEngine()

        # 2 critical (each = 10) + 1 high (= 5) = 25
        findings = []
        for i in range(2):
            findings.append(Finding(
                scanner="test", vuln_type="sql_injection",
                file_path=f"file{i}.py", line_number=i,
                description="test", severity=Severity.CRITICAL,
            ))
        findings.append(Finding(
            scanner="test", vuln_type="xss",
            file_path="file3.py", line_number=3,
            description="test", severity=Severity.HIGH,
        ))

        result = engine.calculate_pipeline_risk(findings)
        assert result["risk_score"] == 25  # 2*10 + 1*5

    def test_severity_normalization_all_tools(self):
        """Saare tools ki severity correctly normalize ho."""
        from scanner.scoring_engine import ScoringEngine, Severity

        engine = ScoringEngine()

        # Bandit
        assert engine.normalize_bandit_severity("HIGH") == Severity.HIGH
        assert engine.normalize_bandit_severity("MEDIUM") == Severity.MEDIUM
        assert engine.normalize_bandit_severity("LOW") == Severity.LOW
        assert engine.normalize_bandit_severity("INVALID") == Severity.INFO

        # Semgrep
        assert engine.normalize_semgrep_severity("ERROR") == Severity.HIGH
        assert engine.normalize_semgrep_severity("WARNING") == Severity.MEDIUM
        assert engine.normalize_semgrep_severity("INFO") == Severity.LOW

        # Trivy
        assert engine.normalize_trivy_severity("CRITICAL") == Severity.CRITICAL
        assert engine.normalize_trivy_severity("HIGH") == Severity.HIGH
        assert engine.normalize_trivy_severity("UNKNOWN") == Severity.INFO


# ─────────────────────────────────────────────
# Report Generator Tests
# ─────────────────────────────────────────────
class TestReportGenerator:
    """Report generation tests."""

    def test_markdown_report_contains_required_sections(self, sample_scan_result, tmp_path):
        """Markdown report mein required sections honi chahiye."""
        from reports.report_generator import ReportGenerator

        generator = ReportGenerator(output_dir=str(tmp_path))
        report = generator.generate_markdown(sample_scan_result)

        # Required sections check karo
        assert "Security Scan Report" in report
        assert "FAIL" in report
        assert "Critical" in report
        assert sample_scan_result["scan_id"] in report
        assert "main" in report  # branch name

    def test_markdown_report_finding_details(self, sample_scan_result, tmp_path):
        """Finding details report mein hone chahiye."""
        from reports.report_generator import ReportGenerator

        generator = ReportGenerator(output_dir=str(tmp_path))
        report = generator.generate_markdown(sample_scan_result)

        # Finding info check
        assert "sql_injection" in report
        assert "app/db.py" in report
        assert "9.8" in report  # CVSS score

    def test_json_summary_structure(self, sample_scan_result, tmp_path):
        """JSON summary correct structure hona chahiye."""
        from reports.report_generator import ReportGenerator

        generator = ReportGenerator(output_dir=str(tmp_path))
        summary = generator.generate_json_summary(sample_scan_result)

        # Required keys check karo
        assert "schema_version" in summary
        assert "risk_level" in summary
        assert "counts" in summary
        assert "top_findings" in summary
        assert "result" in summary

        # Values check
        assert summary["risk_level"] == "FAIL"
        assert summary["result"]["should_fail"] is True
        assert summary["counts"]["critical"] == 2

    def test_report_saved_to_file(self, sample_scan_result, tmp_path):
        """Report file mein save honi chahiye."""
        from reports.report_generator import ReportGenerator

        generator = ReportGenerator(output_dir=str(tmp_path))
        generator.generate_markdown(sample_scan_result, output_file="test_report.md")

        report_file = tmp_path / "test_report.md"
        assert report_file.exists()
        assert report_file.stat().st_size > 0

    def test_json_report_saved_to_file(self, sample_scan_result, tmp_path):
        """JSON report file mein save honi chahiye."""
        from reports.report_generator import ReportGenerator

        generator = ReportGenerator(output_dir=str(tmp_path))
        generator.generate_json_summary(sample_scan_result, output_file="test_report.json")

        report_file = tmp_path / "test_report.json"
        assert report_file.exists()

        # Valid JSON hona chahiye
        content = json.loads(report_file.read_text())
        assert isinstance(content, dict)


# ─────────────────────────────────────────────
# Aggregate Findings Script Tests
# ─────────────────────────────────────────────
class TestAggregateFindingsScript:
    """aggregate_findings.py script tests."""

    def test_parse_semgrep_output(self):
        """Semgrep JSON correctly parse ho."""
        from scripts.aggregate_findings import parse_semgrep

        # Sample Semgrep output format
        semgrep_data = {
            "results": [
                {
                    "check_id": "python.django.security.audit.raw-query.raw-query",
                    "path": "app/views.py",
                    "start": {"line": 25},
                    "extra": {
                        "message": "Raw SQL query detected",
                        "severity": "ERROR",
                        "metadata": {"fix": "Use ORM instead"},
                    }
                }
            ]
        }

        findings = parse_semgrep(semgrep_data)

        assert len(findings) == 1
        assert findings[0]["scanner"] == "semgrep"
        assert findings[0]["file_path"] == "app/views.py"
        assert findings[0]["line_number"] == 25
        assert findings[0]["severity"] == "high"  # ERROR maps to high

    def test_parse_bandit_output(self):
        """Bandit JSON correctly parse ho."""
        from scripts.aggregate_findings import parse_bandit

        bandit_data = {
            "results": [
                {
                    "test_id": "B608",
                    "test_name": "hardcoded_sql_expressions",
                    "filename": "app/db.py",
                    "line_number": 42,
                    "issue_text": "Possible SQL injection via string concatenation",
                    "issue_severity": "HIGH",
                    "issue_confidence": "MEDIUM",
                }
            ]
        }

        findings = parse_bandit(bandit_data)

        assert len(findings) == 1
        assert findings[0]["scanner"] == "bandit"
        assert findings[0]["severity"] == "high"
        assert findings[0]["line_number"] == 42

    def test_parse_trivy_output(self):
        """Trivy JSON correctly parse ho."""
        from scripts.aggregate_findings import parse_trivy

        trivy_data = {
            "Results": [
                {
                    "Target": "python:3.11",
                    "Type": "python-pkg",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1234",
                            "PkgName": "requests",
                            "InstalledVersion": "2.25.0",
                            "FixedVersion": "2.32.0",
                            "Severity": "HIGH",
                            "Title": "SSRF vulnerability",
                            "CVSS": {"nvd": {"V3Score": 7.5}},
                        }
                    ]
                }
            ]
        }

        findings = parse_trivy(trivy_data)

        assert len(findings) == 1
        assert findings[0]["scanner"] == "trivy"
        assert findings[0]["severity"] == "high"
        assert findings[0]["cvss_score"] == 7.5

    def test_empty_inputs_return_empty_list(self):
        """Empty/None inputs se crash nahi hona chahiye."""
        from scripts.aggregate_findings import parse_semgrep, parse_bandit, parse_trivy

        assert parse_semgrep({}) == []
        assert parse_semgrep(None) == []
        assert parse_bandit({}) == []
        assert parse_trivy({}) == []
        assert parse_trivy({"Results": []}) == []


# ─────────────────────────────────────────────
# Enforce Gate Tests
# ─────────────────────────────────────────────
class TestEnforceGate:
    """enforce_gate.py tests."""

    def test_gate_fails_on_critical(self, tmp_path):
        """Critical findings pe gate fail karna chahiye."""
        import subprocess
        import sys

        # Test report create karo
        report = {
            "risk_level": "FAIL",
            "should_fail": True,
            "counts": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
        }
        report_file = tmp_path / "report.json"
        report_file.write_text(json.dumps(report))

        result = subprocess.run(
            [sys.executable, "scripts/enforce_gate.py", "--report", str(report_file)],
            capture_output=True, text=True
        )

        # Exit code 1 hona chahiye — pipeline fail
        assert result.returncode == 1
        assert "FAILED" in result.stdout

    def test_gate_passes_on_clean(self, tmp_path):
        """Koi critical nahi — gate pass karna chahiye."""
        import subprocess
        import sys

        report = {
            "risk_level": "PASS",
            "should_fail": False,
            "counts": {"critical": 0, "high": 0, "medium": 2, "low": 5, "info": 1},
        }
        report_file = tmp_path / "report.json"
        report_file.write_text(json.dumps(report))

        result = subprocess.run(
            [sys.executable, "scripts/enforce_gate.py", "--report", str(report_file)],
            capture_output=True, text=True
        )

        assert result.returncode == 0
        assert "PASS" in result.stdout

    def test_gate_handles_missing_file(self, tmp_path):
        """Missing file pe graceful error."""
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "scripts/enforce_gate.py",
             "--report", str(tmp_path / "nonexistent.json")],
            capture_output=True, text=True
        )

        assert result.returncode == 1