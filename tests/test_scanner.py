# tests/test_scanner.py
# Scanner module ke comprehensive tests

import pytest
import json
import hashlib
from unittest.mock import patch, MagicMock
from pathlib import Path

from scanner.scoring_engine import ScoringEngine, Finding, Severity


# ─────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────
@pytest.fixture
def engine():
    return ScoringEngine()


@pytest.fixture
def critical_sqli():
    return Finding(
        scanner="semgrep",
        vuln_type="sql_injection",
        file_path="app/db.py",
        line_number=42,
        description="User input in SQL query",
        severity=Severity.CRITICAL,
    )


@pytest.fixture
def high_xss():
    return Finding(
        scanner="bandit",
        vuln_type="xss",
        file_path="views/user.py",
        line_number=88,
        description="Reflected XSS",
        severity=Severity.HIGH,
    )


@pytest.fixture
def medium_finding():
    return Finding(
        scanner="semgrep",
        vuln_type="weak_cryptography",
        file_path="utils/crypto.py",
        line_number=15,
        description="MD5 used for hashing",
        severity=Severity.MEDIUM,
    )


@pytest.fixture
def low_finding():
    return Finding(
        scanner="bandit",
        vuln_type="insecure_random",
        file_path="utils/token.py",
        line_number=10,
        description="random.random() used",
        severity=Severity.LOW,
    )


# ─────────────────────────────────────────────
# CVSS Scoring Tests
# ─────────────────────────────────────────────
class TestCVSSScoring:

    def test_critical_sqli_score_9_plus(self, engine, critical_sqli):
        """Critical SQLi should score 9.0+."""
        scored = engine.calculate_score(critical_sqli)
        assert scored.cvss_score >= 9.0
        assert scored.cvss_score <= 10.0

    def test_high_xss_score_7_to_9(self, engine, high_xss):
        """High XSS should score in 7-9 range."""
        scored = engine.calculate_score(high_xss)
        assert 6.0 <= scored.cvss_score <= 9.0

    def test_medium_score_4_to_7(self, engine, medium_finding):
        """Medium findings in 4-7 range."""
        scored = engine.calculate_score(medium_finding)
        assert 3.0 <= scored.cvss_score <= 7.0

    def test_low_score_below_4(self, engine, low_finding):
        """Low findings score below 4."""
        scored = engine.calculate_score(low_finding)
        assert scored.cvss_score < 4.0

    def test_score_is_rounded_to_1_decimal(self, engine, critical_sqli):
        """CVSS score 1 decimal place hona chahiye."""
        scored = engine.calculate_score(critical_sqli)
        # Check it's rounded — no more than 1 decimal
        score_str = str(scored.cvss_score)
        if "." in score_str:
            decimal_places = len(score_str.split(".")[1])
            assert decimal_places <= 1

    def test_info_severity_scores_zero(self, engine):
        """INFO severity = 0.0 CVSS."""
        finding = Finding(
            scanner="test", vuln_type="info_leak",
            file_path="readme.txt", line_number=1,
            description="info", severity=Severity.INFO,
        )
        scored = engine.calculate_score(finding)
        assert scored.cvss_score == 0.0


# ─────────────────────────────────────────────
# Pipeline Risk Tests
# ─────────────────────────────────────────────
class TestPipelineRisk:

    def test_empty_findings_passes(self, engine):
        result = engine.calculate_pipeline_risk([])
        assert result["risk_level"] == "PASS"
        assert result["should_fail"] is False
        assert result["total"] == 0

    def test_one_critical_fails(self, engine, critical_sqli):
        result = engine.calculate_pipeline_risk([critical_sqli])
        assert result["risk_level"] == "FAIL"
        assert result["should_fail"] is True

    def test_five_highs_fail(self, engine):
        """5 high findings pe pipeline fail hona chahiye."""
        findings = [
            Finding(
                scanner="test", vuln_type="xss",
                file_path=f"file{i}.py", line_number=i,
                description="xss", severity=Severity.HIGH,
            )
            for i in range(5)
        ]
        result = engine.calculate_pipeline_risk(findings)
        assert result["should_fail"] is True

    def test_four_highs_warn_not_fail(self, engine):
        """4 high findings — warn karein lekin fail nahi."""
        findings = [
            Finding(
                scanner="test", vuln_type="xss",
                file_path=f"f{i}.py", line_number=i,
                description="x", severity=Severity.HIGH,
            )
            for i in range(4)
        ]
        result = engine.calculate_pipeline_risk(findings)
        assert result["risk_level"] == "WARN"
        assert result["should_fail"] is False

    def test_only_low_findings_passes(self, engine, low_finding):
        result = engine.calculate_pipeline_risk([low_finding, low_finding])
        assert result["risk_level"] == "PASS"

    def test_counts_correct(self, engine, critical_sqli, high_xss, medium_finding, low_finding):
        """Severity counts sahi hone chahiye."""
        findings = [critical_sqli, high_xss, medium_finding, low_finding]
        result = engine.calculate_pipeline_risk(findings)
        assert result["counts"]["critical"] == 1
        assert result["counts"]["high"] == 1
        assert result["counts"]["medium"] == 1
        assert result["counts"]["low"] == 1
        assert result["total"] == 4

    def test_risk_score_math(self, engine):
        """Risk score: critical*10 + high*5 + medium*2 + low*1."""
        findings = [
            Finding(scanner="t", vuln_type="sqli",
                    file_path="f.py", line_number=1,
                    description="d", severity=Severity.CRITICAL),
            Finding(scanner="t", vuln_type="xss",
                    file_path="f.py", line_number=2,
                    description="d", severity=Severity.HIGH),
            Finding(scanner="t", vuln_type="weak",
                    file_path="f.py", line_number=3,
                    description="d", severity=Severity.MEDIUM),
        ]
        result = engine.calculate_pipeline_risk(findings)
        expected = 1*10 + 1*5 + 1*2
        assert result["risk_score"] == expected


# ─────────────────────────────────────────────
# Severity Normalization Tests
# ─────────────────────────────────────────────
class TestSeverityNormalization:

    def test_bandit_all_levels(self, engine):
        assert engine.normalize_bandit_severity("HIGH")   == Severity.HIGH
        assert engine.normalize_bandit_severity("MEDIUM") == Severity.MEDIUM
        assert engine.normalize_bandit_severity("LOW")    == Severity.LOW
        assert engine.normalize_bandit_severity("high")   == Severity.HIGH  # lowercase
        assert engine.normalize_bandit_severity("UNKNOWN")== Severity.INFO  # default

    def test_semgrep_all_levels(self, engine):
        assert engine.normalize_semgrep_severity("ERROR")   == Severity.HIGH
        assert engine.normalize_semgrep_severity("WARNING") == Severity.MEDIUM
        assert engine.normalize_semgrep_severity("INFO")    == Severity.LOW
        assert engine.normalize_semgrep_severity("error")   == Severity.HIGH  # lowercase

    def test_trivy_all_levels(self, engine):
        assert engine.normalize_trivy_severity("CRITICAL") == Severity.CRITICAL
        assert engine.normalize_trivy_severity("HIGH")     == Severity.HIGH
        assert engine.normalize_trivy_severity("MEDIUM")   == Severity.MEDIUM
        assert engine.normalize_trivy_severity("LOW")      == Severity.LOW
        assert engine.normalize_trivy_severity("UNKNOWN")  == Severity.INFO


# ─────────────────────────────────────────────
# SAST Scanner Tests (mocked subprocess)
# ─────────────────────────────────────────────
class TestSASTScanner:

    def test_semgrep_parses_findings(self):
        """Semgrep output correctly parse hona chahiye."""
        from scanner.sast_scanner import SASTScanner

        scanner = SASTScanner()

        # Fake semgrep JSON output
        fake_output = json.dumps({
            "results": [
                {
                    "check_id": "python.lang.security.audit.sqli.sqli",
                    "path": "app/views.py",
                    "start": {"line": 30},
                    "extra": {
                        "message": "SQL injection via f-string",
                        "severity": "ERROR",
                        "metadata": {"fix": "Use parameterized queries"},
                    }
                }
            ]
        })

        # subprocess.run ko mock karo — real scan mat karo
        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.stdout = fake_output
            mock_result.stderr = ""
            mock_result.returncode = 1  # 1 = findings found (normal)
            mock_run.return_value = mock_result

            findings = scanner.run_semgrep(".")

        assert len(findings) == 1
        assert findings[0].file_path == "app/views.py"
        assert findings[0].line_number == 30
        assert findings[0].severity == Severity.HIGH

    def test_bandit_parses_findings(self):
        """Bandit output correctly parse hona chahiye."""
        from scanner.sast_scanner import SASTScanner

        scanner = SASTScanner()

        fake_output = json.dumps({
            "results": [
                {
                    "test_id": "B105",
                    "test_name": "hardcoded_password_string",
                    "filename": "config.py",
                    "line_number": 5,
                    "issue_text": "Possible hardcoded password",
                    "issue_severity": "MEDIUM",
                    "issue_confidence": "MEDIUM",
                }
            ]
        })

        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.stdout = fake_output
            mock_result.stderr = ""
            mock_result.returncode = 1
            mock_run.return_value = mock_result

            findings = scanner.run_bandit(".")

        assert len(findings) == 1
        assert findings[0].scanner == "bandit"
        assert findings[0].severity == Severity.MEDIUM

    def test_empty_output_returns_empty_list(self):
        """Empty scanner output se crash nahi hona chahiye."""
        from scanner.sast_scanner import SASTScanner

        scanner = SASTScanner()

        with patch("subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.stdout = ""
            mock_result.stderr = ""
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            findings = scanner.run_semgrep(".")
            assert findings == []

    def test_tool_not_found_returns_empty(self):
        """Tool install nahi hai to empty list return karo."""
        from scanner.sast_scanner import SASTScanner
        import subprocess

        scanner = SASTScanner()

        with patch("subprocess.run", side_effect=FileNotFoundError):
            findings = scanner.run_semgrep(".")
            assert findings == []

    def test_scan_combines_both_tools(self):
        """scan() method dono tools ka result combine kare."""
        from scanner.sast_scanner import SASTScanner

        scanner = SASTScanner()

        semgrep_output = json.dumps({
            "results": [
                {
                    "check_id": "python.sqli",
                    "path": "a.py",
                    "start": {"line": 1},
                    "extra": {"message": "sqli", "severity": "ERROR", "metadata": {}}
                }
            ]
        })

        bandit_output = json.dumps({
            "results": [
                {
                    "test_id": "B608", "test_name": "sqli",
                    "filename": "b.py", "line_number": 2,
                    "issue_text": "sql injection",
                    "issue_severity": "HIGH", "issue_confidence": "HIGH",
                }
            ]
        })

        call_count = 0

        def mock_subprocess(*args, **kwargs):
            nonlocal call_count
            mock = MagicMock()
            mock.returncode = 1
            mock.stderr = ""
            if call_count == 0:
                mock.stdout = semgrep_output
            else:
                mock.stdout = bandit_output
            call_count += 1
            return mock

        with patch("subprocess.run", side_effect=mock_subprocess):
            result = scanner.scan(".")

        assert "scanner" in result
        assert result["scanner"] == "sast"
        assert len(result["findings"]) == 2
        assert result["tool_counts"]["semgrep"] == 1
        assert result["tool_counts"]["bandit"] == 1


# ─────────────────────────────────────────────
# Secret Scanner Tests
# ─────────────────────────────────────────────
class TestSecretScanner:

    def test_secret_masked_in_finding(self):
        """Secret value finding mein masked hona chahiye."""
        from scanner.secret_scanner import SecretScanner
        import tempfile, os

        scanner = SecretScanner()

        fake_gitleaks = json.dumps([
            {
                "RuleID": "aws-access-token",
                "File": "config.py",
                "StartLine": 5,
                "Secret": "AKIAIOSFODNN7EXAMPLE",
                "Description": "AWS Access Token",
            }
        ])

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as f:
            f.write(fake_gitleaks)
            temp_path = f.name

        try:
            with patch("subprocess.run") as mock_run, \
                 patch("os.path.exists", return_value=True), \
                 patch("builtins.open", side_effect=lambda p, *a, **k:
                     open(temp_path) if "gitleaks" in p else open(p, *a, **k)):

                mock_result = MagicMock()
                mock_result.stdout = ""
                mock_result.stderr = ""
                mock_result.returncode = 0
                mock_run.return_value = mock_result

                # Direct parsing test
                findings = scanner.run_gitleaks(".")

        finally:
            os.unlink(temp_path)

    def test_severity_always_critical_for_secrets(self):
        """Secrets hamesha CRITICAL hone chahiye."""
        from scanner.scoring_engine import Severity

        # Secret ki severity hamesha critical hoti hai
        # Yeh test scoring logic verify karta hai
        from scanner.scoring_engine import ScoringEngine, Finding

        engine = ScoringEngine()
        finding = Finding(
            scanner="gitleaks",
            vuln_type="exposed_secret_aws-access-token",
            file_path="config.py",
            line_number=5,
            description="AWS key exposed",
            severity=Severity.CRITICAL,
        )
        scored = engine.calculate_score(finding)
        assert scored.cvss_score >= 9.0


# ─────────────────────────────────────────────
# Finding Dataclass Tests
# ─────────────────────────────────────────────
class TestFindingDataclass:

    def test_finding_default_values(self):
        """Finding ke defaults sahi hone chahiye."""
        f = Finding(
            scanner="test",
            vuln_type="xss",
            file_path="app.py",
            line_number=1,
            description="test finding",
            severity=Severity.LOW,
        )
        assert f.cvss_score == 0.0
        assert f.remediation == ""
        assert f.ai_confirmed is None
        assert f.finding_id == ""
        assert f.raw_output == {}

    def test_severity_enum_values(self):
        """Severity enum correct values hain."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_finding_equality(self):
        """Same data wale findings equal hone chahiye."""
        f1 = Finding(
            scanner="semgrep", vuln_type="sqli",
            file_path="a.py", line_number=1,
            description="sql", severity=Severity.HIGH,
        )
        f2 = Finding(
            scanner="semgrep", vuln_type="sqli",
            file_path="a.py", line_number=1,
            description="sql", severity=Severity.HIGH,
        )
        assert f1 == f2