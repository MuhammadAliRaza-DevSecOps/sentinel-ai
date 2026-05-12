#!/bin/bash
# scripts/run_local_scan.sh
# Local machine pe manually scan run karne ke liye
# Usage: ./scripts/run_local_scan.sh [target_directory]

set -e

TARGET="${1:-.}"   # Default current directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="scan_results/${TIMESTAMP}"

echo "╔══════════════════════════════════════╗"
echo "║   DevSecOps Local Security Scanner   ║"
echo "╚══════════════════════════════════════╝"
echo ""
echo "Target: ${TARGET}"
echo "Results: ${RESULTS_DIR}"
echo ""

mkdir -p "${RESULTS_DIR}"

# ─────────────────────────────────────────────
# 1. Secret Scan
# ─────────────────────────────────────────────
echo "🔑 [1/4] Secret Scanning..."
if command -v gitleaks &> /dev/null; then
    gitleaks detect \
        --source "${TARGET}" \
        --report-format json \
        --report-path "${RESULTS_DIR}/gitleaks.json" \
        --no-banner \
        --exit-code 0 || true
    echo "   Gitleaks: Done"
else
    echo "   Gitleaks: Skip (not installed)"
fi

# ─────────────────────────────────────────────
# 2. SAST Scan
# ─────────────────────────────────────────────
echo ""
echo "🔍 [2/4] SAST Scanning..."
if command -v semgrep &> /dev/null; then
    semgrep \
        --config=p/python \
        --config=p/security-audit \
        --json \
        --output="${RESULTS_DIR}/semgrep.json" \
        "${TARGET}" || true
    echo "   Semgrep: Done"
fi

if command -v bandit &> /dev/null; then
    bandit -r "${TARGET}" -f json \
        -o "${RESULTS_DIR}/bandit.json" -q || true
    echo "   Bandit: Done"
fi

# ─────────────────────────────────────────────
# 3. SCA Scan
# ─────────────────────────────────────────────
echo ""
echo "📦 [3/4] Dependency Scanning..."
REQ_FILE="${TARGET}/requirements.txt"
if [ -f "${REQ_FILE}" ]; then
    if command -v safety &> /dev/null; then
        safety check --file "${REQ_FILE}" --json \
            --output "${RESULTS_DIR}/safety.json" || true
        echo "   Safety: Done"
    fi
    if command -v pip-audit &> /dev/null; then
        pip-audit --requirement "${REQ_FILE}" --format json \
            --output "${RESULTS_DIR}/pip-audit.json" || true
        echo "   pip-audit: Done"
    fi
else
    echo "   Skip (requirements.txt nahi mili)"
fi

# ─────────────────────────────────────────────
# 4. Aggregate aur Report
# ─────────────────────────────────────────────
echo ""
echo "📊 [4/4] Results Aggregate kar raha hai..."
python scripts/aggregate_findings.py \
    --results-dir "${RESULTS_DIR}" \
    --output "${RESULTS_DIR}/final-report.json" \
    --fail-on-critical true \
    --fail-on-high-count 5 || GATE_FAILED=true

echo ""
echo "📄 Report generate ho raha hai..."
python -c "
import json, sys
with open('${RESULTS_DIR}/final-report.json') as f:
    r = json.load(f)
print(f'Risk Level  : {r[\"risk_level\"]}')
print(f'Risk Score  : {r[\"risk_score\"]}')
print(f'Critical    : {r[\"counts\"][\"critical\"]}')
print(f'High        : {r[\"counts\"][\"high\"]}')
print(f'Medium      : {r[\"counts\"][\"medium\"]}')
print(f'Low         : {r[\"counts\"][\"low\"]}')
print(f'Total       : {r[\"total_findings\"]}')
print(f'Report      : ${RESULTS_DIR}/final-report.json')
"

echo ""
if [ "${GATE_FAILED}" = "true" ]; then
    echo "❌ SECURITY GATE: FAILED"
    echo "   Critical vulnerabilities found!"
    exit 1
else
    echo "✅ SECURITY GATE: PASSED"
    exit 0
fi