# scripts/enforce_gate.py
# CI/CD pipeline ka final gate — FAIL hone pe exit code 1 deta hai
# GitHub Actions exit code 1 pe job fail kar deta hai

import argparse
import json
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True, help="final-report.json path")
    args = parser.parse_args()

    report_path = Path(args.report)
    if not report_path.exists():
        print(f"❌ Report file nahi mili: {report_path}")
        sys.exit(1)

    try:
        report = json.loads(report_path.read_text())
    except json.JSONDecodeError:
        print("❌ Report JSON parse nahi hua")
        sys.exit(1)

    risk_level  = report.get("risk_level", "UNKNOWN")
    should_fail = report.get("should_fail", False)
    counts      = report.get("counts", {})

    print("\n" + "="*60)
    print("🛡️  DEVSECOPS SECURITY GATE")
    print("="*60)
    print(f"  Critical : {counts.get('critical', 0)}")
    print(f"  High     : {counts.get('high', 0)}")
    print(f"  Medium   : {counts.get('medium', 0)}")
    print(f"  Low      : {counts.get('low', 0)}")
    print(f"  Result   : {risk_level}")
    print("="*60)

    if should_fail:
        print("\n🚨 SECURITY GATE: FAILED")
        print("   Pipeline block kar diya gaya hai.")
        print("   Critical/High vulnerabilities fix karein aur dobara push karein.")
        print()
        sys.exit(1)  # GitHub Actions yahan fail karega
    else:
        print(f"\n✅ SECURITY GATE: {risk_level}")
        print("   Pipeline proceed kar sakti hai.")
        sys.exit(0)


if __name__ == "__main__":
    main()