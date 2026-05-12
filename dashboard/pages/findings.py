# dashboard/pages/findings.py
# Individual findings detail page

import streamlit as st
import httpx
import pandas as pd

API_URL = "http://localhost:8000"


@st.cache_data(ttl=60)
def get_recent_findings():
    try:
        with httpx.Client(timeout=10) as c:
            r = c.get(f"{API_URL}/api/v1/scans?limit=20")
            if r.status_code != 200:
                return []
            scans = r.json()
    except Exception:
        return []

    all_findings = []
    for scan in scans:
        for f in scan.get("findings", []) or []:
            f["scan_branch"]  = scan.get("branch", "N/A")
            f["scan_date"]    = scan.get("created_at", "")[:10]
            f["scan_risk"]    = scan.get("risk_level", "N/A")
            all_findings.append(f)
    return all_findings


def render():
    st.header("🔍 Security Findings")

    findings = get_recent_findings()

    if not findings:
        st.info("Koi findings nahi hain. Pehle ek scan run karein.")
        return

    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        sev_filter = st.multiselect(
            "Severity",
            ["critical", "high", "medium", "low", "info"],
            default=["critical", "high"],
        )
    with col2:
        scanner_filter = st.multiselect(
            "Scanner",
            list(set(f.get("scanner", "") for f in findings)),
        )
    with col3:
        search = st.text_input("Search", placeholder="file name ya vuln type...")

    # Filter apply karo
    filtered = findings
    if sev_filter:
        filtered = [f for f in filtered if f.get("severity", "").lower() in sev_filter]
    if scanner_filter:
        filtered = [f for f in filtered if f.get("scanner", "") in scanner_filter]
    if search:
        filtered = [
            f for f in filtered
            if search.lower() in f.get("file_path", "").lower()
            or search.lower() in f.get("vuln_type", "").lower()
            or search.lower() in f.get("description", "").lower()
        ]

    st.caption(f"{len(filtered)} findings (filtered from {len(findings)} total)")

    if not filtered:
        st.warning("Koi finding match nahi hui filter ke saath")
        return

    # Table display
    df = pd.DataFrame([
        {
            "Severity":    f.get("severity", "").upper(),
            "CVSS":        f"{f.get('cvss_score', 0):.1f}",
            "Scanner":     f.get("scanner", ""),
            "Type":        f.get("vuln_type", "")[:40],
            "File":        f.get("file_path", "")[-50:],
            "Line":        f.get("line_number", ""),
            "Branch":      f.get("scan_branch", ""),
            "Date":        f.get("scan_date", ""),
        }
        for f in filtered
    ])

    def highlight_severity(row):
        colors = {
            "CRITICAL": "background-color: #FF4B4B; color: white",
            "HIGH":     "background-color: #FF8C00; color: white",
            "MEDIUM":   "background-color: #FFD700; color: black",
            "LOW":      "background-color: #228B22; color: white",
        }
        c = colors.get(row["Severity"], "")
        return [c if col == "Severity" else "" for col in row.index]

    st.dataframe(
        df.style.apply(highlight_severity, axis=1),
        use_container_width=True,
        hide_index=True,
    )

    # Top critical findings detail
    critical = [f for f in filtered if f.get("severity", "").lower() == "critical"]
    if critical:
        st.divider()
        st.subheader(f"🔴 Critical Findings ({len(critical)})")
        for f in critical[:5]:
            with st.expander(f"**{f.get('vuln_type','Unknown')}** — {f.get('file_path','')[:60]}"):
                st.write(f"**Scanner:** {f.get('scanner')}")
                st.write(f"**CVSS Score:** {f.get('cvss_score', 0):.1f}")
                st.write(f"**Description:** {f.get('description', '')}")
                st.warning(f"**Fix:** {f.get('remediation', '')}")


render()