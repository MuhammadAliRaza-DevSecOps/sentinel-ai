# dashboard/app.py
# Streamlit lets you build interactive web UIs with pure Python
# No HTML/CSS/JavaScript needed
# Run with: streamlit run dashboard/app.py

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import httpx
import json
from datetime import datetime, timedelta

# ─────────────────────────────────────────────
# Page configuration — must be the FIRST Streamlit command
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="DevSecOps Pipeline Dashboard",
    page_icon="🛡️",
    layout="wide",       # Use full browser width
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────
# Custom CSS — make it look professional
# ─────────────────────────────────────────────
st.markdown("""
<style>
    /* Remove default Streamlit padding */
    .block-container { padding-top: 1rem; }
    
    /* Metric cards */
    [data-testid="metric-container"] {
        background-color: #1E1E2E;
        border: 1px solid #333;
        border-radius: 8px;
        padding: 1rem;
    }
    
    /* Severity colors */
    .critical { color: #FF4B4B; font-weight: bold; }
    .high     { color: #FF8C00; font-weight: bold; }
    .medium   { color: #FFD700; font-weight: bold; }
    .low      { color: #00CC44; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# API client — fetches data from our FastAPI backend
# ─────────────────────────────────────────────
API_URL = "http://localhost:8000"  # Change to your actual API URL

@st.cache_data(ttl=60)  # Cache for 60 seconds — don't hit API on every interaction
def fetch_scan_results(limit: int = 50):
    """
    Fetch recent scan results from the API.
    @st.cache_data: Streamlit caches the return value
    If you call this function again within 60 seconds, it returns the cached value
    """
    try:
        # httpx is an async-capable HTTP client — similar to requests
        with httpx.Client() as client:
            response = client.get(f"{API_URL}/api/v1/scans?limit={limit}")
            response.raise_for_status()  # Raises exception if status code is 4xx or 5xx
            return response.json()
    except Exception as e:
        st.error(f"Failed to fetch scan results: {e}")
        return []

@st.cache_data(ttl=300)  # Cache for 5 minutes
def fetch_trends(days: int = 30):
    """Fetch trend data for the last N days."""
    try:
        with httpx.Client() as client:
            response = client.get(f"{API_URL}/api/v1/scans/trends?days={days}")
            response.raise_for_status()
            return response.json()
    except Exception as e:
        return {}


# ─────────────────────────────────────────────
# MAIN DASHBOARD
# ─────────────────────────────────────────────

# Header
st.title("🛡️ DevSecOps Security Pipeline Dashboard")
st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# Sidebar — filters and controls
with st.sidebar:
    st.header("Filters")
    
    # Date range picker
    date_range = st.date_input(
        "Date range",
        value=(datetime.now() - timedelta(days=30), datetime.now()),
    )
    
    # Severity filter
    severity_filter = st.multiselect(
        "Severity",
        ["critical", "high", "medium", "low", "info"],
        default=["critical", "high", "medium"],
    )
    
    # Scanner filter
    scanner_filter = st.multiselect(
        "Scanner",
        ["sast", "sca", "container", "secret", "dast"],
        default=["sast", "sca", "container", "secret", "dast"],
    )
    
    st.divider()
    
    # Trigger a new scan
    st.header("Trigger Scan")
    target_path = st.text_input("Target path", value=".")
    if st.button("🔍 Run Scan", type="primary"):
        with st.spinner("Scanning..."):
            try:
                with httpx.Client() as client:
                    resp = client.post(
                        f"{API_URL}/api/v1/scans/trigger",
                        json={"target_path": target_path},
                        timeout=30,
                    )
                    if resp.status_code == 200:
                        st.success("Scan queued!")
                    else:
                        st.error("Failed to queue scan")
            except Exception as e:
                st.error(f"Error: {e}")

# ─────────────────────────────────────────────
# Summary Metrics Row
# ─────────────────────────────────────────────
scan_data = fetch_scan_results()

if scan_data:
    # Count findings across all recent scans
    total_scans    = len(scan_data)
    total_critical = sum(s.get("counts", {}).get("critical", 0) for s in scan_data)
    total_high     = sum(s.get("counts", {}).get("high", 0) for s in scan_data)
    total_medium   = sum(s.get("counts", {}).get("medium", 0) for s in scan_data)
    pass_rate      = sum(1 for s in scan_data if s.get("risk_level") == "PASS") / total_scans * 100

    # Display as metric cards — Streamlit's st.metric() shows a number + delta
    col1, col2, col3, col4, col5 = st.columns(5)
    
    col1.metric("Total Scans", total_scans, delta="last 30 days")
    col2.metric("Critical", total_critical, 
                delta=f"{total_critical} active", delta_color="inverse")
    col3.metric("High", total_high,
                delta=f"{total_high} active", delta_color="inverse")
    col4.metric("Medium", total_medium)
    col5.metric("Pass Rate", f"{pass_rate:.1f}%",
                delta="↑ good" if pass_rate > 80 else "↓ needs attention")

    st.divider()

    # ─────────────────────────────────────────────
    # Charts Row
    # ─────────────────────────────────────────────
    col_left, col_right = st.columns(2)

    with col_left:
        st.subheader("Findings by Severity")
        
        # Prepare data for the pie chart
        severity_counts = {
            "Critical": total_critical,
            "High":     total_high,
            "Medium":   total_medium,
        }
        
        # Plotly pie chart — much more interactive than matplotlib
        fig = px.pie(
            names=list(severity_counts.keys()),
            values=list(severity_counts.values()),
            color=list(severity_counts.keys()),
            color_discrete_map={
                "Critical": "#FF4B4B",
                "High":     "#FF8C00",
                "Medium":   "#FFD700",
            },
            hole=0.4,   # Makes it a donut chart
        )
        fig.update_traces(textposition="inside", textinfo="percent+label")
        fig.update_layout(showlegend=True, height=300)
        st.plotly_chart(fig, use_container_width=True)

    with col_right:
        st.subheader("Scan Results Over Time")
        
        # Build a DataFrame for the trend line chart
        # DataFrame = a table of data (like Excel)
        trend_data = []
        for scan in sorted(scan_data, key=lambda x: x.get("created_at", "")):
            trend_data.append({
                "date":     scan.get("created_at", ""),
                "critical": scan.get("counts", {}).get("critical", 0),
                "high":     scan.get("counts", {}).get("high", 0),
                "medium":   scan.get("counts", {}).get("medium", 0),
            })
        
        if trend_data:
            df = pd.DataFrame(trend_data)
            fig2 = px.line(
                df, x="date", y=["critical", "high", "medium"],
                color_discrete_map={
                    "critical": "#FF4B4B",
                    "high":     "#FF8C00",
                    "medium":   "#FFD700",
                },
                title="Finding Trend",
            )
            fig2.update_layout(height=300, legend_title="Severity")
            st.plotly_chart(fig2, use_container_width=True)

    # ─────────────────────────────────────────────
    # Recent Findings Table
    # ─────────────────────────────────────────────
    st.subheader("Recent Findings")
    
    # Flatten findings from all scans into one list
    all_findings = []
    for scan in scan_data[:10]:  # Last 10 scans
        for finding in scan.get("findings", []):
            all_findings.append({
                "Severity":    finding.get("severity", ""),
                "Scanner":     finding.get("scanner", ""),
                "Type":        finding.get("vuln_type", ""),
                "File":        finding.get("file_path", ""),
                "Line":        finding.get("line_number", ""),
                "CVSS":        finding.get("cvss_score", 0),
                "Description": finding.get("description", "")[:100] + "...",
            })
    
    if all_findings:
        findings_df = pd.DataFrame(all_findings)
        
        # Color-code the severity column
        def color_severity(val):
            """Returns CSS style string based on severity value."""
            colors = {
                "critical": "background-color: #FF4B4B; color: white",
                "high":     "background-color: #FF8C00; color: white",
                "medium":   "background-color: #FFD700; color: black",
                "low":      "background-color: #00CC44; color: white",
            }
            return colors.get(val.lower(), "")
        
        # Apply the styling and display the table
        styled_df = findings_df.style.applymap(
            color_severity, subset=["Severity"]
        )
        st.dataframe(styled_df, use_container_width=True, hide_index=True)

else:
    # Show a helpful message if no data yet
    st.info("""
    📊 No scan data yet. To get started:
    1. Run a scan using the sidebar panel, or
    2. Push code to GitHub to trigger the automated pipeline
    """)