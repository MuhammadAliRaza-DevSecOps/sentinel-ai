# dashboard/pages/overview.py
# Dashboard ka overview page — quick stats aur summary

import streamlit as st
import httpx
import plotly.express as px
from datetime import datetime, timedelta

API_URL = "http://localhost:8000"


@st.cache_data(ttl=30)
def get_stats():
    """API se scan data fetch karo — 30 seconds cache."""
    try:
        with httpx.Client(timeout=10) as client:
            r = client.get(f"{API_URL}/api/v1/scans?limit=100")
            if r.status_code == 200:
                return r.json()
            return []
    except Exception:
        # API nahi chal rahi — empty return karo
        return []


def render():
    st.header("📊 Overview")
    st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")

    data = get_stats()

    # ─────────────────────────────────────────────
    # Koi data nahi — pehla scan run karo
    # ─────────────────────────────────────────────
    if not data:
        st.warning("Koi scan data nahi mila abhi tak.")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔍 Pehla Scan Run Karein", type="primary"):
                try:
                    with httpx.Client(timeout=30) as c:
                        resp = c.post(
                            f"{API_URL}/api/v1/scans/trigger",
                            json={
                                "target_path": ".",
                                "scan_type": "sast",
                            },
                        )
                        if resp.status_code == 202:
                            st.success("✅ Scan queue ho gaya! 30 seconds mein results aayenge.")
                            st.rerun()
                        else:
                            st.error(f"Error: {resp.status_code}")
                except Exception as e:
                    st.error(f"API connect nahi ho rahi: {e}")
                    st.info("Docker chal raha hai? docker-compose up -d run karo.")
        with col2:
            st.info("💡 Pehle docker-compose up -d run karo")
        return

    # ─────────────────────────────────────────────
    # Summary Numbers
    # ─────────────────────────────────────────────
    total          = len(data)
    passed         = sum(1 for s in data if s.get("risk_level") == "PASS")
    failed         = sum(1 for s in data if s.get("risk_level") == "FAIL")
    warned         = sum(1 for s in data if s.get("risk_level") == "WARN")
    total_critical = sum(s.get("count_critical", 0) for s in data)
    total_high     = sum(s.get("count_high", 0) for s in data)
    pass_rate      = (passed / total * 100) if total > 0 else 0

    # ─────────────────────────────────────────────
    # Metric Cards — Top Row
    # ─────────────────────────────────────────────
    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric(
        label="Total Scans",
        value=total,
    )
    c2.metric(
        label="✅ Passed",
        value=passed,
        delta=f"{pass_rate:.0f}% pass rate",
    )
    c3.metric(
        label="❌ Failed",
        value=failed,
        delta=f"-{failed} blocked" if failed else "0 blocked",
        delta_color="inverse",
    )
    c4.metric(
        label="🔴 Critical",
        value=total_critical,
        delta_color="inverse",
    )
    c5.metric(
        label="🟠 High",
        value=total_high,
        delta_color="inverse",
    )

    st.divider()

    # ─────────────────────────────────────────────
    # Charts Row
    # ─────────────────────────────────────────────
    col_left, col_right = st.columns(2)

    with col_left:
        st.subheader("Pass vs Fail vs Warn")

        pie_data = {
            "Status": ["Pass", "Fail", "Warn"],
            "Count":  [passed, failed, warned],
        }

        fig = px.pie(
            pie_data,
            names="Status",
            values="Count",
            color="Status",
            color_discrete_map={
                "Pass": "#00CC44",
                "Fail": "#FF4B4B",
                "Warn": "#FFD700",
            },
            hole=0.5,
        )
        fig.update_traces(
            textposition="inside",
            textinfo="percent+label",
        )
        fig.update_layout(
            showlegend=True,
            height=300,
            margin=dict(t=10, b=10),
        )
        st.plotly_chart(fig, use_container_width=True)

    with col_right:
        st.subheader("Recent 8 Scans")

        recent = sorted(
            data,
            key=lambda x: x.get("created_at", ""),
            reverse=True,
        )[:8]

        for scan in recent:
            rl      = scan.get("risk_level", "?")
            emoji   = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️"}.get(rl, "❓")
            branch  = scan.get("branch", "N/A")
            created = scan.get("created_at", "")[:16] if scan.get("created_at") else "N/A"
            crit    = scan.get("count_critical", 0)
            high    = scan.get("count_high", 0)
            scanner = scan.get("scan_type", "full")

            st.write(
                f"{emoji} `{branch}` · {scanner} · "
                f"C:{crit} H:{high} · {created}"
            )

    st.divider()

    # ─────────────────────────────────────────────
    # Severity Breakdown Bar Chart
    # ─────────────────────────────────────────────
    st.subheader("Total Findings by Severity")

    sev_data = {
        "Severity": ["Critical", "High", "Medium", "Low"],
        "Count": [
            sum(s.get("count_critical", 0) for s in data),
            sum(s.get("count_high",     0) for s in data),
            sum(s.get("count_medium",   0) for s in data),
            sum(s.get("count_low",      0) for s in data),
        ],
        "Color": ["#FF4B4B", "#FF8C00", "#FFD700", "#00CC44"],
    }

    fig2 = px.bar(
        sev_data,
        x="Severity",
        y="Count",
        color="Severity",
        color_discrete_map={
            "Critical": "#FF4B4B",
            "High":     "#FF8C00",
            "Medium":   "#FFD700",
            "Low":      "#00CC44",
        },
        text="Count",
    )
    fig2.update_traces(textposition="outside")
    fig2.update_layout(
        showlegend=False,
        height=300,
        margin=dict(t=30, b=10),
        yaxis_title="Count",
        xaxis_title="",
    )
    st.plotly_chart(fig2, use_container_width=True)

    # ─────────────────────────────────────────────
    # Latest Scan Detail
    # ─────────────────────────────────────────────
    if data:
        latest = sorted(
            data,
            key=lambda x: x.get("created_at", ""),
            reverse=True,
        )[0]

        st.divider()
        st.subheader("Latest Scan Detail")

        rl    = latest.get("risk_level", "N/A")
        color = {"PASS": "green", "FAIL": "red", "WARN": "orange"}.get(rl, "gray")

        st.markdown(f"**Status:** :{color}[{rl}]")

        d1, d2, d3, d4 = st.columns(4)
        d1.metric("Branch",   latest.get("branch", "N/A"))
        d2.metric("Scanner",  latest.get("scan_type", "N/A"))
        d3.metric("Duration", f"{latest.get('duration_ms', 0)}ms")
        d4.metric("Commit",   str(latest.get("commit_sha", "N/A"))[:8])

        # View full report button
        scan_id = latest.get("id", "")
        if scan_id:
            if st.button("📄 Full Report Dekho"):
                try:
                    with httpx.Client(timeout=10) as c:
                        r = c.get(f"{API_URL}/api/v1/reports/{scan_id}/markdown")
                        if r.status_code == 200:
                            content = r.json().get("content", "")
                            st.markdown(content)
                except Exception as e:
                    st.error(f"Report load nahi hua: {e}")


# Page run karo
render()