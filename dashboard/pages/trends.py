# dashboard/pages/trends.py
# Historical trends page

import streamlit as st
import httpx
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

API_URL = "http://localhost:8000"


@st.cache_data(ttl=300)
def get_trends(days: int):
    try:
        with httpx.Client(timeout=10) as c:
            r = c.get(f"{API_URL}/api/v1/scans/trends/summary?days={days}")
            return r.json() if r.status_code == 200 else {}
    except Exception:
        return {}


def render():
    st.header("📈 Security Trends")

    days = st.select_slider(
        "Time range",
        options=[7, 14, 30, 60, 90],
        value=30,
    )

    data = get_trends(days)

    if not data or not data.get("daily"):
        st.info("Trend data ke liye zyada scans chahiye")
        return

    daily = data.get("daily", [])
    summary = data.get("summary", {})

    # Summary cards
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Scans", data.get("total_scans", 0))
    c2.metric("Total Critical", summary.get("total_critical", 0))
    c3.metric("Pass Rate", f"{summary.get('pass_rate', 0):.1f}%")

    st.divider()

    if daily:
        df = pd.DataFrame(daily)

        # Stacked area chart — severity trends
        fig = go.Figure()
        for sev, color in [
            ("critical", "#FF4B4B"),
            ("high", "#FF8C00"),
            ("medium", "#FFD700"),
            ("low", "#00CC44"),
        ]:
            if sev in df.columns:
                fig.add_trace(go.Scatter(
                    x=df["date"], y=df[sev],
                    name=sev.capitalize(),
                    fill="tonexty",
                    line=dict(color=color),
                    stackgroup="one",
                ))

        fig.update_layout(
            title=f"Finding Trends — Last {days} Days",
            xaxis_title="Date",
            yaxis_title="Findings",
            height=400,
            hovermode="x unified",
        )
        st.plotly_chart(fig, use_container_width=True)

        # Pass/Fail trend
        if "pass" in df.columns and "fail" in df.columns:
            fig2 = px.bar(
                df, x="date",
                y=["pass", "fail"],
                color_discrete_map={"pass": "#00CC44", "fail": "#FF4B4B"},
                title="Daily Pass vs Fail",
                barmode="stack",
            )
            fig2.update_layout(height=300)
            st.plotly_chart(fig2, use_container_width=True)


render()