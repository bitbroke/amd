import streamlit as st
import plotly.express as px
import pandas as pd
import os

# Custom CSS for a 'Cybersecurity' feel
st.set_page_config(page_title="PrivacyLens Dashboard", layout="wide")
st.markdown("""
    <style>
    .main { background-color: #0e1117; color: #ffffff; }
    .stAlert { background-color: #1e2127; border: 1px solid #ff4b4b; }
    </style>
    """, unsafe_allow_html=True)

def render_dashboard(verdict_data):
    st.title("🛡️ PrivacyLens: Neuro-Symbolic Audit Report")
    st.write("Cross-referencing Binary Capabilities against Legal Privacy Policies.")
    
    # 1. Metrics Overview
    col1, col2, col3 = st.columns(3)
    total_apis = len(verdict_data)
    violations = len([v for v in verdict_data if v['status'] == 'VIOLATION'])
    
    col1.metric("Total Capabilities Scanned", total_apis)
    col2.metric("Privacy Violations", violations, delta=violations, delta_color="inverse")
    col3.metric("System Integrity", f"{((total_apis-violations)/total_apis)*100:.1f}%")

    st.divider()

    # 2. Visualization: The Risk Map
    st.subheader("📊 Alignment Heatmap")
    df = pd.DataFrame(verdict_data)
    # Convert scores to a 0-100 scale for easier viewing
    df['Confidence'] = df['score'].apply(lambda x: abs(x) * 100)
    
    fig = px.bar(df, x="api", y="Confidence", color="status",
                 color_discrete_map={"VIOLATION": "#ff4b4b", "COMPLIANT": "#00cc96"},
                 hover_data=["desc"], title="Capability Alignment Scores")
    st.plotly_chart(fig, use_container_width=True)

    # 3. Detailed Findings Table
    st.subheader("🔍 Granular Audit Logs")
    for v in verdict_data:
        with st.expander(f"{'🚨' if v['status'] == 'VIOLATION' else '✅'} API: {v['api']}"):
            st.write(f"**Description:** {v['desc']}")
            st.write(f"**AI Alignment Score:** {v['score']:.4f}")
            st.progress(abs(v['score']))

if __name__ == "__main__":
    # Import the audit logic inside the UI
    import sys
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from main import run_audit

    # Run the audit and display it
    with st.spinner("Analyzing Binary & Policy Alignment..."):
        report_data = run_audit()
    
    render_dashboard(report_data)