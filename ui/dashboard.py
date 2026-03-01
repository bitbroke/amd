import streamlit as st
import pandas as pd
import json
import os
import subprocess
import plotly.express as px

# --- UI CONFIGURATION ---
st.set_page_config(
    page_title="PrivacyLens Audit",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for a "Hacker/Cyber" feel
st.markdown("""
    <style>
    .stApp { background-color: #0e1117; }
    .metric-card { background-color: #262730; padding: 15px; border-radius: 10px; border: 1px solid #41444b; }
    h1, h2, h3 { color: #00e5ff !important; font-family: 'Courier New', monospace; }
    .stButton>button { background-color: #00e5ff; color: #000; font-weight: bold; border-radius: 5px; }
    .stButton>button:hover { background-color: #00b8cc; color: #fff; }
    div[data-testid="stMetricValue"] { color: #ffffff; }
    </style>
    """, unsafe_allow_html=True)

# --- HEADER ---
st.title("🛡️ PrivacyLens")
st.markdown("### Neuro-Symbolic Privacy Audit System")
st.markdown("---")

# --- SIDEBAR CONTROLS ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

with st.sidebar:
    st.header("⚙️ Audit Controls")
    target = st.text_input("Target Application", value="notepad.exe (Sandbox)")
    
    st.info(f"Targeting: {target}")
    
    if st.button("🚀 START AUDIT", use_container_width=True):
        with st.spinner("Running Neuro-Symbolic Pipeline... Please wait."):
            try:
                result = subprocess.run(["python", "main.py"], capture_output=True, text=True, check=True)
                
                if "FATAL: ML Brain predicts this is MALWARE" in result.stdout:
                    st.session_state['malware_blocked'] = True
                else:
                    st.session_state['malware_blocked'] = False
                    
                st.success("Audit Complete!")
            except subprocess.CalledProcessError as e:
                st.error(f"Pipeline Failed. Check terminal for details.")
                print(e.stderr)

# --- PHASE 0: ML MALWARE ALERT ---
if st.session_state.get('malware_blocked'):
    st.error("🚨 **CRITICAL THREAT BLOCKED:** The Machine Learning engine classified this file as **MALWARE** based on its PE header structure. Execution was halted to protect the host system.")
    st.stop() 

# --- DASHBOARD LOGIC ---
report_path = os.path.join(BASE_DIR, "report.json")

if os.path.exists(report_path):
    with open(report_path, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            data = []
            
    df = pd.DataFrame(data)

    if not df.empty:
        if 'score' not in df.columns:
            df['score'] = df.get('confidence', 0.99)
        
        def categorize(desc):
            desc = str(desc).lower()
            if any(k in desc for k in ['ip address', 'network', 'server', 'url']): return 'Networking'
            if 'registry' in desc: return 'Registry'
            if 'file' in desc: return 'File System'
            return 'General'
            
        df['category'] = df['desc'].apply(categorize)

        # 1. TOP METRICS
        col1, col2, col3, col4 = st.columns(4)
        
        total_findings = len(df)
        violations = len(df[df['status'] == "VIOLATION"])
        compliant = len(df[df['status'] == "COMPLIANT"])
        avg_risk = df['risk'].mean() if 'risk' in df.columns else 0

        col1.metric("Total Capabilities", total_findings, delta_color="off")
        col2.metric("Privacy Violations", violations, delta=violations, delta_color="inverse")
        col3.metric("Compliant Features", compliant, delta_color="normal")
        col4.metric("Average Risk Score", f"{avg_risk:.2f}", delta_color="off")

        st.markdown("---")

        # 2. VISUALIZATION ROW
        col_chart1, col_chart2 = st.columns(2)

        with col_chart1:
            st.subheader("📊 Violation Heatmap")
            fig = px.sunburst(df, path=['status', 'category'], values='risk', 
                              color='status', 
                              color_discrete_map={'VIOLATION':'#ff4b4b', 'COMPLIANT':'#00cc96'},
                              title="Risk Distribution by Subsystem")
            st.plotly_chart(fig, use_container_width=True)

        with col_chart2:
            st.subheader("📉 Policy Support vs Risk")
            # FIX: Adjusted labels to reflect NLI math (-1.0 to 1.0)
            fig2 = px.scatter(df, x="risk", y="score", color="status",
                              hover_data=["desc"], 
                              color_discrete_map={'VIOLATION':'#ff4b4b', 'COMPLIANT':'#00cc96'},
                              labels={"risk": "Technical Risk (0.0 - 1.0)", "score": "Policy Support Score (-1.0 to 1.0)"},
                              title="The Decision Boundary")
            fig2.add_hline(y=0.3, line_dash="dash", line_color="white", annotation_text="Compliance Threshold")
            st.plotly_chart(fig2, use_container_width=True)

        # 3. DETAILED FINDINGS
        st.subheader("📝 Audit Ledger")
        
        tab1, tab2 = st.tabs(["🚨 Violations Only", "📂 Full Report"])
        
        with tab1:
            violation_df = df[df['status'] == "VIOLATION"]
            if len(violation_df) > 0:
                for index, row in violation_df.iterrows():
                    with st.expander(f"🔴 Risk {row['risk']}: {row['category']} Anomaly"):
                        st.write(f"**AI Explanation:** `{row['desc']}`")
                        # FIX: Display as a raw float instead of a weird negative percentage
                        st.write(f"**Policy Support (NLI Score):** {float(row['score']):.2f} / 1.0")
                        st.write(f"**Verdict:** The application's stated privacy policy does not adequately disclose this behavior.")
            else:
                st.success("No violations detected!")
        
        with tab2:
            display_df = df[['status', 'category', 'desc', 'risk', 'score']].rename(
                columns={'status': 'Verdict', 'category': 'Subsystem', 'desc': 'Behavior', 'risk': 'Risk', 'score': 'Policy Score'}
            )
            st.dataframe(display_df, use_container_width=True)

    else:
        st.info("Report is empty. Please run the audit.")

else:
    st.info("👋 Welcome to PrivacyLens! Click **'START AUDIT'** in the sidebar to scan your sandbox environment.")