import streamlit as st
import pandas as pd
import numpy as np
import joblib
import io
import extractor 
from tempfile import NamedTemporaryFile
import plotly.express as px

# --- 1. PAGE CONFIGURATION ---
st.set_page_config(
    page_title="AI Network Guardian", 
    page_icon="🛡️", 
    layout="wide"
)

# Custom CSS for a cleaner look
st.markdown("""
    <style>
    .main { background-color: #f5f7f9; }
    .stMetric { background-color: #ffffff; padding: 15px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
    </style>
    """, unsafe_allow_html=True)

# --- 2. LOAD ASSETS (CACHED) ---
@st.cache_resource
def load_assets():
    # Caching ensures these large files load only once
    model = joblib.load('traffic_analyzer_model.joblib')
    scaler = joblib.load('scaler.joblib')
    label_encoder = joblib.load('label_encoder.joblib')
    scaler_features = list(scaler.feature_names_in_)
    return model, scaler, label_encoder, scaler_features

try:
    model, scaler, label_encoder, scaler_features = load_assets()
except Exception as e:
    st.error(f"Failed to load AI Assets: {e}")
    st.stop()

# --- 3. SIDEBAR (User Instructions) ---
with st.sidebar:
    st.title("🛡️ Threat Controls")
    st.markdown("""
    ### How to use:
    1. **Upload** a `.pcap` or `.pcapng` file.
    2. **Adjust** sensitivity. A higher threshold means the AI must be very "sure" before calling traffic safe.
    3. **Analyze** the dashboard for real-time threats.
    """)
    
    threshold = st.slider("Confidence Threshold", 0.0, 1.0, 0.90, step=0.01)
    
    st.divider()
    st.info(f"**Current Sensitivity:** {threshold}\n\n*If the AI's confidence in 'Normal' traffic is below this number, it triggers an alert.*")

# --- 4. MAIN INTERFACE ---
st.title("🛰️ AI Multi-Class Intrusion Detector")
st.caption("Advanced Network Traffic Analysis |AI Powered")

uploaded_file = st.file_uploader("Upload Network Capture File", type=['pcap', 'pcapng'], help="Upload pcap files from Wireshark or tcpdump")

if uploaded_file:
    # --- STEP 1: EXTRACTION ---
    with st.spinner("Analyzing packets..."):
        with NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(uploaded_file.getvalue())
            tmp_path = tmp.name
        df_raw = extractor.extract_features_from_pcap(tmp_path)

    if df_raw.empty:
        st.warning("Analysis complete: No network flows were found in this file.")
        st.stop()

    # --- STEP 2: STITCHING & PREDICTION ---
    try:
        # Preprocessing
        X_raw = df_raw.copy()
        time_cols = [c for c in X_raw.columns if any(w in c for w in ['IAT', 'Duration', 'Active', 'Idle'])]
        for col in time_cols:
            X_raw[col] = pd.to_numeric(X_raw[col], errors='coerce').fillna(0) * 1000000

        # Alignment
        X_77 = X_raw.reindex(columns=scaler_features, fill_value=0)
        X_scaled_77 = scaler.transform(X_77)
        fwd_header_duplicate = X_raw['Fwd Header Length.1'].values.reshape(-1, 1)
        X_final_78 = np.insert(X_scaled_77, 55, fwd_header_duplicate.flatten(), axis=1)
        X_final_78 = np.nan_to_num(X_final_78)

        # AI Inference
        probs = model.predict_proba(X_final_78)
        
        # Calculate Preds & Confidence
        custom_preds = []
        confidences = []
        for p in probs:
            if p[0] < threshold:
                best_attack_id = np.argmax(p[1:]) + 1 
                custom_preds.append(best_attack_id)
                confidences.append(p[best_attack_id] * 100)
            else:
                custom_preds.append(0)
                confidences.append(p[0] * 100)

        df_raw['Predicted_Class'] = label_encoder.inverse_transform(custom_preds)
        df_raw['Confidence_%'] = confidences

        # --- 5. RESULTS DASHBOARD ---
        st.divider()
        m1, m2, m3 = st.columns(3)
        total_flows = len(df_raw)
        attack_flows = df_raw[df_raw['Predicted_Class'] != 'BENIGN'].copy()
        attack_count = len(attack_flows)
        
        m1.metric("Total Flows Analyzed", f"{total_flows:,}")
        m2.metric("Threats Detected", f"{attack_count:,}", delta=f"{(attack_count/total_flows)*100:.1f}%", delta_color="inverse")
        
        if attack_count > 0:
            m3.error("🚨 CRITICAL: THREATS DETECTED")
        else:
            m3.success("✅ SECURE: NO THREATS")

        # Visualization Row
        col_chart, col_table = st.columns([4, 6])
        
        with col_chart:
            st.subheader("Traffic Composition")
            fig = px.pie(df_raw, names='Predicted_Class', hole=0.5, 
                         color='Predicted_Class',
                         color_discrete_map={'BENIGN': '#00CC96'})
            fig.update_layout(margin=dict(t=0, b=0, l=0, r=0))
            st.plotly_chart(fig, use_container_width=True)

        with col_table:
            st.subheader("Suspicious Activity Log")
            if not attack_flows.empty:
                # Sort by confidence to show most certain threats first
                display_df = attack_flows[['Predicted_Class', 'Confidence_%', 'Destination Port', 'Flow Duration']].sort_values(by='Confidence_%', ascending=False)
                st.dataframe(display_df.head(100), use_container_width=True)
                
                # --- EXPORT BUTTON ---
                csv = df_raw.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="📥 Download Full Security Report (CSV)",
                    data=csv,
                    file_name='security_scan_report.csv',
                    mime='text/csv',
                )
            else:
                st.info("No suspicious patterns identified in this dataset.")

    except Exception as e:
        st.error(f"Processing Error: {e}")

st.divider()
st.caption("Enterprise AI Intrusion Detection System | Built for Multi-Class Traffic Classification")