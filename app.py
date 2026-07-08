import streamlit as st
import pandas as pd
import joblib
import time

# -------------------------
# LOAD DATA
# -------------------------
df = pd.read_csv("UNSW_NB15_test_split.csv")

model = joblib.load("Multiclass_lightgbm_model.pkl")
label_encoder = joblib.load("label_encoder.pkl")

# -------------------------
# PAGE SETTINGS
# -------------------------
st.set_page_config(
    page_title="Enterprise NIDS",
    layout="wide"
)

st.title("🛡 Enterprise Network Intrusion Intelligence System")

# -------------------------
# METRICS
# -------------------------
total_traffic = len(df)

normal_count = (df["attack_cat"] == "Normal").sum()
attack_count = total_traffic - normal_count

col1, col2, col3 = st.columns(3)

col1.metric("Total Traffic", total_traffic)
col2.metric("Normal Traffic", normal_count)
col3.metric("Attack Traffic", attack_count)

st.divider()

# -------------------------
# ATTACK DISTRIBUTION
# -------------------------
st.subheader("Attack Distribution")

attack_distribution = df["attack_cat"].value_counts()

st.bar_chart(attack_distribution)

# -------------------------
# LIVE PACKET SIMULATOR
# -------------------------
st.subheader("🚨 Live Packet Monitor")

packet_placeholder = st.empty()
status_placeholder = st.empty()

X_stream = df.drop(columns=["attack_cat"], errors="ignore")

for col in ["proto", "service", "state"]:
    if col in X_stream.columns:
        X_stream[col] = (
            X_stream[col]
            .fillna("missing")
            .astype(str)
            .astype("category")
        )

for i in range(50):

    packet = X_stream.iloc[[i]]

    pred = model.predict(packet)[0]

    predicted_attack = label_encoder.inverse_transform([pred])[0]

    packet_placeholder.dataframe(packet)

    if predicted_attack == "Normal":

        status_placeholder.success(
            f"SAFE TRAFFIC ✓ | Prediction: {predicted_attack}"
        )

    else:

        status_placeholder.error(
            f"ATTACK DETECTED 🚨 | Prediction: {predicted_attack}"
        )

    time.sleep(1)
