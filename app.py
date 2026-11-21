import json
import re
from pathlib import Path

import streamlit as st

from explainer_engine import analyze_security_alert

st.set_page_config(page_title="Rule-Based SOC Alert Explainer", page_icon="🛡️", layout="wide")

DATA_FILE = Path(__file__).parent / "alerts_data.json"
UNCERTAINTY_COLORS = {"Low": "green", "Medium": "orange", "High": "red"}
MAX_INPUT_CHARS = 5000  # strict cap on pasted input


def escape_md(text: str) -> str:
    """Stop payload text (e.g. '*' or '$') from being rendered as Markdown formatting."""
    return re.sub(r"([\\`*_{}\[\]<>#+!|~$])", r"\\\1", str(text))


st.title("🛡️ AEGYTHON 2026 — Security Alert Explainer")
st.markdown("### Track 4: Grounded Explanations for Synthetic Security Signals")
st.caption("Deterministic rule-based engine. Runs fully offline. No AI model is called.")
st.write("---")

# Load the synthetic test suite
try:
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        mock_database = json.load(f)
except (FileNotFoundError, json.JSONDecodeError) as err:
    mock_database = {}
    st.warning(f"Could not load alerts_data.json ({err}). You can still paste custom JSON below.")

# Step 1: ingestion
st.subheader("📥 Step 1: Ingest Structured Synthetic Input")
data_mode = st.radio("Choose input method:", ["Select from Test Suite Profile", "Paste Custom Raw JSON String"])

selected_alert = None

if data_mode == "Select from Test Suite Profile":
    if mock_database:
        case_choice = st.selectbox(
            "Choose a pre-configured alert profile to process:",
            options=list(mock_database.keys()),
            format_func=lambda x: f"Profile: {x.replace('_', ' ').title()}",
        )
        selected_alert = mock_database[case_choice]
        st.json(selected_alert)  # raw log preview for the analyst
else:
    raw_input_str = st.text_area(
        "Paste custom structured JSON object data below:", height=150, max_chars=MAX_INPUT_CHARS
    )
    if raw_input_str.strip():
        try:
            selected_alert = json.loads(raw_input_str)
            st.success("Valid JSON formatting verified.")
        except (json.JSONDecodeError, RecursionError):
            st.error("Invalid JSON. The engine will treat this input as a malformed log.")
            selected_alert = "MALFORMED"

# Step 2: analysis
st.write("---")
st.subheader("⚙️ Step 2: Run Analytical Pipeline")

if st.button("🚀 Process Alert", type="primary"):
    if selected_alert is not None:
        analysis_output = analyze_security_alert(selected_alert)

        st.write("### 📊 Results")

        # Stages 01 & 02: ingestion and extracted signals
        st.info("#### 📂 01 & 02: Extracted Signals")
        st.json(analysis_output["signals"])

        # Stages 03 & 04: explanation + uncertainty, and safety guidance
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### 📝 03. Grounded Explanation")
            st.info(escape_md(analysis_output["explanation"]))

            level = analysis_output["uncertainty"]
            color = UNCERTAINTY_COLORS.get(level, "gray")
            st.markdown(f"**Uncertainty:** :{color}[{level}]")
            st.markdown(f"**Why:** {escape_md(analysis_output['uncertainty_reason'])}")

        with col2:
            st.markdown("### 🔒 04. Tactical Safety Guidance")
            st.success(analysis_output["proposed_action"])
    else:
        st.warning("Please select a test profile or paste an alert before processing.")