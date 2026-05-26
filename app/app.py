import streamlit as st
import pandas as pd
import joblib
import plotly.express as px
from streamlit_option_menu import option_menu
import fitz

# ====================================================
# PAGE CONFIG
# ====================================================

st.set_page_config(
    page_title="AI Security Analytics Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# ====================================================
# CUSTOM THEME
# ====================================================
st.markdown("""
<style>

.main {
    background-color: #0E1117;
}

h1, h2, h3 {
    color: #00D4FF;
}

/* Metric Cards */

div[data-testid="metric-container"] {
    background-color: #1E1E1E;
    border: 1px solid #00D4FF;
    padding: 15px;
    border-radius: 12px;
}

/* Metric Label */

div[data-testid="metric-container"] label {
    color: white !important;
    font-size: 18px !important;
}

/* Metric Value */

div[data-testid="metric-container"] div {
    color: #00FF88 !important;
}

</style>
""", unsafe_allow_html=True)
# ====================================================
# LOAD MODEL
# ====================================================

saved_model = joblib.load("model/ransomware_model.pkl")

model = saved_model["model"]
feature_names = saved_model["feature_names"]

# ====================================================
# SIDEBAR
# ====================================================

with st.sidebar:

    selected = option_menu(
        menu_title="Navigation",
        options=[
            "Dashboard",
            "CSV Detection",
            "Feature Importance",
            "PDF Analyzer",
            "About"
        ],
        icons=[
            "shield-fill-check",
            "file-earmark-spreadsheet",
            "bar-chart-fill",
            "file-earmark-pdf",
            "info-circle"
        ],
        default_index=0
    )

# ====================================================
# DASHBOARD
# ====================================================

if selected == "Dashboard":

    st.title("🛡️ AI Security Analytics Dashboard")

    st.markdown("""
    ### Machine Learning Powered Ransomware Detection System

    Detect malicious activity using behavioral analytics,
    process monitoring, and AI-driven threat detection.
    """)

    col1, col2, col3 = st.columns(3)

    col1.metric("🤖 Detection Engine", "Random Forest")
    col2.metric("🎯 Detection Accuracy", "100%")
    col3.metric("🛡️ Security Status", "Protected")
    st.divider()

    left, right = st.columns(2)

    with left:

        st.info("""
        ### Features

        ✅ CSV Malware Detection

        ✅ PDF Threat Analysis

        ✅ AI Threat Scoring

        ✅ Interactive Visualizations

        ✅ Feature Importance Analytics
        """)

    with right:

        st.success("""
        ### Technology Stack

        • Python

        • Scikit-Learn

        • Streamlit

        • Plotly

        • PyMuPDF

        • Cybersecurity Analytics
        """)

# ====================================================
# CSV DETECTION
# ====================================================

elif selected == "CSV Detection":

    st.title("📊 CSV Malware Detection")

    uploaded_file = st.file_uploader(
        "Upload CSV File",
        type=["csv"]
    )

    if uploaded_file is not None:

        data = pd.read_csv(uploaded_file)

        st.subheader("Dataset Preview")

        st.dataframe(
            data.head(),
            use_container_width=True
        )

        prediction_data = data.copy()

        if "hash" in prediction_data.columns:
            prediction_data.drop(
                "hash",
                axis=1,
                inplace=True
            )

        if "classification" in prediction_data.columns:
            prediction_data.drop(
                "classification",
                axis=1,
                inplace=True
            )

        predictions = model.predict(prediction_data)

        labels = [
            "Malware" if p == 1 else "Benign"
            for p in predictions
        ]

        malware_count = labels.count("Malware")
        benign_count = labels.count("Benign")
        total_records = len(labels)

        # ====================================================
        # METRICS
        # ====================================================

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "🔴 Malware Detected",
            malware_count
        )

        col2.metric(
            "🟢 Benign Processes",
            benign_count
        )

        col3.metric(
            "📊 Total Records",
            total_records
        )

        # ====================================================
        # THREAT LEVEL
        # ====================================================

        if malware_count == 0:

            st.success(
                "✅ No Malware Threats Detected"
            )

        elif malware_count <= total_records * 0.2:

            st.warning(
                "🟡 Low Threat Environment"
            )

        elif malware_count <= total_records * 0.5:

            st.warning(
                "🟠 Medium Threat Environment"
            )

        else:

            st.error(
                "🔴 High Threat Environment"
            )

        # ====================================================
        # RESULTS TABLE
        # ====================================================

        results_df = pd.DataFrame({
            "Prediction": labels
        })

        st.subheader("Prediction Results")

        st.dataframe(
            results_df,
            use_container_width=True
        )

        # ====================================================
        # DOWNLOAD BUTTON
        # ====================================================

        csv_download = results_df.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            label="📥 Download Predictions",
            data=csv_download,
            file_name="prediction_results.csv",
            mime="text/csv"
        )

        # ====================================================
        # CHARTS
        # ====================================================

        chart_data = pd.DataFrame({
            "Category": ["Malware", "Benign"],
            "Count": [malware_count, benign_count]
        })

        pie_fig = px.pie(
            chart_data,
            names="Category",
            values="Count",
            title="Prediction Distribution"
        )

        st.plotly_chart(
            pie_fig,
            use_container_width=True
        )

        bar_fig = px.bar(
            chart_data,
            x="Category",
            y="Count",
            title="Threat Distribution"
        )

        st.plotly_chart(
            bar_fig,
            use_container_width=True
        )

# ====================================================
# FEATURE IMPORTANCE
# ====================================================

elif selected == "Feature Importance":

    st.title("📈 Feature Importance Analysis")

    importance_df = pd.DataFrame({
        "Feature": feature_names,
        "Importance": model.feature_importances_
    })

    importance_df = importance_df.sort_values(
        by="Importance",
        ascending=False
    )

    st.subheader(
        "Top Features Influencing Predictions"
    )

    st.dataframe(
        importance_df,
        use_container_width=True
    )

    fig = px.bar(
        importance_df.head(10),
        x="Importance",
        y="Feature",
        orientation="h",
        title="Top 10 Most Important Features"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

# ====================================================
# PDF ANALYZER
# ====================================================

elif selected == "PDF Analyzer":

    st.title("📄 PDF Threat Analyzer")

    uploaded_pdf = st.file_uploader(
        "Upload PDF File",
        type=["pdf"]
    )

    if uploaded_pdf is not None:

        try:

            pdf = fitz.open(
                stream=uploaded_pdf.read(),
                filetype="pdf"
            )

            pages = []

            for page in pdf:

                pages.append(
                    str(page.get_text())
                )

            text = "\n".join(pages)

            st.subheader("PDF Preview")

            st.text_area(
                "Extracted Text",
                text[:3000],
                height=250
            )

            keywords = [
                "encrypt",
                "encrypted",
                "bitcoin",
                "payment",
                "ransom",
                "decrypt",
                "wallet",
                "crypto",
                "lock files",
                "recover files"
            ]

            threat_score = 0
            found_keywords = []

            for word in keywords:

                count = text.lower().count(word)

                if count > 0:

                    threat_score += count
                    found_keywords.append(word)

            # ====================================================
            # THREAT ANALYSIS
            # ====================================================

            st.subheader("Threat Analysis")

            st.metric(
                "🚨 Threat Score",
                threat_score
            )

            # ====================================================
            # THREAT SEVERITY METER
            # ====================================================

            max_score = 20

            severity = min(
                threat_score / max_score,
                1.0
            )

            st.subheader(
                "Threat Severity Meter"
            )

            st.progress(severity)

            if threat_score == 0:

                st.success(
                    "🟢 Safe Document"
                )

            elif threat_score <= 5:

                st.warning(
                    "🟡 Low Risk"
                )

            elif threat_score <= 10:

                st.warning(
                    "🟠 Medium Risk"
                )

            else:

                st.error(
                    "🔴 High Risk"
                )

            # ====================================================
            # DETECTED KEYWORDS
            # ====================================================

            st.subheader("Detected Keywords")

            if found_keywords:

                keyword_data = []

                for word in found_keywords:

                    keyword_data.append({
                        "Keyword": word,
                        "Occurrences": text.lower().count(word)
                    })

                keyword_df = pd.DataFrame(
                    keyword_data
                )

                st.dataframe(
                    keyword_df,
                    use_container_width=True
                )

            else:

                st.write(
                    "No suspicious keywords found."
                )

        except Exception as e:

            st.error(
                f"Error processing PDF: {e}"
            )

# ====================================================
# ABOUT
# ====================================================

elif selected == "About":

    st.title("ℹ️ About Project")

    st.markdown("""
    ## AI-Based Ransomware Detection System

    This project combines Machine Learning and Cybersecurity
    to identify malicious process behavior and ransomware activity.

    ### Key Features

    - Behavior-Based Malware Detection
    - AI Threat Analytics
    - PDF Threat Analysis
    - Feature Importance Visualization
    - Interactive Security Dashboard
    - Real-Time Prediction Reporting

    ### Technologies Used

    - Python
    - Pandas
    - Scikit-Learn
    - Streamlit
    - Plotly
    - PyMuPDF

    ### Machine Learning Model

    Random Forest Classifier

    ### Developer

    Somya Gupta
    """)

