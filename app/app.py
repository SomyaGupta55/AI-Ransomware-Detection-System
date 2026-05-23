import streamlit as st
import pandas as pd
import joblib
import plotly.express as px

# Page config
st.set_page_config(
    page_title="Ransomware Detection System",
    page_icon="🛡️",
    layout="wide"
)

# Load model
model = joblib.load("model/ransomware_model.pkl")

# Title
st.title("🛡️ AI-Based Ransomware Detection System")

st.markdown("""
This system uses Machine Learning to detect malicious ransomware behavior.
Upload a CSV dataset for prediction.
""")

# Upload CSV
uploaded_file = st.file_uploader(
    "Upload CSV File",
    type=["csv"]
)

if uploaded_file is not None:

    data = pd.read_csv(uploaded_file)

    st.subheader("Uploaded Dataset")
    st.write(data.head())

    # Remove unnecessary columns
    if "hash" in data.columns:
        data = data.drop("hash", axis=1)

    if "classification" in data.columns:
        data = data.drop("classification", axis=1)

    # Predictions
    predictions = model.predict(data)

    # Convert predictions
    labels = [
        "Malware" if p == 1 else "Benign"
        for p in predictions
    ]

    data["Prediction"] = labels

    st.subheader("Prediction Results")
    st.write(data.head())

    # Count values
    malware_count = labels.count("Malware")
    benign_count = labels.count("Benign")

    # Metrics
    col1, col2 = st.columns(2)

    col1.metric("Malware Detected", malware_count)
    col2.metric("Benign Files", benign_count)

    # Pie chart
    chart_data = pd.DataFrame({
        "Category": ["Malware", "Benign"],
        "Count": [malware_count, benign_count]
    })

    fig = px.pie(
        chart_data,
        names="Category",
        values="Count",
        title="Prediction Distribution"
    )

    st.plotly_chart(fig)

    # Download results
    csv = data.to_csv(index=False)

    st.download_button(
        label="Download Prediction Results",
        data=csv,
        file_name="prediction_results.csv",
        mime="text/csv"
    )

    st.success("Prediction Completed Successfully")