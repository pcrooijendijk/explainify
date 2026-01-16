import streamlit as st
import json
import pandas as pd

with open("semgrep_explanations.json", "r") as f:
    explanations = json.load(f)

st.set_page_config(page_title="Explainify", layout="wide")
st.title("LLM Vulnerability Explanations")

rows = []
for file in explanations:
    for vuln in explanations[file]:
        rows.append({
            "File Name": file,
            "Code": vuln['file_lines'],
            "CWE-IDs": vuln['CWE'],
            "Vulnerable Lines": vuln['code_snippet'],
            "Explanation": vuln['explanation']
        })
    
df = pd.DataFrame(rows)

selection = st.dataframe(
    df[["File Name", "CWE-IDs"]], 
    use_container_width=True, 
    hide_index=True
)
selected = st.selectbox("Select a file to view full explanation:", df['File Name'])
row = df[df["File Name"] == selected].iloc[0]

st.markdown(f"### {row['File Name']}")
st.markdown(f"**CWE-ID:**")
for cwe in row['CWE-IDs']:
    st.markdown("**-** " + cwe)
st.markdown(f"**Explanation:**\n\n{row['Explanation']}")

st.divider()
with st.expander("See the vulnerable code lines"):
    st.markdown(f"**Vulnerable lines:**\n\n")
    st.code(row["Vulnerable Lines"])