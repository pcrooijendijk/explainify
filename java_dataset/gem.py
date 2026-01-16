import streamlit as st
import json
import pandas as pd
import re

with open("semgrep_explanations.json", "r") as f:
    explanations = json.load(f)

st.set_page_config(page_title="Explainify", layout="wide", page_icon="🛡️")

rows = []
for file_name, vulns in explanations.items():
    for vuln in vulns:
        rows.append({
            "File Name": file_name,
            "CWE-IDs": vuln.get('CWE', []),
            "Vulnerable Lines": vuln.get('code_snippet', ''),
            "Code": vuln.get('file_lines', ''),
            "Explanation": vuln.get('explanation', 'No explanation provided.'),
        })

df = pd.DataFrame(rows)

with st.sidebar:
    st.title("Vulnerability Dashboard")
    st.metric("Total Files", len(df["File Name"].unique()))
    st.metric("Total Vulnerability Findings", len(df))
    
    st.markdown("---")
    unique_files = df["File Name"].unique()
    selected_file = st.selectbox("Select File for Analysis:", unique_files)

st.header(f"Analysis for: `{selected_file}`")
file_findings = df[df["File Name"] == selected_file]
st.info(f"Found {len(file_findings)} issue(s) in this file.")

for i, row in file_findings.iterrows():
    with st.container():
        c1, c2 = st.columns([1, 3])
        
        with c1:
            st.markdown("#### Vulnerabilities Found")
            for cwe in row['CWE-IDs']:
                st.caption(f"**{cwe}**")
                
        with c2:
            with st.expander("#### Explanation"):
                
            # st.markdown("#### Explanation")
                st.write(row['Explanation'])

        with st.expander(f"View Vulnerable Code Snippet (#{i+1})", expanded=False):
            st.code(row['Vulnerable Lines'], language='java')

        st.divider()

with st.expander(f"View Code File:"):
    st.code(row["Code"])