import json
import pandas as pd
import streamlit as st

path = "./results/explanations.json"
path_w_message = "./results/explanations-message.json"
patch_path = "./results/comparison.json"

st.set_page_config(page_title="LLM Patch Explanations", layout="wide")
st.title("LLM Patch Explanations")

with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

with open(path_w_message, "r", encoding="utf-8") as f: 
    data_w_message = json.load(f)

with open(patch_path, "r", encoding="utf-8") as f: 
    patch_data = json.load(f)

# Convert to the json to pandas dataframe
rows = []
for patch, info in data.items():
    rows.append({
        "Patch": patch,
        "CWE-ID": ", ".join(info.get("CWE-id", [])),
        "Commit Message": info.get("commit_message", ""),
        "Explanation": info.get("explanation", ""),
        "Explanation_w": data_w_message[patch]['explanation'],
        "Diff": info["diff"],
    }) 
df = pd.DataFrame(rows)

selection = st.dataframe(df[["Patch", "CWE-ID", "Commit Message"]], width="stretch", hide_index=True)

selected = st.selectbox("Select a file to view full explanation:", df["Patch"])
row = df[df["Patch"] == selected].iloc[0]
st.markdown(f"### {row['Patch']}")
st.markdown(f"**CWE-ID:** {row['CWE-ID']}")
st.markdown(f"**Commit Message:** {row['Commit Message']}")
st.markdown(f"**Explanation with given commit message:**\n\n{row['Explanation']}")
st.markdown(f"**Explanation without given commit message:**\n\n{row['Explanation_w']}")

st.divider()
with st.expander("See most important patch(es)"):
    st.markdown(f"**Diff:**\n\n")

    st.code(row["Diff"], language="diff")

