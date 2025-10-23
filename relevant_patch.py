import re
import json
import os
import ollama
from typing import List
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def call_mistral(system_prompt: str, user_prompt: str) -> str:       
    try: 
        model_name = "mistral:7b"
        response = ollama.chat(
            model=model_name,
            messages=[
                {
                    'role': 'system',
                    'content': system_prompt
                },
                {
                    'role': 'user',
                    'content': user_prompt
                }
            ],
            options={
                'temperature': 0.6,
            }
        )
        
        return response['message']['content']
        
    except Exception as e:
        logger.error(f"Error generating response: {str(e)}")
        raise

def find_sets(obj, path="root"):
    if isinstance(obj, set):
        print(f"Found a set at {path}: {obj}")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            find_sets(v, f"{path}[{repr(k)}]")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            find_sets(v, f"{path}[{i}]")

def extract_patches(path_to_patches: str) -> List:
    # Loading the diffs and getting the seperate patches
    with open(path_to_patches, "r") as f: 
        diffs = json.load(f)

    patches_total = {}

    for index, diff in enumerate(diffs): 
        patches = re.split(r"(?=^@@)", diffs[diff]["diff"], flags=re.MULTILINE)
        patches = [patch for patch in patches if patch.strip()]
        patches_total[index] = [patch for patch in patches]
    return patches_total, diffs[diff]["message"]

def main():
    path_to_patches = "./patch_data/"
    json_files = [pos_json for pos_json in os.listdir(path_to_patches) if pos_json.endswith('.json')]
    relevant_lines = {}

    for file in json_files:
        print(file)
        patches, message = extract_patches(path_to_patches + file)

        system_prompt = "You are a security analyst."
        user_prompt = f"""
            You are given several code patches from a single commit, the index is also given within this dictionary:

            {patches}

            Commit message:
            "{message}"

            Task:
            For each patch, find the most important *code lines* (not comments, not blank lines).

            Return valid JSON ONLY, structured like this where the patch_index is the index of the patch where you got the most important lines from:
            [
                {{
                    "patch_index": 1,
                    "lines": ["important line 1", "important line 2"]
                }},
                {{
                    "patch_index": 2,
                    "lines": ["important line 3"]
                }}
            ]

            Rules:
            - Include only *actual code lines* from the given patches that were added or modified.
            - Do not include the whole patch as important code lines. More than 10 lines is too much.
            - Do not include explanations or natural language.
            - Ensure your output is valid JSON that can be parsed by `json.loads()` in Python.
            """

        answer = call_mistral(system_prompt, user_prompt)

        if "json" in answer: 
            answer = re.split("json", answer)[1]
            answer = re.split("```", answer)[0]

        try:
            relevant_lines[file] = {
                "patches": patches,
                "message": message,
                "lines": json.loads(answer),
            }
            print("=" * 60)
            print(relevant_lines)
            find_sets(relevant_lines)
            print("=" * 60)
        except json.decoder.JSONDecodeError:
            print("Invalid character or answer, skipping...")
            print(answer)
    
    with open("./results/relevant_lines.json", "w") as f:
        if isinstance(relevant_lines, set):
            relevant_lines = list(relevant_lines)
        json.dump(relevant_lines, f, indent=4)

if __name__ == "__main__":
    main()