import json
import ollama
import pandas as pd
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
DATASET_CSV = "./vader.csv"
CASES_DIR = "cases"
MODEL_NAME = "mistral:7b"

# Prompt templates
SYSTEM_TEMPLATE = """
Each commit includes:
- CVE ID(s)
- Repository and commit hash
- Commit message
- Code changes (diffs)

Your task is:
1. Explain what the commit is fixing or mitigating.
2. Describe how this commit relates to the CWE ({cwe_id}).
3. Provide a short explanation of the risk if the issue had not been fixed.
4. Keep the explanation clear and concise for a technical audience.

Here is the commit to analyze:

CVE(s): {cve_ids}
Repository: {repo}

The most relevant diffs:
{diff}

Most important lines in the diff:
{lines}

---

Now provide your explanation by filling in the following template:
- Vulnerability Type: 
- Severity: 
- Root cause:
- Exploit scenario:
- Why it happens:
- Security implications:
- Suggested fix: [do not mention the actual diff or the commit message, describe it as if you suggested the fix]
"""

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
                'temperature': 0.7,
            }
        )
        
        return response['message']['content']
        
    except Exception as e:
        logger.error(f"Error generating response: {str(e)}")
        raise

def main():
    path_to_patches = "./patch_data/"

    with open("./results/lines_semgrep.json", "r") as f: 
        relevant_lines = json.load(f)

    explanations = {}
    
    for file in relevant_lines:
        # Open the patch data
        with open(path_to_patches + file + "_patch.json", "r") as f: 
            patch_file = json.load(f)

        patch_file = patch_file[next(iter(patch_file))]
        cwe_id="CWE-89",
        cwe_name="XSS",
        system_prompt = f"You are a security analyst. You are analyzing code commits that are related to the CWE: {cwe_id} ({cwe_name})."
        user_prompt = SYSTEM_TEMPLATE.format(
            cwe_id=cwe_id,
            cve_ids=["cve_id"][0],
            repo=patch_file["repo"],
            # commit_hash=patch_file["file"]["sha"],
            # commit_message=patch_file["message"],
            diff=relevant_lines[file]["patches"],
            lines=relevant_lines[file]["lines"]
        )

        explanations[file] = {
            "explanation": call_mistral(system_prompt, user_prompt).lstrip(),
            "CWE-id": cwe_id,
            "commit_message": patch_file["message"],
        }

    with open("./results/explanations.json", "w") as f: 
        json.dump(explanations, f, indent=4)

if __name__ == '__main__':
    main()
