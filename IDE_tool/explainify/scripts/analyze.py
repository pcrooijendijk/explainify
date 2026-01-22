import sys
import json
import subprocess
import os
import logging
import Semgrep
from google import genai
from dotenv import load_dotenv

load_dotenv()
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
client = genai.Client(api_key=GOOGLE_API_KEY)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Prompt template
SYSTEM_TEMPLATE = """
Context:
- The code below was flagged by a static analysis tool (Semgrep).
- Semgrep Message: "{semgrep_message}"
- Related CWEs: {cwe_id}

Your task is:
1. Analyze the "Code Context" and the specific "Vulnerable Snippet".
2. Explain the vulnerability using the Semgrep finding as a guide.
3. Determine why this specific pattern is dangerous in this context.

Here is the code to analyze:

Code Context (Surrounding lines):
{file_lines}

Vulnerable Snippet (Flagged lines):
{code_snippet}

---

Now provide your explanation by filling in the following template:
- Vulnerability Type: 
- Severity: 
- Root cause:
- Exploit scenario:
- Why it happens:
- Security implications:
- Suggested fix: [do not mention the message, describe it as if you suggested the fix]
"""

def call_gemini(system_prompt: str, user_prompt: str) -> str:
    try:
        full_prompt = f"{system_prompt}\n\n{user_prompt}"

        response = client.models.generate_content(
            model='gemini-2.0-flash', 
            contents=full_prompt
        )
        
        return response.text
        
    except Exception as e:
        logger.error(f"Error generating response from Gemini: {str(e)}")
        return "Error generating explanation from AI."

def run_semgrep(target_file):
    # Using full path to the output file, otherwise it's safed somewhere else
    output_file = "/Users/prooijendijk/Documents/explainify/IDE_tool/explainify/scripts/semgrep_temp_results.json"
    
    cmd = [
        "/opt/homebrew/bin/semgrep", "scan",
        "--config=auto",
        "--verbose",
        "--no-git-ignore",
        "--json",
        "--output", output_file,
        target_file
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)

        if not os.path.exists(output_file):
            return []

        with open(output_file, 'r') as f:
            data = json.load(f)
        # os.remove(output_file)      
        return data.get('results', [])
        
    except Exception as e:
        sys.stderr.write(f"Semgrep Error: {str(e)}\n")
        return []
    
def extract_code_context(base_path, relative_path, start_line, end_line):
    if os.path.isfile(base_path):
        file_to_open = base_path
    else: 
        file_to_open = os.path.join(base_path, relative_path)
    
    try: 
        with open(file_to_open, 'r', encoding='utf-8', errors='replace') as f: 
            lines = f.readlines()
        
        context_start = max(0, start_line - 5)
        context_end = min(len(lines), end_line + 2)
        return "".join(lines[context_start:context_end])
    except Exception: 
        return "Could not read source file."

if __name__ == "__main__":  
    if len(sys.argv) < 2:
        sys.exit(1)

    target_file_path = sys.argv[1]
    findings = run_semgrep(target_file_path)

    sm = Semgrep.Semgrep()
    sm.set_results()
    results_list = sm.result_list
    path_to_files = "java_files/"
    explanations = {}

    # Looping through the results from Semgrep by file
    for file in results_list:
        with open(file, 'r', encoding='utf-8') as f: 
            all_lines = f.readlines()
        all_lines_final = "".join(all_lines)

        # Looping through the results of each file (each file can have multiple vulnerabilities)
        for finding in results_list[file]:
            start = finding['start_line']['line']
            end = finding['end_line']['line']
            code_snippet = extract_code_context(target_file_path, file, start, end)

            # Constructing the user and system prompts
            user_prompt = SYSTEM_TEMPLATE.format(
                semgrep_message=finding['message'],
                cwe_id=finding['vuln_ids'],
                file_lines=all_lines_final,
                code_snippet=code_snippet
            )
            
            system_prompt = f"You are a security analyst or expert analyzing a code change."
            explanation = call_gemini(system_prompt, user_prompt).lstrip()
            print(explanation)

            # This checks if the file name is already in the final results
            if file not in explanations:
                explanations[file] = []

            explanations[file].append(
                {
                    "line": start,
                    "endLine": end,
                    "message": finding['message'],
                    "ai_explanation": explanation,
                    "vulnerability": finding['vuln_ids']
                }
            )

        with open("/Users/prooijendijk/Documents/explainify/IDE_tool/explainify/scripts/semgrep_explanations.json", "w") as f: 
            json.dump(explanations, f, indent=4)
            
    print(json.dumps(explanations, indent=2))