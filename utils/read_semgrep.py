import json 
import re
from typing import Dict, List

def find_patch(lines: str, owner: str) -> List:
    json_path = f'./patch_data/{owner}_patch.json'

    try:
        with open(json_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Could not read {json_path}: {e}")
        return

    patches = []

    for _, value in data.items():
        file_data = value.get('file', {})
        if lines in file_data['patch']:
            patches.append(file_data['patch'])
    
    return patches

def safe_lines(data: Dict) -> None:
    safe_file = {}

    for sample in data['results']:
        # Getting the path to the file which is found vulnerable after Semgrep analysis
        path = sample['path']
        lines = sample['extra']['lines'].lstrip()
        message_semgrep = sample['extra']['message']

        # Getting the owner of the repository for indexing the dictionary
        match = re.search(r"^/([^/]+)", path.split("file_downloads")[1])
        if match: 
            owner = match.group(1)

        patches = find_patch(lines, owner)
        if patches: 
            safe_file[owner] = {
                'path': path, 
                'lines': lines,
                'message_semgrep': message_semgrep,
                'patches': patches
            }

    with open("./results/lines_semgrep.json", "w") as f: 
        json.dump(safe_file, f, indent=4)

if __name__ == "__main__":
    with open("./results/semgrep_results.json", "r") as f: 
        data = json.load(f)

    safe_lines(data)
