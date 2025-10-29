import json

def parse_semgrep_report(json_file_path: str) -> None:
    with open(json_file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    findings_count = 0
    vuln_by_project = {}

    for result in data['results']:
        findings_count += 1
        
        extra = result['extra']
        message = extra.get('message', 'No description provided.')
        lines_of_code = extra.get('lines', 'No code snippet available.') # Get the code snippet

        file_path = result.get('path', 'Unknown file')

        patches = extra.get('patches', [])
        if not patches:
            # If 'patches' is empty, check for 'fix'
            fix = extra.get('fix')
            if fix:
                patches = [fix] # Store 'fix' as a list

        start_line = result.get('start', {}).get('line', 'N/A')
        end_line = result.get('end', {}).get('line', start_line) # Default to start_line if end_line is missing
        
        finding_data = {
            "id": findings_count,
            "message": message,
            "file": file_path,
            "start_line": start_line,
            "end_line": end_line,
            "code_snippet": lines_of_code
        }

        # Sorting the dictionary by project owner
        project_key = "" # Default string for owner
        try:
            parts = file_path.split('/')
            if len(parts) > 1:
                project_key = parts[1]
            else:
                project_key = parts[0] 
        except Exception:
            pass # Stick with the default name

        if project_key not in vuln_by_project:
            vuln_by_project[project_key] = []
        
        vuln_by_project[project_key].append(finding_data)

    with open("./results/lines_semgrep.json", 'w', encoding='utf-8') as f:
        json.dump(vuln_by_project, f, indent=4)

if __name__ == "__main__":
    parse_semgrep_report("./results/semgrep_results.json")