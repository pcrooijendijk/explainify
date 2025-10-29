import json

def parse_snyk_report(json_file_path):
    with open(json_file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    findings_count = 0 # For counting the findings
    vuln_by_project = {}

    run = data['runs'][0]
    rules = run['tool']['driver']['rules']

    # Check if there are rules, if not the CWE description is missing
    if not rules:
        print("No 'rules' definitions found in the report.")

    for result in run['results']:
        findings_count += 1
        
        message = result.get('message', {}).get('text', 'No description provided.')

        location = result.get('locations', [{}])[0]
        physical_location = location['physicalLocation']
        artifact_location = physical_location['artifactLocation']
        region = physical_location['region']

        file_path = artifact_location.get('uri', 'Unknown file')
        start_line = region.get('startLine', 'N/A')
        end_line = region.get('endLine', start_line) # Default to start_line if end_line is missing

        cwe_id = "CWE-Unknown"
        rule_index = result['ruleIndex']
        
        if rule_index is not None and rule_index < len(rules):
            rule = rules[rule_index]
            cwe_list = rule.get('properties', {}).get('cwe', [])
            if cwe_list:
                cwe_id = cwe_list[0]
        
        file_path = "file_downloads/" + file_path

        finding_data = {
            "id": findings_count,
            "message": message,
            "cwe": cwe_id,
            "file": file_path,
            "start_line": start_line,
            "end_line": end_line
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

    with open("./results/lines_snyk.json", "w") as f: 
        json.dump(vuln_by_project, f, indent=4)
def main():
    parse_snyk_report("./file_downloads/vuln.json")

if __name__ == "__main__":
    main()