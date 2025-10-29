import json
from collections import defaultdict

def load_findings_map(filepath: str) -> defaultdict:
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    findings_map = defaultdict(list)
    total_findings = 0
    
    for project, findings in data.items():
        for finding in findings:
            total_findings += 1
            path = finding['file']
            line = finding['start_line']

            if path and line and line != 'Unknown':
                key = (path, line)
                finding['project'] = project 
                findings_map[key].append(finding)
            
    return findings_map

def compare_reports(snyk_file: str, semgrep_file: str, output_file: str) -> None:
    snyk_map = load_findings_map(snyk_file)
    semgrep_map = load_findings_map(semgrep_file)

    agreements = []
    snyk_only = []
    semgrep_only = []

    snyk_locations = set(snyk_map.keys())
    semgrep_locations = set(semgrep_map.keys())

    agreed_locations = snyk_locations.intersection(semgrep_locations)
    for location in agreed_locations:
        patch_file = location[0].split("/")[-1]
        owner = location[0].split("/")[1]
        with open(f"./patch_data/{owner}_patch.json", "r") as f: 
            patch_data = json.load(f)
        for patch in patch_data:
            if patch_file == patch.split("/")[-1]:
                agreements.append({
                    "path": location[0],
                    "start_line": location[1],
                    "owner": snyk_map[location][0]['project'],
                    "diff": patch_data[patch]["diff"],
                    "snyk_findings": snyk_map[location],
                    "semgrep_findings": semgrep_map[location]
                })

    # snyk_only_locations = snyk_locations.difference(semgrep_locations)
    # for location in snyk_only_locations:
    #     snyk_only.extend(snyk_map[location])

    # semgrep_only_locations = semgrep_locations.difference(snyk_locations)
    # for location in semgrep_only_locations:
    #     semgrep_only.extend(semgrep_map[location])

    output_data = {
        "agreements": agreements,
        # "snyk_only": snyk_only,
        # "semgrep_only": semgrep_only
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=4)

if __name__ == "__main__":
    compare_reports("./results/lines_snyk.json", "./results/lines_semgrep.json", "./results/comparison.json")
