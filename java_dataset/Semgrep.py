import json

class Semgrep: 
    def __init__(self):
        self.json_file_path = "semgrep_results.json"

        with open(self.json_file_path, 'r', encoding='utf-8') as f:
            self.data = json.load(f)

    def set_results(self):
        self.result_list = {}

        for result in self.data['results']:
            file_name = result['path']

            finding_details = {
                "start_line": result['start'], 
                "end_line": result['end'],
                "message": result['extra']['message'],
                "vuln_ids": result['extra']['metadata'].get('cwe') 
            }

            if file_name not in self.result_list:
                self.result_list[file_name] = []

            # Saving it to a dictionary
            self.result_list[file_name].append(finding_details)