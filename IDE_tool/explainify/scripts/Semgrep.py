import json
import os

class Semgrep: 
    def __init__(self):
        # Getting the absolute path to the semgrep results file
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.json_file_path = os.path.join(script_dir, "semgrep_temp_results.json")

        with open(self.json_file_path, 'r', encoding='utf-8') as f:
            self.data = json.load(f)

    def set_results(self) -> None:
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

    # Helper function for ensuring the temporary semgrep file is deleted
    def delete_semgrep_file(self) -> None:
        os.remove(self.json_file_path)