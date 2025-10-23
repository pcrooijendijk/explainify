import json
import os
import re
from typing import Dict

def get_patch_files(download_folder: str) -> Dict:
    # Getting the patches and their indices
    patch_to_file = {}
    for i, filename in enumerate(os.listdir(download_folder)):
        patch_to_file[i+1] = os.path.join(download_folder, filename)
    return patch_to_file

def main(patch_data: Dict) -> None:
    result = {} # Storing the results of finding the line numbers

    # Going through the different repositories with the patches and relevant lines attached
    for repo in patch_data:   
        repo_name = repo.split("_patch.json")[0] # Getting the repository name
        print("repo", repo_name)

        for version in ["old", "new"]:
            download_folder = f"./file_downloads/{repo_name}/{version}/"  
            patch_to_file = get_patch_files(download_folder)

            for entry in patch_data[repo]["lines"]:
                patch_index = entry["patch_index"]
                lines_to_find = entry["lines"]
                print(patch_index)
                
                if patch_index not in patch_to_file:
                    print(f"Patch index {patch_index} file not found!")
                    continue

                file_path = patch_to_file[patch_index]

                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.readlines()
                print(content)
                print(lines_to_find)
                pattern = re.escape(lines_to_find[0]) + r"\(.*?\),"
                dinges = []
                for i in content:
                    match = re.search(pattern, i, re.DOTALL)
                    dinges.append(match)
                print(dinges)
                if match:
                    print("Match found! Here is the full code block:\n")
                    print(match.group(0))
                else:
                    print("No match found.")
                break
            break
        break

                # for target_line in lines_to_find:
                #     for lineno, line in enumerate(content, start=1):
                #         print(target_line)
                #         print(line)
                #         if target_line.strip() in line.strip():
                #             print(repo_name)
                #             if repo_name not in result:
                #                 result[repo_name] = {}

                #             relative_path = str(file_path).split(f"{repo_name}", 1)[1]

                #             if relative_path not in result[repo_name]:
                #                 result[repo_name][relative_path] = []
                            
                #             # Append the match to the resulting dictionary
                #             result[repo_name][relative_path].append({ 
                #                 "found_lines": lineno,
                #                 "file": file_path,
                #                 "line": line.strip(),
                #             })

                #             print(f"Line found at {lineno}: {line.strip()}")

    with open("./results/found_lines.json", "w") as f: 
        json.dump(result, f, indent=4)

if __name__ == "__main__":
    path_relevant_lines = "./results/relevant_lines.json" # The json file with the relevant patches and lines

    with open(path_relevant_lines, "r") as f: 
        patch_data = json.load(f)
    
    main(patch_data)