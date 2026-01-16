from github import Auth
from github import Github
from urllib.parse import urlparse
from dotenv import load_dotenv
import requests
import pandas as pd
import os

load_dotenv()
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
output_dir = "java_dataset/java_files"
os.makedirs(output_dir, exist_ok=True)

# Use PyGithub to authenticate and make requests to Github
auth = Auth.Token(GITHUB_TOKEN)
g = Github(auth=auth)

# Used the dataset form the Vul4j dataset with Java vulnerabilities
# https://github.com/tuhh-softsec/vul4j/blob/main/dataset/vul4j_dataset.csv
java_data = pd.read_csv("java_dataset/vul4j_dataset.csv")
urls = java_data['human_patch']

for url in urls[:20]:
    parsed = urlparse(url)
    parts = parsed.path.strip("/").split("/")
    owner, repo, sha = parts[0], parts[1], parts[3]

    repo = g.get_repo(owner + "/" + repo)
    commit = repo.get_commit(sha=sha)

    for file in commit.files:
        if file.filename.endswith(".java"): # Only download Java files
            file_url = file.raw_url
            filename = os.path.basename(file.filename)
            filepath = os.path.join(output_dir, filename)

            response = requests.get(file_url)
            if response.status_code == 200: 
                with open(filepath, 'wb') as f: 
                    f.write(response.content)