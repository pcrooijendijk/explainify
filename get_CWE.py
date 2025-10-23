# Script to get CVEs by CWE-id -> CWE-89 of the past 20 days

import nvdlib
import datetime
import lxml.html
import requests
from typing import List, Tuple
from urllib.parse import urljoin
import json
from langdetect import detect
import time
import subprocess
import os
from dotenv import load_dotenv

load_dotenv()  

NVD_KEY = os.getenv("NVD_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"} 

CSV_FILE = "commit_data.csv"

def run_diffsitter(old_file, new_file):
    result = subprocess.run(
        ["diffsitter", old_file, new_file],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    return result.stdout

def search_by_cwe(cwe_id, start_date='2024-01-01 00:00', end_date='2025-09-01 23:59'):
    results = nvdlib.searchCVE(
        pubStartDate=start_date,
        pubEndDate=end_date,
        key=NVD_KEY,
        delay=6,
    )

    csv_data = [] # List for storing the CSV data which should be added to the CSV file

    filtered = []
    for cve in results:

        # Get the references of the CVE to check if it's a GitHub commit
        references_urls = cve.__dict__["references"]
        references = [ref.__dict__["url"] for ref in references_urls]

        for url in references:
            if ("github" in url):
                if ("commit" in url):
                    csv_data.append([cve.id, url])
                    # Only proceed if there is a GitHub commit in the references
                    for w in getattr(cve, "weaknesses", []):
                        w = w.__dict__
                        for desc in w["description"]:
                            desc = desc.__dict__
                            if desc["value"] == cwe_id:
                                filtered.append(cve)
    return filtered, csv_data

def clean_number_pull(url: str) -> str:
    if "pull/" not in url:
        return url

    # Split around "pull/"
    parts = url.split("pull/", 1)
    left = parts[0]  # "https://github.com/org/repo/"
    right = parts[1]

    # Remove the pull request number
    right = right.split("/", 1)[1] if "/" in right else ""

    normalized = left + right
    normalized = normalized.replace("commits", "commit")

    # Ensure full GitHub URL
    if normalized.startswith("/"):
        normalized = "https://www.github.com" + normalized

    return normalized

def download_file(url: str, save_path: str):
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            with open(save_path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(resp.text)
            print(f"Saved file: {save_path}")
        else:
            print(f"Failed to download {url}: HTTP {resp.status_code}")
    except Exception as e:
        print(f"Error downloading {url}: {e}")

def process_commits_page(url: str, cve: str):
    try:
        response = requests.get(url, timeout=10, headers=HEADERS)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"# ERROR fetching {url}: {e}")
        return

    doc = lxml.html.fromstring(response.content)
    commit_links = doc.xpath('//*[@id="commits_bucket"]//a[@class="message"]/@href')

    for href in commit_links:
        if "issues" in href:
            continue
        full_url = urljoin("https://github.com", href)
        print(f"{cve};{clean_number_pull(full_url)}")

def get_pull(csv_data: List) -> List:
    csv_data_list = []
    for cve in csv_data: 
        url = cve[1]
        if url.endswith("/commits"):
            process_commits_page(url, cve)

        elif "pull/" in url:
            csv_data_list.append([cve, clean_number_pull(url)])

        else:
            csv_data_list.append([cve, url])
    return csv_data_list

# Getting the commit URLs, commits and diffs
def get_commit_files(commit_url: str, cve_id: str) -> Tuple[str, str, List[str]]:
    parts = commit_url.rstrip("/").split("/")
    if len(parts) < 7:
        print(f"Invalid commit URL: {commit_url}")
        return [], [], [], []

    owner, repo, commit_hash = parts[3], parts[4], parts[6]

    api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_hash}"
    
    # Getting the data and commit message from the URL
    try:
        resp = requests.get(api_url, headers=HEADERS)
        if resp.status_code == 200:
            data = resp.json()
            commit_message = data['commit']['message'].replace('\n', ' ').replace(';', ',')
            if detect(commit_message) != "en":
                print("GitHub commit message is not in English.")
                return [], [], [], []
            elif len(commit_message) < 50:
                print("GitHub commit message is too short.")
                return [], [], [], []
            elif commit_message.lower().find("Merge commit from fork".lower()) != -1:
                return [], [], [], []
            elif commit_message.lower().find("Merge commit".lower()) != -1:
                return [], [], [], []
        else: 
            commit_message = "None"      
        resp.raise_for_status()
    except Exception as e:
        print(f"GitHub API error for {commit_url}: {e}")
        return [], [], [], []

    data = resp.json()
    if "files" not in data or not data["files"]:
        print(f"No files changed in {commit_url}")
        return [], [], [], []

    parent_hash = data["parents"][0]["sha"] if data["parents"] else None
    if not parent_hash:
        print(f"No parent found for {commit_url}")
        return [], [], [], []

    old_links, new_links, original_filenames = [], [], []

    files = []
    dataset = []
    dum = {}
    # Getting the links and diffs from the URL
    for file in data["files"]:
        path = file["filename"]
        old_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{parent_hash}/{path}"
        new_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{commit_hash}/{path}"

        diff = file.get("patch", "").replace(";", ",") if "patch" in file else " "

        files.append(
            {
                "filename": path,
                "old_url": old_url, 
                "new_url": new_url, 
                "diff": diff,
            }
        )

        dum[path] = {
            "cve_id": cve_id,
            "repo": repo,
            "file": file,
            "diff": diff,
            "message": commit_message,
        }

        old_file_path = f"./file_downloads/{owner}/old/{os.path.basename(path)}"
        new_file_path = f"./file_downloads/{owner}/new/{os.path.basename(path)}"

        download_file(old_url, old_file_path)
        download_file(new_url, new_file_path)

        old_links.append(old_url)
        new_links.append(new_url)
        original_filenames.append(path.split("/")[-1])
    
    patch_path = f"./patch_data/{owner}_patch.json"
    os.makedirs(os.path.dirname(patch_path), exist_ok=True)
    with open(patch_path, "w") as txt_write: 
        json.dump(dum, txt_write, indent=4)

    dataset.append(
        {
            "cve_id": cve_id,
            "repo": repo, 
            "commit_hash": commit_hash,
            "commit_message": commit_message,
            "files_changed": files
        }
    )

    return old_links, new_links, original_filenames, dataset

def process_csv(csv_data_list: List) -> None:
    final_dataset = []
    saved_files = 0

    for _, row in enumerate(csv_data_list):
        cve_id, commit_url = row
        print(f"\nProcessing {cve_id} - {commit_url}")

        old_links, new_links, _, dataset = get_commit_files(commit_url, cve_id)
        if dataset: 
            final_dataset.append(dataset)
            saved_files += 1
        if not old_links and not new_links:
            print(f"No files to download for {commit_url}, skipping.")
            continue
        if saved_files == 20: 
            break

    with open("./results/commits_dataset_test.json", "w") as f: 
        json.dump(final_dataset, f, indent=2)

if __name__ == "__main__":
    # Getting the time frame in which to search for the specified CWE
    end = datetime.datetime.now()
    start = end - datetime.timedelta(days=20)

    # Getting the CVEs and the data by searching within the time frime and looking for a specific CWE-id
    cves, csv_data = search_by_cwe("CWE-89", start_date=start, end_date=end)

    for c in cves:
        print(c.id, c.url)

    csv_data_list = get_pull(csv_data)
    process_csv(csv_data_list)