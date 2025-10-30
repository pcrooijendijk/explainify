#!/bin/bash
set -e  # Exit if any command fails

GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
RESET="\033[0m"

run_step() {
    echo -e "${YELLOW}>>> Running: $1 ${RESET}"
    if python "$1"; then
        echo -e "${GREEN}✔ Finished: $1${RESET}\n"
    else
        echo -e "${RED}✖ Failed: $1${RESET}\n"
        exit 1
    fi
}

run_step get_CWE.py
# Running the root cause analysis using both Semgrep and Snyk
cd file_downloads/
semgrep scan --verbose --no-git-ignore --json --output results/semgrep_results.json
snyk code test --all-projects --json-file-output=vuln.json

run_step utils/read_semgrep.py
run_step utils/read_snyk.py
run_step utils/comparator.py
run_step CWE_runner.py

echo -e "${GREEN} All scripts completed successfully!${RESET}"

