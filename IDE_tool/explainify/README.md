# Explainify: A Static Analysis Framework utilizing Large Language Models for Explaining Vulnerabilities

## Overview

**Explainify** is an Integrated Development Environment (IDE) extension designed to expalin the outcomes of Static Application Security Testing (SAST). This framework integrates **Semgrep** which is a static analysis tool, with **Google Gemini**, a Large Language Model (LLM). The system automates the detection of security flaws and augments them with explanations, risk assessments, and remediation strategies directly within the developer's workspace.

## 1\. System Overview

The framework operates as a Visual Studio Code extension where:

1.  The system starts with a workspace-wide scan using the Semgrep CLI to identify potential vulnerabilities based on semantic code patterns.
2.  A prompt, containing the vulnerability metadata and code context, is send to Gemini.
3.  The LLM's response is parsed and mapped back to the source code, providing inline visual cues and detailed diagnostic reports.

## 2\. Key Capabilities

The tool perfroms an alaysis of the active project, supporting the anlaysis of multiple files. It uses an LLM to analyze specific details and explains why the vulnerability is present given a predefined template. Some visualization is applied such as yellow underlinings to highlight vulnerable code segments and file names are highlighted which allows rapid identificiation of vulnerable files within the project. 

## 3\. Requirements

### Installation

1.  Clone or download the repository:

```
git clone explainify
cd explainify
```

1.  Install the requirements:

```
pip install -r requirements.txt
```

### Semgrep

```
# Install through homebrew for macOS
brew install semgrep

# Install through pip
python3 -m pip install semgrep

# Confirm installation succeeded by printing the currently installed version
semgrep --version

# Login to semgrep 
semgrep login
```

### LLM API key

To run this extension, a valid Google Gemini key is required which needs to be in a file named `.env` and define the API key as follows:

```
GOOGLE_API_KEY=your_api_key_here
```