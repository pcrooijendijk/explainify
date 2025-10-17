# Explainify

Explainify is a Visual Studio Code extension for exploring vulnerabilities interactively in your code after mining the NVD database. It highlights vulnerable lines in your project, shows CWE IDs, and provides detailed explanations and commit information. It is particularly useful for analyzing/studying security patches, CVEs, and root causes of vulnerabilities.

---

## Features

- Highlights vulnerable lines with a purple wavy underline.
- Hover over underlined lines to see the CWE ID(s) and detailed explanation.
- Click on code snippets in the webview to jump directly to the affected file and lines in the editor.
- Shows repository-level explanations and associated commit messages in a webview page.
- Groups consecutive vulnerable lines to make the view cleaner.
- Supports multiple repositories and multiple CWE entries.

---

## Installation

1. Clone or download the extension repository:

```bash
git clone <your-repo-url>
cd <your-extension-folder>
