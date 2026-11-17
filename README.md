# ScopeDesk — AI-Assisted Bug Bounty Research Desk

ScopeDesk is a local-first workspace for organizing authorized bug bounty research. It helps a researcher record a program's scope, inspect sanitized technical artifacts, track AI-generated hypotheses, and prepare a report that a person has manually verified.

The existing Windows app is the full research workspace. A small browser-only scope-change demo is being added for the Kiroween entry; it will compare two policy versions without sending their text to a server.

## What it does

- Records the official program link, exact in-scope domains and paths, exclusions, rate limits, and authorization notes.
- Imports user-provided HAR, Burp XML, OpenAPI JSON, or selected Java controller source for local analysis.
- Redacts common credentials and personal values from imported request metadata.
- Produces candidate findings and report drafts through a user-configured OpenAI-compatible API. Model output is a hypothesis, not a verified vulnerability.
- Tracks manual verification evidence and report status.
- Optionally performs one HTTPS `HEAD` reachability check after explicit confirmation. It is limited to the exact authorized host and port 443, sends no credentials or query parameters, and does not follow redirects.

## Safety boundaries

ScopeDesk does not scan targets, enumerate paths, test credentials, exploit vulnerabilities, read third-party data, or submit reports. The researcher must confirm the current program rules and manually verify every finding.

The local database and evidence files are not encrypted. Keep `data/`, API keys, `.streamlit/secrets.toml`, and private artifacts out of GitHub. The optional AI call sends the selected project summary and imported metadata to the endpoint configured by the user.

The companion browser demo is designed to compare only text entered by the user. It must not fetch target pages or transmit pasted policy text.

## Run the local app on Windows

Requirements: Python 3.11 and network access for the initial dependency install.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1
```

Or double-click `run_windows.bat`. The server binds to `127.0.0.1`.

To put working data on another drive:

```powershell
$env:AI_BUG_BOUNTY_DATA_DIR = 'F:\BugBountyData'
.\run_windows.bat
```

## Demo

The Kiroween release will include a public static demo under `docs/`. The demo will use fictional `.test` hostnames, keep data in the browser, and provide a Markdown review export.

## Repository and license

The complete local research app and its setup instructions are included in this repository. The project is licensed under the MIT License; see [LICENSE](LICENSE).

For Chinese instructions, see [README.zh-CN.md](README.zh-CN.md).
