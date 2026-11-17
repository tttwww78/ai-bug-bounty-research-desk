# ScopeDesk — AI-Assisted Bug Bounty Research Desk

ScopeDesk is a local-first workspace for organizing authorized bug bounty research. It helps a researcher record a program's scope, inspect sanitized technical artifacts, track AI-generated hypotheses, and prepare a report that a person has manually verified.

The Windows app is the full research workspace. The companion browser demo under `docs/` compares two policy versions, shows exact added and removed lines, highlights scope-related candidates, and exports a manual review record. It processes pasted text in the browser only.

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

The companion browser demo compares only text entered by the user. It does not fetch target pages or transmit pasted policy text.

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

The browser-only demo lives under `docs/`. It uses fictional `.test` hostnames, compares line occurrences, highlights exact source excerpts, supports manual review, and exports a Markdown record. It makes no network requests and does not save pasted policy text. [Open the public demo](https://tttwww78.github.io/ai-bug-bounty-research-desk/).

## Repository and license

The complete local research app and its setup instructions are included in this repository. The project is licensed under the MIT License; see [LICENSE](LICENSE).

For Chinese instructions, see [README.zh-CN.md](README.zh-CN.md).
