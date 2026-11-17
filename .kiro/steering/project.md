# Project Steering

## Product

ScopeDesk is a safety-first research workspace for bug bounty programs. It organizes user-provided authorization rules, sanitized technical artifacts, candidate findings, manual verification notes, and report drafts.

## Boundaries

- The app never scans targets, brute-forces paths, tests credentials, exploits vulnerabilities, reads third-party data, or submits reports.
- Scope and authorization come only from the user and the current program rules. The app must not infer permission from a URL or a prior approval.
- The public browser demo compares text pasted by the visitor. It must not send text to a server, model, API, analytics service, or third-party script.
- Every automated extraction is a candidate with an exact source excerpt. Human review remains explicit.

## Implementation

- Keep the existing Streamlit desktop workflow compatible with Python 3.11 and the dependency range in `requirements.txt`.
- The public demo uses browser-native HTML, CSS, and JavaScript; do not add runtime dependencies.
- Render all user-provided text as text, never as HTML. Do not use `innerHTML` with user content.
- Keep secrets, local databases, imported files, and evidence out of Git.
- Use English for the public demo and primary README. Preserve a concise Chinese guide for the owner.
