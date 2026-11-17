# Scope Change Review Requirements

## Purpose

Help a researcher compare two user-provided versions of a bug bounty program's rules and review the exact text that changed before updating a local authorization record.

## User stories

1. As a researcher, I can paste an older and a newer rules document and see which lines were added, removed, or left unchanged.
2. As a researcher, I can see candidate domains, paths, rate-limit statements, and prohibited-action statements linked to the exact source line that contains them.
3. As a researcher, I can mark each change as reviewed and export a Markdown review record with line evidence and review status.
4. As a new user, I can load a clearly fictional sample so I can understand the workflow without supplying real program data.

## Acceptance criteria

- The comparison is deterministic and runs entirely in the browser.
- Added and removed lines preserve their source line numbers and exact text.
- Unchanged lines preserve the exact text from both versions and carry both source line numbers, with deterministic duplicate handling.
- Extracted terms are labeled as candidates; the UI does not claim they are authoritative or prove authorization.
- Every review checkbox has an accessible label and its state appears in the exported Markdown.
- An accessible filter for All, Added, Removed, and Unchanged is provided.
- The unchanged count appears in the summary grid.
- Unchanged rows display both source line references but do not show a review checkbox.
- Export places unchanged lines in a separate section without a review label.
- The sample uses reserved `.test` hostnames and does not point at a real target.
- Export creates a Markdown file locally in the browser.
- A clear empty state, input-size error, and no-change result are provided.
- The demo makes no network requests and does not persist user-pasted rules.
- Candidate extraction remains limited to changed lines only.

## Non-goals

- Fetching policy pages from URLs.
- Calling an AI model or external API.
- Scanning, probing, validating, or submitting anything to a target.
- Replacing the user's responsibility to read the current official rules.
