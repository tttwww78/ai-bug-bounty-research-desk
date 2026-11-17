# Kiroween Research Desk Readiness Plan

> **For agentic workers:** Use this plan task by task, keeping the local copy isolated from the original workspace.

**Goal:** Turn the local AI Bug Bounty Research Desk into a truthful, public Kiroween 2026 entry with a working demo and documented Kiro use.

**Architecture:** Keep the existing Python 3.11 / Streamlit desktop workflow as the full local app. Add a small English, browser-only scope-revision demo under `docs/` for GitHub Pages; it compares user-provided rule text, quotes exact source lines, records manual review, and exports a Markdown checklist. All demo processing stays in the browser and makes no network requests.

**Tech Stack:** Existing Streamlit app and Python standard library; new demo uses plain HTML, CSS, and JavaScript; GitHub Pages publishes `/docs`.

## Global Constraints

- Preserve the original `ai_bug_bounty_agent_v1` folder; work only in the separate `Kiro-Bounty-ResearchDesk` copy.
- Use the existing source as the project baseline; do not claim it was newly authored by Kiro.
- Kiro must make a real, observable contribution before the Devpost entry describes Kiro use.
- Keep `.kiro/` at repository root and commit an open-source license.
- Never scan targets, submit reports, or fetch policy URLs from the demo; compare only text supplied by the user.
- The copy's source-file timestamps show 2026-11-16; confirm the actual start date before final contest submission.
- Do not publish secrets, API keys, databases, uploads, evidence, or local user data.

## Acceptance Criteria

- A visitor can load the hosted demo, compare two policy versions, view additions/removals and extracted scope terms with source excerpts, mark items reviewed, and export a Markdown review record.
- Demo operations are client-side only; it has no external scripts, fonts, API calls, or telemetry.
- The existing local Streamlit workflow and its safety boundaries remain intact.
- Public GitHub repo includes a license, English project README, `.kiro/` artifacts, source, and setup instructions.
- Devpost materials identify the project as a new standalone Kiroween entry, use the Frankenstein category, and describe only verifiable Kiro contributions.
- Demo video is under three minutes and shows the published app working.

## Tasks

### Task 1: Establish the isolated repository

- Inspect the copy for secrets, databases, and generated data.
- Initialize a clean `main` branch in the copied project and commit the unchanged baseline.
- Keep all work out of the original workspace repository.

### Task 2: Prepare the Kiro project contract

- Add root `.kiro/steering/` guidance that states the local-only data flow and safety limits.
- Add a feature spec for the scope-revision review demo with acceptance criteria and non-goals.
- Use Kiro Web on the connected repository to implement the demo; retain an honest record of which feature Kiro changed.

### Task 3: Build the browser demo

- Add the static demo to `docs/` with old/new sample policy text, deterministic line comparison, scope-term extraction, review controls, and Markdown export.
- Keep the layout responsive, keyboard-operable, and readable without relying on color alone.
- Do not add third-party runtime dependencies.

### Task 4: Make the repository submission-ready

- Add an open-source license and an English README; include a Chinese quick-start alongside it.
- Explain local installation, hosted demo behavior, data handling, limitations, and actual Kiro use.
- Configure GitHub Pages to publish `/docs` from `main` and record the live URL.

### Task 5: Prepare and submit the entry

- Create a short public demo video under three minutes showing the real app.
- Fill the Devpost submission with the public repo, hosted demo, video, category, and accurate Kiro-use description.
- Fill the credit request only with the user's Kiro ID and truthful project details; leave ID/selfie verification for the user.
- Before the final submit action, confirm the entry date window and user-facing legal/identity consent fields.

## Open Conditions

- User must sign into the existing Kiro account in p4 so the User ID can be read and Kiro Web can access the repo.
- The user should correct the inferred project start date if the source actually predates 2026-10-30.
- The Devpost rules agreement and identity-verification consent must be confirmed by the entrant.
