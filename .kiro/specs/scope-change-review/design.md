# Scope Change Review Design

## Layout

- A compact header states the tool's purpose and local-only privacy boundary.
- Two labeled text areas show the previous and current policy text side by side on wide screens and stacked on narrow screens.
- Controls load fictional sample data, clear both inputs, compare, and export the review.
- Results are grouped as added, removed, and candidate scope terms. Each row shows the source version, line number, exact excerpt, and a review checkbox.

## Comparison model

- Normalize line endings only; preserve visible text exactly.
- Compare line occurrences with a multiset so duplicate lines are not silently collapsed.
- Extract candidate hostnames, path-like strings, rate-limit language, and prohibited-action language from the original lines.
- Treat extraction as a hint only. Never rewrite policy language or decide whether a target is authorized.

## Data handling

- Use no backend and no network APIs.
- Render user text with `textContent`.
- Do not store pasted rules in localStorage, cookies, IndexedDB, logs, or URL parameters.
- Export only when the user presses the export button, using a browser-generated Blob.

## Files

- `docs/index.html`: semantic page structure and labeled controls.
- `docs/demo.css`: responsive visual system and focus states.
- `docs/demo.js`: line comparison, candidate extraction, review state, and Markdown export.
