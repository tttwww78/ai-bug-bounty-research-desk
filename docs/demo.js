(() => {
  "use strict";

  const MAX_CHARS = 20000;
  const SAMPLE_OLD = `Program: Example Research Program (fictional)
In scope:
- portal.example.test
- GET /api/v1/*
Rate limit: no more than 2 requests per second
Not allowed: brute force, denial of service, or testing real user accounts`;
  const SAMPLE_CURRENT = `Program: Example Research Program (fictional)
In scope:
- portal.example.test
- api.example.test
- GET /api/v1/* and GET /api/v2/status
Rate limit: no more than 1 request per second
Not allowed: brute force, denial of service, or testing real user accounts`;

  const oldInput = document.getElementById("previous-rules");
  const currentInput = document.getElementById("current-rules");
  const compareButton = document.getElementById("compare-rules");
  const exportButton = document.getElementById("export-review");
  const resultsSection = document.getElementById("results-section");
  const compareMessage = document.getElementById("compare-message");
  const changeList = document.getElementById("change-list");
  const candidateList = document.getElementById("candidate-list");
  const noChanges = document.getElementById("no-changes");
  const noCandidates = document.getElementById("no-candidates");
  const state = { changes: [], candidates: [], filter: "all", reviewed: new Set() };

  function setMessage(message) {
    compareMessage.textContent = message;
    compareMessage.hidden = !message;
  }

  function updateCounts() {
    document.getElementById("previous-count").textContent = `${oldInput.value.length.toLocaleString()} / ${MAX_CHARS.toLocaleString()}`;
    document.getElementById("current-count").textContent = `${currentInput.value.length.toLocaleString()} / ${MAX_CHARS.toLocaleString()}`;
  }

  function handleInputChange() {
    updateCounts();
    if (!resultsSection.hidden) {
      resultsSection.hidden = true;
      setMessage("The policy text changed. Compare again to refresh the review.");
    }
  }

  function lineRecords(text, version) {
    return text.replace(/\r\n?/g, "\n").split("\n").map((raw, index) => ({
      raw,
      number: index + 1,
      version,
      key: raw.trim().replace(/[\t ]+/g, " ")
    })).filter((line) => line.key.length > 0);
  }

  function compareLines(oldText, currentText) {
    const oldLines = lineRecords(oldText, "previous");
    const currentLines = lineRecords(currentText, "current");
    const oldBuckets = new Map();

    oldLines.forEach((line) => {
      const bucket = oldBuckets.get(line.key) || [];
      bucket.push({ ...line, matched: false });
      oldBuckets.set(line.key, bucket);
    });

    const added = [];
    currentLines.forEach((line, index) => {
      const bucket = oldBuckets.get(line.key);
      const match = bucket?.find((candidate) => !candidate.matched);
      if (match) {
        match.matched = true;
        return;
      }
      added.push({ ...line, kind: "added", id: `added-${line.number}-${index}` });
    });

    const removed = [];
    oldBuckets.forEach((bucket) => {
      bucket.filter((line) => !line.matched).forEach((line, index) => {
        removed.push({ ...line, kind: "removed", id: `removed-${line.number}-${index}` });
      });
    });

    return [...added, ...removed];
  }

  function extractCandidates(changes) {
    const candidates = [];
    const seen = new Set();
    const domainPattern = /\b(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
    const pathPattern = /(?:^|\s)(\/[A-Za-z0-9._~%*:/-]{1,})/g;
    const limitPattern = /\b(?:rate\s*limit|rps|rpm|\d+\s*(?:requests?|reqs?)\s*(?:per|\/)\s*(?:second|minute|hour|sec|min|s|m|h))\b/i;
    const restrictionPattern = /\b(?:not allowed|not permitted|prohibited|forbidden|out[-\s]?of[-\s]?scope|excluded?|do not test|no scanning|no brute[- ]?force|denial[- ]of[- ]service)\b/i;
    const scopePattern = /\b(?:in[- ]scope|allowed domain|scope|included?|excluded?)\b/i;

    function add(category, term, change) {
      const cleanTerm = term.trim();
      if (!cleanTerm) return;
      const key = `${category}|${cleanTerm.toLowerCase()}|${change.version}|${change.number}`;
      if (seen.has(key)) return;
      seen.add(key);
      candidates.push({ category, term: cleanTerm, change });
    }

    changes.forEach((change) => {
      const domains = change.raw.match(domainPattern) || [];
      domains.forEach((domain) => add("Domain candidate", domain, change));

      let pathMatch;
      while ((pathMatch = pathPattern.exec(change.raw)) !== null) {
        const path = pathMatch[1].replace(/[),.;]+$/, "");
        if (path && path !== "/") add("Path candidate", path, change);
      }
      pathPattern.lastIndex = 0;

      if (limitPattern.test(change.raw)) add("Rate / limit text", change.raw, change);
      if (restrictionPattern.test(change.raw)) add("Restriction text", change.raw, change);
      if (scopePattern.test(change.raw) && domains.length === 0) add("Scope statement", change.raw, change);
    });

    return candidates;
  }

  function makeElement(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }

  function renderSummary() {
    const summary = document.getElementById("summary-grid");
    summary.replaceChildren();
    const addedCount = state.changes.filter((change) => change.kind === "added").length;
    const removedCount = state.changes.filter((change) => change.kind === "removed").length;
    const reviewedCount = state.changes.filter((change) => state.reviewed.has(change.id)).length;
    const items = [
      { className: "added", value: addedCount, label: "Added lines" },
      { className: "removed", value: removedCount, label: "Removed lines" },
      { className: "review", value: `${reviewedCount} / ${state.changes.length}`, label: "Changes reviewed" }
    ];
    items.forEach((item) => {
      const card = makeElement("div", `summary-item ${item.className}`);
      card.append(makeElement("strong", "", String(item.value)), makeElement("span", "", item.label));
      summary.append(card);
    });
    exportButton.disabled = state.changes.length === 0;
  }

  function renderChanges() {
    changeList.replaceChildren();
    const visible = state.changes.filter((change) => state.filter === "all" || change.kind === state.filter);
    noChanges.hidden = visible.length > 0;

    visible.forEach((change) => {
      const item = makeElement("li", "change-row");
      const meta = makeElement("div", "change-meta");
      const badge = makeElement("span", `change-kind ${change.kind}`, change.kind);
      const version = change.version === "current" ? "Current version" : "Previous version";
      const lineRef = makeElement("span", "line-ref", `${version}, line ${change.number}`);
      meta.append(badge, lineRef);
      const quote = makeElement("code", "source-line", change.raw);
      const label = makeElement("label", "review-control");
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.checked = state.reviewed.has(change.id);
      checkbox.setAttribute("aria-label", `Mark ${change.kind} line ${change.number} as reviewed`);
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) state.reviewed.add(change.id);
        else state.reviewed.delete(change.id);
        renderSummary();
      });
      label.append(checkbox, makeElement("span", "", "I reviewed this source line"));
      item.append(meta, quote, label);
      changeList.append(item);
    });
  }

  function renderCandidates() {
    candidateList.replaceChildren();
    noCandidates.hidden = state.candidates.length > 0;
    state.candidates.forEach((candidate) => {
      const item = makeElement("li", "candidate-row");
      const category = makeElement("span", "candidate-category", candidate.category);
      const term = makeElement("strong", "candidate-term", candidate.term);
      const version = candidate.change.version === "current" ? "Current" : "Previous";
      const source = makeElement("span", "candidate-source", `${version} version, line ${candidate.change.number}: ${candidate.change.raw}`);
      item.append(category, term, source);
      candidateList.append(item);
    });
  }

  function compare() {
    setMessage("");
    if (!oldInput.value.trim() || !currentInput.value.trim()) {
      setMessage("Paste both the previous and current policy text before comparing.");
      return;
    }
    if (oldInput.value.length > MAX_CHARS || currentInput.value.length > MAX_CHARS) {
      setMessage("Each policy version must be 20,000 characters or fewer.");
      return;
    }
    state.changes = compareLines(oldInput.value, currentInput.value);
    state.candidates = extractCandidates(state.changes);
    state.reviewed.clear();
    state.filter = "all";
    document.querySelectorAll(".filter-button").forEach((button) => {
      const active = button.dataset.filter === "all";
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-pressed", String(active));
    });
    renderSummary();
    renderChanges();
    renderCandidates();
    resultsSection.hidden = false;
    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function escapeMarkdown(text) {
    return String(text).replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
  }

  function exportReview() {
    const lines = [
      "# Scope Change Review",
      "",
      `Generated: ${new Date().toISOString()}`,
      "",
      "> This report compares user-provided text only. It does not verify authorization or test any target.",
      "",
      "## Changes"
    ];
    if (state.changes.length === 0) lines.push("No line changes found.");
    state.changes.forEach((change) => {
      const reviewed = state.reviewed.has(change.id) ? "Reviewed" : "Needs review";
      const version = change.version === "current" ? "Current" : "Previous";
      lines.push(`- **${change.kind.toUpperCase()} — ${reviewed}** (${version}, line ${change.number})`);
      lines.push(`  > ${escapeMarkdown(change.raw)}`);
    });
    lines.push("", "## Candidate terms", "");
    if (state.candidates.length === 0) lines.push("No terms matched the current keyword patterns.");
    state.candidates.forEach((candidate) => {
      const version = candidate.change.version === "current" ? "Current" : "Previous";
      lines.push(`- **${escapeMarkdown(candidate.category)}:** ${escapeMarkdown(candidate.term)} — ${version}, line ${candidate.change.number}`);
      lines.push(`  > ${escapeMarkdown(candidate.change.raw)}`);
    });
    const blob = new Blob([lines.join("\n")], { type: "text/markdown;charset=utf-8" });
    const objectUrl = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = "scope-change-review.md";
    link.click();
    URL.revokeObjectURL(objectUrl);
  }

  document.getElementById("load-sample").addEventListener("click", () => {
    oldInput.value = SAMPLE_OLD;
    currentInput.value = SAMPLE_CURRENT;
    handleInputChange();
    setMessage("");
    oldInput.focus();
  });

  document.getElementById("clear-all").addEventListener("click", () => {
    oldInput.value = "";
    currentInput.value = "";
    state.changes = [];
    state.candidates = [];
    state.reviewed.clear();
    resultsSection.hidden = true;
    setMessage("");
    renderSummary();
    renderChanges();
    renderCandidates();
    updateCounts();
    oldInput.focus();
  });

  compareButton.addEventListener("click", compare);
  exportButton.addEventListener("click", exportReview);
  oldInput.addEventListener("input", handleInputChange);
  currentInput.addEventListener("input", handleInputChange);

  document.querySelectorAll(".filter-button").forEach((button) => {
    button.addEventListener("click", () => {
      state.filter = button.dataset.filter;
      document.querySelectorAll(".filter-button").forEach((item) => {
        const active = item === button;
        item.classList.toggle("is-active", active);
        item.setAttribute("aria-pressed", String(active));
      });
      renderChanges();
    });
  });

  updateCounts();
  renderSummary();
})();
