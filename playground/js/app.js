/**
 * Aegis Playground — Main application logic.
 *
 * Loads Pyodide, installs agent-aegis, and provides interactive
 * policy evaluation entirely in the browser.
 */

/* ---- State ---- */
let pyodide = null;
let editor = null;
let actionCount = 0;
let auditEntries = [];

/* ---- DOM refs ---- */
const $overlay = document.getElementById("loading-overlay");
const $status = document.getElementById("loading-status");
const $progress = document.getElementById("progress-fill");
const $result = document.getElementById("result-content");
const $audit = document.getElementById("audit-content");
const $auditCount = document.getElementById("audit-count");

/* ---- Init ---- */
document.addEventListener("DOMContentLoaded", async () => {
  initEditor();
  loadPolicyFromURL();
  bindEvents();
  await initPyodide();
});

/* ---- CodeMirror Setup ---- */
function initEditor() {
  editor = CodeMirror.fromTextArea(document.getElementById("policy-editor"), {
    mode: "yaml",
    theme: "dracula",
    lineNumbers: true,
    tabSize: 2,
    indentWithTabs: false,
    lineWrapping: true,
    viewportMargin: Infinity,
  });
  editor.setValue(POLICY_PRESETS.default);
  initTheme();
}

/* ---- URL State (share policies via URL hash) ---- */
function loadPolicyFromURL() {
  const hash = window.location.hash;
  if (hash && hash.startsWith("#policy=")) {
    try {
      const encoded = hash.slice("#policy=".length);
      const yaml = decodeURIComponent(atob(encoded));
      editor.setValue(yaml);
      // Deactivate all preset buttons
      document.querySelectorAll(".preset-btn").forEach((b) => b.classList.remove("active"));
    } catch {
      // Ignore invalid hash
    }
  }
}

function sharePolicyURL() {
  const yaml = editor.getValue();
  const encoded = btoa(encodeURIComponent(yaml));
  const url = `${window.location.origin}${window.location.pathname}#policy=${encoded}`;
  return url;
}

/* ---- Theme Toggle ---- */
function initTheme() {
  const saved = localStorage.getItem("aegis-theme");
  if (saved === "light") {
    document.documentElement.setAttribute("data-theme", "light");
    editor.setOption("theme", "default");
  }
}

function toggleTheme() {
  const isLight = document.documentElement.getAttribute("data-theme") === "light";
  if (isLight) {
    document.documentElement.removeAttribute("data-theme");
    editor.setOption("theme", "dracula");
    localStorage.setItem("aegis-theme", "dark");
  } else {
    document.documentElement.setAttribute("data-theme", "light");
    editor.setOption("theme", "default");
    localStorage.setItem("aegis-theme", "light");
  }
}

/* ---- Event Binding ---- */
function bindEvents() {
  // Theme toggle
  document.getElementById("theme-toggle").addEventListener("click", toggleTheme);

  // Comparison tabs
  document.querySelectorAll(".comp-tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".comp-tab").forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById("comp-without").classList.toggle("hidden", tab.dataset.tab !== "without");
      document.getElementById("comp-with").classList.toggle("hidden", tab.dataset.tab !== "with");
    });
  });

  // Preset buttons
  document.querySelectorAll(".preset-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelector(".preset-btn.active")?.classList.remove("active");
      btn.classList.add("active");
      const preset = btn.dataset.preset;
      editor.setValue(POLICY_PRESETS[preset]);
      updateActionButtons(preset);
    });
  });

  // Action buttons
  document.querySelectorAll(".action-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const action = JSON.parse(btn.dataset.action);
      evaluateAction(action);
    });
  });

  // Custom action
  document.getElementById("run-custom").addEventListener("click", () => {
    const type = document.getElementById("custom-type").value.trim();
    const target = document.getElementById("custom-target").value.trim();
    const paramsStr = document.getElementById("custom-params").value.trim();

    if (!type) {
      showToast("Action type is required");
      return;
    }

    let params = {};
    if (paramsStr) {
      try {
        params = JSON.parse(paramsStr);
      } catch {
        showToast("Invalid JSON in params");
        return;
      }
    }

    evaluateAction({
      action_type: type,
      target: target || "default",
      params,
      description: `Custom: ${type} on ${target || "default"}`,
    });
  });

  // Run all
  document.getElementById("run-all").addEventListener("click", runAllActions);

  // Keyboard shortcuts
  document.addEventListener("keydown", (e) => {
    // Ctrl/Cmd + Enter → run custom action (or last clicked preset)
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      const type = document.getElementById("custom-type").value.trim();
      if (type) {
        document.getElementById("run-custom").click();
      } else {
        // Run all actions as fallback
        document.getElementById("run-all").click();
      }
    }
    // Ctrl/Cmd + Shift + Enter → run all
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === "Enter") {
      e.preventDefault();
      document.getElementById("run-all").click();
    }
  });

  // Clear buttons
  document.getElementById("clear-result").addEventListener("click", () => {
    $result.innerHTML =
      '<div class="empty-state">Click an action above to see the policy evaluation result</div>';
  });

  document.getElementById("clear-audit").addEventListener("click", () => {
    auditEntries = [];
    $audit.innerHTML =
      '<div class="empty-state">Audit entries will appear here as you evaluate actions</div>';
    $auditCount.textContent = "0 entries";
  });

  // Copy buttons
  document.getElementById("copy-policy").addEventListener("click", (e) => {
    copyToClipboard(editor.getValue(), e.target);
  });

  document.getElementById("copy-pip").addEventListener("click", (e) => {
    copyToClipboard("pip install agent-aegis", e.target);
  });

  document.getElementById("share-policy").addEventListener("click", (e) => {
    const url = sharePolicyURL();
    copyToClipboard(url, e.target);
  });

  // Export audit log
  document.getElementById("export-audit").addEventListener("click", () => {
    if (auditEntries.length === 0) {
      showToast("No audit entries to export");
      return;
    }
    const json = JSON.stringify(auditEntries, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aegis-audit-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });
}

/* ---- Pyodide Init ---- */
async function initPyodide() {
  try {
    setProgress(10, "Loading Python runtime...");
    pyodide = await loadPyodide();

    setProgress(40, "Installing dependencies...");
    await pyodide.loadPackage("micropip");
    const micropip = pyodide.pyimport("micropip");

    setProgress(60, "Installing PyYAML...");
    await micropip.install("pyyaml");

    setProgress(75, "Installing agent-aegis...");
    await micropip.install("agent-aegis");

    setProgress(90, "Setting up evaluation engine...");
    await pyodide.runPythonAsync(AEGIS_SETUP_CODE);

    setProgress(100, "Ready!");
    setupPolicyValidation();
    setTimeout(() => {
      $overlay.classList.add("hidden");
      // Auto-run demo if no policy in URL
      if (!window.location.hash.startsWith("#policy=")) {
        autoDemo();
      }
    }, 400);
  } catch (err) {
    setProgress(0, `Error: ${err.message}`);
    console.error("Pyodide init failed:", err);
  }
}

function setProgress(pct, msg) {
  $progress.style.width = pct + "%";
  $status.textContent = msg;
}

/* ---- Auto Demo ---- */
async function autoDemo() {
  // Run through 3 representative actions to show the playground in action
  const demoActions = [
    { action_type: "read", target: "crm", params: { selector: ".contacts" }, description: "Read contact list" },
    { action_type: "write", target: "crm", params: { field: "name", value: "Alice" }, description: "Update contact name" },
    { action_type: "delete", target: "crm", params: { id: "all" }, description: "Delete all records" },
  ];

  for (const action of demoActions) {
    await evaluateAction(action);
    await new Promise((r) => setTimeout(r, 500));
  }
}

/* ---- Policy Validation ---- */
let validationTimer = null;

function setupPolicyValidation() {
  editor.on("change", () => {
    clearTimeout(validationTimer);
    validationTimer = setTimeout(validatePolicy, 600);
  });
}

async function validatePolicy() {
  if (!pyodide) return;

  // Clear previous marks
  editor.getAllMarks().forEach((m) => m.clear());
  const errorWidget = document.getElementById("editor-error");
  if (errorWidget) errorWidget.remove();

  const yaml = editor.getValue();
  try {
    const resultJson = await pyodide.runPythonAsync(
      `validate_policy(${JSON.stringify(yaml)})`
    );
    const result = JSON.parse(resultJson);

    if (result.error) {
      showEditorError(result.error, result.line);
    }
  } catch (err) {
    // Silently ignore validation errors during typing
  }
}

function showEditorError(msg, line) {
  // Highlight error line
  if (line !== undefined && line !== null && line >= 0) {
    const lineIdx = Math.max(0, line - 1);
    editor.markText(
      { line: lineIdx, ch: 0 },
      { line: lineIdx, ch: editor.getLine(lineIdx)?.length || 0 },
      { className: "cm-error-line" }
    );
  }

  // Show error banner below editor
  const wrapper = document.querySelector(".editor-wrapper");
  let errorEl = document.getElementById("editor-error");
  if (!errorEl) {
    errorEl = document.createElement("div");
    errorEl.id = "editor-error";
    errorEl.className = "editor-error";
    wrapper.parentNode.insertBefore(errorEl, wrapper.nextSibling);
  }
  errorEl.textContent = msg;
}

/* ---- Dynamic Action Buttons for Industry Presets ---- */
const RISK_CLASSES = { low: "risk-low", medium: "risk-medium", high: "risk-high", critical: "risk-critical" };
const RISK_ICONS = {
  low: "&#x1F4D6;", medium: "&#x270F;&#xFE0F;", high: "&#x26A1;", critical: "&#x1F6A8;",
  navigate: "&#x1F310;", read: "&#x1F4D6;", read_file: "&#x1F4C4;", search: "&#x1F50D;",
  create: "&#x2795;", update: "&#x270F;&#xFE0F;", write: "&#x270F;&#xFE0F;", write_file: "&#x1F4DD;",
  export: "&#x1F4E4;", delete: "&#x1F6A8;", merge: "&#x1F500;", shell: "&#x1F4BB;",
  git_push: "&#x1F680;", deploy: "&#x1F6AB;", install: "&#x1F4E6;",
  view: "&#x1F441;&#xFE0F;", report: "&#x1F4CA;", create_invoice: "&#x1F9FE;",
  payment: "&#x1F4B3;", refund: "&#x1F4B8;", transfer: "&#x1F3E6;",
  screenshot: "&#x1F4F7;", scroll: "&#x2195;&#xFE0F;", click: "&#x1F5B1;&#xFE0F;",
  fill: "&#x1F4DD;", submit: "&#x1F4E8;", upload: "&#x1F4E4;", eval: "&#x26D4;", execute_js: "&#x26D4;",
  select: "&#x1F50E;", insert: "&#x2795;", alter_table: "&#x1F527;", drop: "&#x1F4A3;", truncate: "&#x1F4A3;",
  bulk_update: "&#x26A1;", bulk_delete: "&#x1F6A8;",
};

function guessRisk(actionType) {
  if (["read", "read_file", "view", "report", "navigate", "search", "screenshot", "scroll", "select", "list_dir"].includes(actionType)) return "low";
  if (["delete", "drop", "truncate", "deploy", "eval", "execute_js", "transfer"].includes(actionType)) return "critical";
  if (["shell", "bulk_update", "export", "install", "payment", "refund", "upload", "submit", "alter_table"].includes(actionType)) return "high";
  return "medium";
}

function updateActionButtons(preset) {
  const actions = typeof PRESET_ACTIONS !== "undefined" && PRESET_ACTIONS[preset];
  if (!actions) return; // keep default buttons for non-industry presets

  const container = document.querySelector(".quick-actions");
  container.innerHTML = "";
  actions.forEach((a) => {
    const risk = guessRisk(a.action_type);
    const icon = RISK_ICONS[a.action_type] || RISK_ICONS[risk];
    const btn = document.createElement("button");
    btn.className = `action-btn ${RISK_CLASSES[risk]}`;
    btn.dataset.action = JSON.stringify(a);
    btn.innerHTML = `<span class="action-icon">${icon}</span><span class="action-label">${a.description}</span><span class="action-risk">${risk.toUpperCase()}</span>`;
    btn.addEventListener("click", () => evaluateAction(a));
    container.appendChild(btn);
  });
}

/* ---- Evaluate Action ---- */
async function evaluateAction(action) {
  if (!pyodide) {
    showToast("Python runtime is still loading...");
    return;
  }

  const yaml = editor.getValue();

  try {
    const resultJson = await pyodide.runPythonAsync(`
evaluate_action(
  ${JSON.stringify(yaml)},
  ${JSON.stringify(action)}
)
`);
    const result = JSON.parse(resultJson);

    if (result.error) {
      showToast(result.error);
      return;
    }

    renderResult(result);
    addAuditEntry(result);
    actionCount++;
    const counter = document.getElementById("action-counter");
    if (counter) counter.textContent = actionCount;
  } catch (err) {
    showToast(`Evaluation error: ${err.message}`);
    console.error(err);
  }
}

/* ---- Run All Actions ---- */
async function runAllActions() {
  const buttons = document.querySelectorAll(".action-btn");
  for (const btn of buttons) {
    const action = JSON.parse(btn.dataset.action);
    await evaluateAction(action);
    // Small delay for visual effect
    await new Promise((r) => setTimeout(r, 150));
  }
}

/* ---- Render Result ---- */
function renderResult(r) {
  const riskClass = r.risk_level.toLowerCase();
  const approvalClass = r.approval.toLowerCase();
  const isAllowed = r.is_allowed;

  const card = document.createElement("div");
  card.className = "result-card";
  card.innerHTML = `
    <div class="result-header">
      <span class="result-action-type">${escHtml(r.action_type)}</span>
      <span class="result-target">${escHtml(r.target)}</span>
      <div class="result-badges">
        <span class="risk-badge ${riskClass}">${r.risk_level}</span>
        <span class="approval-badge ${approvalClass}">${r.approval}</span>
      </div>
    </div>
    <div class="result-details">
      <div class="result-detail">
        <span class="label">Matched Rule: </span>
        <span class="value">${r.matched_rule ? escHtml(r.matched_rule) : "(default)"}</span>
      </div>
      <div class="result-detail">
        <span class="label">Description: </span>
        <span class="value">${escHtml(r.description || "-")}</span>
      </div>
    </div>
    <div class="result-footer">
      <div class="result-allowed ${isAllowed ? "yes" : "no"}">
        ${isAllowed ? "&#x2705; ALLOWED" : "&#x1F6AB; BLOCKED"}
        ${!isAllowed && r.approval === "block" ? " — Policy explicitly blocks this action" : ""}
      </div>
      <button class="copy-python-btn" title="Copy as Python code">Copy as Python</button>
    </div>
  `;

  // Copy as Python handler
  card.querySelector(".copy-python-btn").addEventListener("click", (e) => {
    const params = r.description
      ? `params=${JSON.stringify({})}, description="${r.description}"`
      : `params=${JSON.stringify({})}`;
    const code = `from aegis import Action, Policy, Runtime

runtime = Runtime(executor=your_executor, policy=Policy.from_yaml("policy.yaml"))
result = await runtime.run_one(Action("${r.action_type}", "${r.target}", ${params}))
# Result: ${r.is_allowed ? "ALLOWED" : "BLOCKED"} (${r.risk_level}, ${r.approval})`;
    copyToClipboard(code, e.target);
  });

  // Add risk-specific border color
  if (!isAllowed) {
    card.style.borderColor = "var(--risk-" + riskClass + ")";
  }

  // Prepend (latest first)
  const empty = $result.querySelector(".empty-state");
  if (empty) empty.remove();
  $result.prepend(card);

  // Shield particles on block (CSS-only, no sound)
  if (r.approval === "block") {
    spawnBlockParticles(card);
  }
}

/* ---- Block Particles (visual feedback for blocked actions) ---- */
function spawnBlockParticles(card) {
  const symbols = ["\u{1F6E1}", "\u{1F6AB}", "\u{26D4}", "\u{2716}"];
  const rect = card.getBoundingClientRect();

  for (let i = 0; i < 8; i++) {
    const p = document.createElement("div");
    p.className = "block-particle";
    p.textContent = symbols[i % symbols.length];
    p.style.left = rect.left + Math.random() * rect.width + "px";
    p.style.top = rect.top + "px";
    p.style.setProperty("--dx", (Math.random() - 0.5) * 120 + "px");
    p.style.setProperty("--dy", -(40 + Math.random() * 80) + "px");
    document.body.appendChild(p);
    p.addEventListener("animationend", () => p.remove());
  }

/* ---- Audit Log ---- */
function addAuditEntry(r) {
  const now = new Date();
  const time = now.toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  const entry = {
    time,
    type: r.action_type,
    risk: r.risk_level,
    decision: r.approval,
    rule: r.matched_rule || "(default)",
    allowed: r.is_allowed,
  };
  auditEntries.push(entry);

  const riskClass = entry.risk.toLowerCase();
  const decisionClass = entry.decision.toLowerCase();

  const row = document.createElement("div");
  row.className = "audit-entry";
  row.innerHTML = `
    <span class="audit-time">${entry.time}</span>
    <span class="audit-type">${escHtml(entry.type)}</span>
    <span class="audit-risk ${riskClass}">${entry.risk}</span>
    <span class="audit-decision ${decisionClass}">${entry.decision}</span>
    <span class="audit-rule">${escHtml(entry.rule)}</span>
  `;

  const empty = $audit.querySelector(".empty-state");
  if (empty) empty.remove();
  $audit.prepend(row);
  $auditCount.textContent = `${auditEntries.length} entries`;
}

/* ---- Toast ---- */
function showToast(msg) {
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.textContent = msg;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

/* ---- Utils ---- */
async function copyToClipboard(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    const orig = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => {
      btn.textContent = orig;
    }, 1500);
  } catch {
    showToast("Failed to copy — try manually");
  }
}

function escHtml(s) {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

/* ---- Python evaluation code ---- */
const AEGIS_SETUP_CODE = `
import json
import yaml
import hashlib
from aegis.core.action import Action
from aegis.core.policy import Policy

# Policy cache — avoids re-parsing identical YAML
_policy_cache = {}

def _get_policy(yaml_str):
    """Get or create cached Policy from YAML string."""
    key = hashlib.md5(yaml_str.encode()).hexdigest()
    if key not in _policy_cache:
        data = yaml.safe_load(yaml_str)
        _policy_cache[key] = Policy.from_dict(data)
        # Keep cache bounded
        if len(_policy_cache) > 20:
            oldest = next(iter(_policy_cache))
            del _policy_cache[oldest]
    return _policy_cache[key]

def evaluate_action(yaml_str, action_dict):
    """Evaluate a single action against a YAML policy. Returns JSON string."""
    try:
        policy = _get_policy(yaml_str)

        action = Action(
            type=action_dict.get("action_type", action_dict.get("type", "")),
            target=action_dict.get("target", ""),
            params=action_dict.get("params", {}),
            description=action_dict.get("description", ""),
        )

        decision = policy.evaluate(action)

        return json.dumps({
            "action_type": action.type,
            "target": action.target,
            "description": action.description,
            "risk_level": decision.risk_level.name,
            "approval": decision.approval.value,
            "is_allowed": decision.is_allowed,
            "matched_rule": decision.matched_rule,
        })
    except Exception as e:
        return json.dumps({"error": str(e)})

def validate_policy(yaml_str):
    """Validate YAML policy syntax. Returns JSON with error info or ok."""
    try:
        data = yaml.safe_load(yaml_str)
        if data is None:
            return json.dumps({"ok": True})
        Policy.from_dict(data)
        return json.dumps({"ok": True})
    except yaml.YAMLError as e:
        line = None
        if hasattr(e, 'problem_mark') and e.problem_mark:
            line = e.problem_mark.line + 1
        return json.dumps({"error": f"YAML syntax error: {e}", "line": line})
    except Exception as e:
        return json.dumps({"error": f"Policy error: {e}", "line": None})
`;
