/**
 * Aegis Playground — Main application logic.
 *
 * Loads Pyodide, installs agent-aegis, and provides interactive
 * policy evaluation entirely in the browser.
 */

/* ---- State ---- */
let pyodide = null;
let editor = null;
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
}

/* ---- Event Binding ---- */
function bindEvents() {
  // Preset buttons
  document.querySelectorAll(".preset-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelector(".preset-btn.active")?.classList.remove("active");
      btn.classList.add("active");
      editor.setValue(POLICY_PRESETS[btn.dataset.preset]);
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
    setTimeout(() => $overlay.classList.add("hidden"), 400);
  } catch (err) {
    setProgress(0, `Error: ${err.message}`);
    console.error("Pyodide init failed:", err);
  }
}

function setProgress(pct, msg) {
  $progress.style.width = pct + "%";
  $status.textContent = msg;
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
    <div class="result-allowed ${isAllowed ? "yes" : "no"}">
      ${isAllowed ? "&#x2705; ALLOWED" : "&#x1F6AB; BLOCKED"}
      ${!isAllowed && r.approval === "block" ? " — Policy explicitly blocks this action" : ""}
    </div>
  `;

  // Prepend (latest first)
  const empty = $result.querySelector(".empty-state");
  if (empty) empty.remove();
  $result.prepend(card);
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
function escHtml(s) {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

/* ---- Python evaluation code ---- */
const AEGIS_SETUP_CODE = `
import json
import yaml
from aegis.core.action import Action
from aegis.core.policy import Policy

def evaluate_action(yaml_str, action_dict):
    """Evaluate a single action against a YAML policy. Returns JSON string."""
    try:
        policy_data = yaml.safe_load(yaml_str)
        policy = Policy.from_dict(policy_data)

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
`;
