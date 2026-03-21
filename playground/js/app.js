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
let stats = { total: 0, auto: 0, approve: 0, block: 0, totalMs: 0 };

/* ---- Loading Tips ---- */
const LOADING_TIPS = [
  "Tip: Aegis evaluates policies in under 1ms",
  "Tip: YAML policies can be hot-reloaded without restarting",
  "Tip: 7 adapters — LangChain, CrewAI, OpenAI, Anthropic, MCP, and more",
  "Tip: Use 'aegis simulate' to test policies without executing",
  "Tip: Approval handlers support Slack, Discord, Telegram, and webhooks",
  "Tip: Audit logs export to JSONL for compliance review",
  "Tip: Policy conditions support time-based and parameter-based rules",
  "Tip: Try different industry presets after loading!",
];
let tipInterval = null;
function rotateTips() {
  const $tip = document.getElementById("loading-tip");
  if (!$tip) return;
  let idx = 0;
  tipInterval = setInterval(() => {
    idx = (idx + 1) % LOADING_TIPS.length;
    $tip.style.opacity = 0;
    setTimeout(() => {
      $tip.textContent = LOADING_TIPS[idx];
      $tip.style.opacity = 1;
    }, 300);
  }, 3000);
}

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
  rotateTips();
  initLazyReveal();
  await initPyodide();
});

/* ---- Guided Tour (first-time visitors) ---- */
const TOUR_STEPS = [
  {
    target: ".CodeMirror",
    title: "1. Policy Editor",
    text: "Write YAML governance rules here. Try switching presets above to see different industry policies.",
    position: "right",
  },
  {
    target: ".quick-actions",
    title: "2. Test Actions",
    text: "Click any action button to simulate an AI agent request and see how your policy evaluates it.",
    position: "bottom",
  },
  {
    target: ".result-panel",
    title: "3. See Results",
    text: "Each evaluation shows the decision (auto/approve/block), risk level, and which rule matched.",
    position: "left",
  },
  {
    target: ".audit-panel",
    title: "4. Audit Trail",
    text: "Every decision is logged here. Export as JSON for compliance review.",
    position: "left",
  },
];

function shouldShowTour() {
  return !localStorage.getItem("aegis-tour-done") && !window.location.hash.startsWith("#policy=");
}

function startTour() {
  if (!shouldShowTour()) return;
  let step = 0;

  function showStep() {
    // Remove previous
    document.querySelectorAll(".tour-overlay, .tour-tooltip").forEach((el) => el.remove());
    document.querySelectorAll(".tour-highlight").forEach((el) => el.classList.remove("tour-highlight"));

    if (step >= TOUR_STEPS.length) {
      localStorage.setItem("aegis-tour-done", "1");
      return;
    }

    const s = TOUR_STEPS[step];
    const el = document.querySelector(s.target);
    if (!el) { step++; showStep(); return; }

    el.classList.add("tour-highlight");
    el.scrollIntoView({ behavior: "smooth", block: "center" });

    setTimeout(() => {
      const rect = el.getBoundingClientRect();
      const tip = document.createElement("div");
      tip.className = `tour-tooltip tour-${s.position}`;
      tip.innerHTML = `
        <div class="tour-title">${s.title}</div>
        <div class="tour-text">${s.text}</div>
        <div class="tour-actions">
          <button class="tour-skip">Skip tour</button>
          <button class="tour-next">${step < TOUR_STEPS.length - 1 ? "Next" : "Got it!"}</button>
        </div>
        <div class="tour-progress">${step + 1} / ${TOUR_STEPS.length}</div>`;

      // Position tooltip
      const gap = 12;
      if (s.position === "right") {
        tip.style.top = rect.top + rect.height / 2 + "px";
        tip.style.left = rect.right + gap + "px";
        tip.style.transform = "translateY(-50%)";
      } else if (s.position === "bottom") {
        tip.style.top = rect.bottom + gap + "px";
        tip.style.left = rect.left + rect.width / 2 + "px";
        tip.style.transform = "translateX(-50%)";
      } else {
        tip.style.top = rect.top + rect.height / 2 + "px";
        tip.style.left = rect.left - gap + "px";
        tip.style.transform = "translate(-100%, -50%)";
      }

      document.body.appendChild(tip);

      tip.querySelector(".tour-next").addEventListener("click", () => {
        step++;
        showStep();
      });
      tip.querySelector(".tour-skip").addEventListener("click", () => {
        document.querySelectorAll(".tour-overlay, .tour-tooltip").forEach((e) => e.remove());
        document.querySelectorAll(".tour-highlight").forEach((e) => e.classList.remove("tour-highlight"));
        localStorage.setItem("aegis-tour-done", "1");
      });
    }, 350);
  }

  // Delay tour start so user sees the interface first
  setTimeout(showStep, 800);
}

/* ---- Lazy Reveal (fade-in below-fold sections) ---- */
function initLazyReveal() {
  const sections = document.querySelectorAll(
    ".how-it-works, .usecases-section, .comparison-section, .cta-section"
  );
  if (!sections.length || !("IntersectionObserver" in window)) return;

  sections.forEach((s) => s.classList.add("reveal-hidden"));

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("reveal-visible");
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.1, rootMargin: "0px 0px -40px 0px" }
  );
  sections.forEach((s) => observer.observe(s));
}

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

function openShareModal() {
  const url = sharePolicyURL();
  const ruleCount = (editor.getValue().match(/- name:/g) || []).length;
  const text = `Check out my AI agent governance policy (${ruleCount} rules) built with Aegis Playground`;

  let modal = document.getElementById("share-modal");
  if (!modal) {
    modal = document.createElement("div");
    modal.id = "share-modal";
    modal.className = "shortcut-overlay hidden";
    modal.innerHTML = `
      <div class="shortcut-modal share-modal-inner">
        <div class="shortcut-header">
          <h3>Share This Policy</h3>
          <button class="shortcut-close" aria-label="Close">&times;</button>
        </div>
        <div class="share-url-row">
          <input type="text" id="share-url-input" readonly class="share-url-input">
          <button id="share-copy-btn" class="action-btn action-low">Copy</button>
        </div>
        <div class="share-links">
          <a id="share-twitter" target="_blank" rel="noopener" class="share-link share-twitter">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
            Post on X
          </a>
          <a id="share-linkedin" target="_blank" rel="noopener" class="share-link share-linkedin">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 01-2.063-2.065 2.064 2.064 0 112.063 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg>
            Share on LinkedIn
          </a>
        </div>
        <p class="share-hint">Anyone with this link can load your policy in the playground</p>
      </div>`;
    document.body.appendChild(modal);

    modal.addEventListener("click", (e) => {
      if (e.target === modal) modal.classList.add("hidden");
    });
    modal.querySelector(".shortcut-close").addEventListener("click", () => {
      modal.classList.add("hidden");
    });
    document.getElementById("share-copy-btn").addEventListener("click", () => {
      const input = document.getElementById("share-url-input");
      copyToClipboard(input.value, document.getElementById("share-copy-btn"));
    });
  }

  // Update dynamic content
  document.getElementById("share-url-input").value = url;
  const enc = encodeURIComponent;
  document.getElementById("share-twitter").href =
    `https://x.com/intent/tweet?text=${enc(text)}&url=${enc(url)}`;
  document.getElementById("share-linkedin").href =
    `https://www.linkedin.com/sharing/share-offsite/?url=${enc(url)}`;
  modal.classList.remove("hidden");
}

/* ---- Keyboard Shortcut Help ---- */
function buildShortcutOverlay() {
  const overlay = document.createElement("div");
  overlay.id = "shortcut-overlay";
  overlay.className = "shortcut-overlay hidden";
  overlay.innerHTML = `
    <div class="shortcut-modal">
      <div class="shortcut-header">
        <h3>Keyboard Shortcuts</h3>
        <button class="shortcut-close" aria-label="Close">&times;</button>
      </div>
      <div class="shortcut-list">
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>Enter</kbd><span>Evaluate custom action</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>Enter</kbd><span>Run all actions</span></div>
        <div class="shortcut-row"><kbd>1</kbd>-<kbd>9</kbd><span>Switch preset (by position)</span></div>
        <div class="shortcut-row"><kbd>?</kbd><span>Show this help</span></div>
        <div class="shortcut-row"><kbd>Esc</kbd><span>Close dialogs</span></div>
      </div>
      <p class="shortcut-hint">On macOS, use <kbd>Cmd</kbd> instead of <kbd>Ctrl</kbd></p>
    </div>`;
  document.body.appendChild(overlay);

  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) overlay.classList.add("hidden");
  });
  overlay.querySelector(".shortcut-close").addEventListener("click", () => {
    overlay.classList.add("hidden");
  });
}

function toggleShortcutHelp() {
  const overlay = document.getElementById("shortcut-overlay");
  if (overlay) overlay.classList.toggle("hidden");
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

  // Use case cards → select preset + scroll to editor
  document.querySelectorAll(".usecase-card").forEach((card) => {
    card.addEventListener("click", () => {
      const preset = card.dataset.preset;
      if (!POLICY_PRESETS[preset]) return;
      // Update preset button state
      document.querySelector(".preset-btn.active")?.classList.remove("active");
      const matchBtn = document.querySelector(`.preset-btn[data-preset="${preset}"]`);
      if (matchBtn) matchBtn.classList.add("active");
      editor.setValue(POLICY_PRESETS[preset]);
      updateActionButtons(preset);
      // Scroll to editor
      document.querySelector(".policy-panel")?.scrollIntoView({ behavior: "smooth", block: "start" });
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
    // Ignore when typing in inputs
    const tag = document.activeElement?.tagName;
    const isInput = tag === "INPUT" || tag === "TEXTAREA";

    // Ctrl/Cmd + Shift + Enter → run all (check first, before plain Enter)
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === "Enter") {
      e.preventDefault();
      document.getElementById("run-all").click();
      return;
    }
    // Ctrl/Cmd + Enter → run custom action (or run all as fallback)
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      const type = document.getElementById("custom-type").value.trim();
      if (type) {
        document.getElementById("run-custom").click();
      } else {
        document.getElementById("run-all").click();
      }
      return;
    }
    // ? → toggle keyboard shortcut help overlay
    if (e.key === "?" && !isInput) {
      e.preventDefault();
      toggleShortcutHelp();
      return;
    }
    // Escape → close shortcut help
    if (e.key === "Escape") {
      const overlay = document.getElementById("shortcut-overlay");
      if (overlay && !overlay.classList.contains("hidden")) {
        overlay.classList.add("hidden");
        return;
      }
    }
    // 1-9 → switch preset (when not in input)
    if (!isInput && e.key >= "1" && e.key <= "9" && !e.ctrlKey && !e.metaKey) {
      const presetBtns = document.querySelectorAll(".preset-btn:not(.preset-divider)");
      const idx = parseInt(e.key) - 1;
      if (idx < presetBtns.length) {
        presetBtns[idx].click();
      }
    }
  });

  // Build shortcut help overlay
  buildShortcutOverlay();

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

  document.getElementById("share-policy").addEventListener("click", () => {
    openShareModal();
  });

  // Export audit log — toggle dropdown
  document.getElementById("export-audit").addEventListener("click", (e) => {
    e.stopPropagation();
    if (auditEntries.length === 0) {
      showToast("No audit entries to export");
      return;
    }
    toggleExportMenu();
  });

  // Close dropdown on outside click
  document.addEventListener("click", () => {
    const menu = document.getElementById("export-menu");
    if (menu) menu.remove();
  });
}

/* ---- Export Menu ---- */
function toggleExportMenu() {
  let menu = document.getElementById("export-menu");
  if (menu) { menu.remove(); return; }

  const btn = document.getElementById("export-audit");
  const rect = btn.getBoundingClientRect();

  menu = document.createElement("div");
  menu.id = "export-menu";
  menu.className = "export-menu";
  menu.style.top = rect.bottom + 4 + "px";
  menu.style.right = window.innerWidth - rect.right + "px";
  menu.innerHTML = `
    <button class="export-option" data-format="json">Export as JSON</button>
    <button class="export-option" data-format="csv">Export as CSV</button>`;
  document.body.appendChild(menu);

  menu.addEventListener("click", (e) => {
    const format = e.target.dataset.format;
    if (format === "json") exportAuditJSON();
    if (format === "csv") exportAuditCSV();
    menu.remove();
  });
}

function downloadBlob(content, type, ext) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `aegis-audit-${new Date().toISOString().slice(0, 10)}.${ext}`;
  a.click();
  URL.revokeObjectURL(url);
}

function exportAuditJSON() {
  downloadBlob(JSON.stringify(auditEntries, null, 2), "application/json", "json");
}

function exportAuditCSV() {
  const headers = ["timestamp", "action_type", "target", "risk", "approval", "rule", "description"];
  const rows = auditEntries.map((e) =>
    headers.map((h) => {
      const v = e[h] ?? "";
      return typeof v === "string" && v.includes(",") ? `"${v}"` : v;
    }).join(",")
  );
  downloadBlob([headers.join(","), ...rows].join("\n"), "text/csv", "csv");
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
    if (tipInterval) clearInterval(tipInterval);
    setTimeout(() => {
      $overlay.classList.add("hidden");
      // Auto-run demo if no policy in URL
      if (!window.location.hash.startsWith("#policy=")) {
        autoDemo();
      }
      // Start guided tour for first-time visitors (after demo completes)
      setTimeout(startTour, 2000);
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
    const t0 = performance.now();
    const resultJson = await pyodide.runPythonAsync(`
evaluate_action(
  ${JSON.stringify(yaml)},
  ${JSON.stringify(action)}
)
`);
    const t1 = performance.now();
    const result = JSON.parse(resultJson);
    result.latency_ms = t1 - t0;

    if (result.error) {
      showToast(result.error);
      return;
    }

    renderResult(result);
    addAuditEntry(result);
    actionCount++;
    const counter = document.getElementById("action-counter");
    if (counter) counter.textContent = actionCount;
    updateStats(result);
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
  card.className = `result-card ${isAllowed ? "result-allowed" : "result-blocked"}`;
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
    showBlockedEffect(card);
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
}

/* ---- Blocked Effect (CSS-only particle burst) ---- */
function showBlockedEffect(card) {
  card.classList.add("blocked-effect");
  card.addEventListener(
    "animationend",
    () => card.classList.remove("blocked-effect"),
    { once: true }
  );
}

/* ---- Audit Log ---- */
/* ---- Stats Bar ---- */
function updateStats(result) {
  stats.total++;
  const approval = (result.approval || "").toLowerCase();
  if (approval === "auto") stats.auto++;
  else if (approval === "approve") stats.approve++;
  else if (approval === "block") stats.block++;
  if (result.latency_ms) stats.totalMs += result.latency_ms;

  const $t = document.getElementById("stat-total");
  const $a = document.getElementById("stat-auto");
  const $ap = document.getElementById("stat-approve");
  const $b = document.getElementById("stat-block");
  const $l = document.getElementById("stat-latency");
  if ($t) $t.textContent = stats.total;
  if ($a) $a.textContent = stats.auto;
  if ($ap) $ap.textContent = stats.approve;
  if ($b) $b.textContent = stats.block;
  if ($l && stats.total > 0) {
    $l.textContent = (stats.totalMs / stats.total).toFixed(1) + "ms";
  }
}

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
  updateAuditChart();
}

function updateAuditChart() {
  let chart = document.getElementById("audit-chart");
  if (!chart) {
    chart = document.createElement("div");
    chart.id = "audit-chart";
    chart.className = "audit-chart";
    $auditCount.parentNode.insertBefore(chart, $auditCount.nextSibling);
  }
  const total = auditEntries.length;
  if (total === 0) { chart.innerHTML = ""; return; }
  const auto = auditEntries.filter((e) => e.approval === "auto").length;
  const approve = auditEntries.filter((e) => e.approval === "approve").length;
  const block = total - auto - approve;
  chart.innerHTML = `
    <div class="chart-bar">
      <div class="chart-seg chart-auto" style="width:${(auto / total) * 100}%"></div>
      <div class="chart-seg chart-approve" style="width:${(approve / total) * 100}%"></div>
      <div class="chart-seg chart-block" style="width:${(block / total) * 100}%"></div>
    </div>
    <div class="chart-legend">
      <span class="legend-auto">${auto} auto</span>
      <span class="legend-approve">${approve} approve</span>
      <span class="legend-block">${block} block</span>
    </div>`;
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
