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
function typewriterEffect($el, text, speed = 25) {
  $el.textContent = "";
  let i = 0;
  const timer = setInterval(() => {
    if (i < text.length) {
      $el.textContent += text[i];
      i++;
    } else {
      clearInterval(timer);
    }
  }, speed);
  return timer;
}

function rotateTips() {
  const $tip = document.getElementById("loading-tip");
  if (!$tip) return;
  let idx = 0;
  let typeTimer = null;
  tipInterval = setInterval(() => {
    idx = (idx + 1) % LOADING_TIPS.length;
    $tip.style.opacity = 0;
    clearInterval(typeTimer);
    setTimeout(() => {
      $tip.style.opacity = 1;
      typeTimer = typewriterEffect($tip, LOADING_TIPS[idx]);
    }, 300);
  }, 4000);
}

/* ---- DOM refs ---- */
const $overlay = document.getElementById("loading-overlay");
const $status = document.getElementById("loading-status");
const $progress = document.getElementById("progress-fill");
const $result = document.getElementById("result-content");
const $audit = document.getElementById("audit-content");
const $auditCount = document.getElementById("audit-count");
let _presetBtns = null; // cached after DOMContentLoaded
function _getPresetBtns() {
  return _presetBtns || (_presetBtns = [...document.querySelectorAll(".preset-btn:not(.preset-divider)")]);
}

/* ---- Init ---- */
document.addEventListener("DOMContentLoaded", async () => {
  initEditor();
  loadPolicyFromURL();
  window.addEventListener("hashchange", loadPolicyFromURL);
  setupPolicySave();
  bindEvents();
  rotateTips();
  initLazyReveal();
  initMobileFab();
  initSwipePresets();
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

/* ---- Command Palette ---- */
function toggleCommandPalette() {
  let palette = document.getElementById("command-palette");
  if (palette && !palette.classList.contains("hidden")) {
    palette.classList.add("hidden");
    return;
  }
  if (!palette) {
    palette = document.createElement("div");
    palette.id = "command-palette";
    palette.className = "shortcut-overlay";
    palette.innerHTML = `
      <div class="command-palette-inner">
        <input type="text" class="command-input" placeholder="Type a command or preset name..." autofocus>
        <div class="command-list"></div>
      </div>`;
    document.body.appendChild(palette);
    palette.addEventListener("click", (e) => {
      if (e.target === palette) palette.classList.add("hidden");
    });
    const input = palette.querySelector(".command-input");
    input.addEventListener("input", () => renderCommands(input, input.value));
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        const first = palette.querySelector(".command-item");
        if (first) first.click();
      }
    });
  }
  palette.classList.remove("hidden");
  const input = palette.querySelector(".command-input");
  input.value = "";
  input.focus();
  renderCommands(input, "");
}

let _commandItems = null;
function getCommandItems() {
  if (_commandItems) return _commandItems;
  const items = [
    { label: "Run All Actions", icon: "\u25B6", action: () => document.getElementById("run-all")?.click() },
    { label: "Toggle Theme", icon: "\uD83C\uDFA8", action: () => toggleTheme() },
    { label: "Copy Policy", icon: "\uD83D\uDCCB", action: () => { copyToClipboard(editor.getValue(), document.getElementById("copy-policy")); showToast("Copied!"); } },
    { label: "Export Audit JSON", icon: "\uD83D\uDCC4", action: () => exportAuditJSON() },
    { label: "Export Audit CSV", icon: "\uD83D\uDCC4", action: () => exportAuditCSV() },
    { label: "Keyboard Shortcuts", icon: "\u2328\uFE0F", action: () => toggleShortcutHelp() },
    { label: "Clear Results", icon: "\uD83D\uDDD1\uFE0F", action: () => document.getElementById("clear-result")?.click() },
    { label: "Share Policy", icon: "\uD83D\uDD17", action: () => openShareModal() },
  ];
  _getPresetBtns().forEach((btn) => {
    items.push({ label: `Preset: ${btn.textContent.trim()}`, icon: "\uD83D\uDCD1", action: () => btn.click() });
  });
  _commandItems = items;
  return items;
}

let _commandListDelegated = false;
let _lastFilteredItems = [];
function renderCommands(input, query) {
  const list = document.querySelector(".command-list");
  const items = getCommandItems().filter((i) =>
    !query || i.label.toLowerCase().includes(query.toLowerCase())
  );
  _lastFilteredItems = items;
  list.innerHTML = items.slice(0, 12).map((i, idx) =>
    `<button class="command-item" data-idx="${idx}">${i.icon} ${i.label}</button>`
  ).join("");
  // Delegate once instead of per-item listeners on every render
  if (!_commandListDelegated) {
    _commandListDelegated = true;
    list.addEventListener("click", (e) => {
      const btn = e.target.closest(".command-item");
      if (!btn) return;
      const idx = parseInt(btn.dataset.idx);
      _lastFilteredItems[idx]?.action();
      document.getElementById("command-palette")?.classList.add("hidden");
    });
  }
}

/* ---- Mobile FAB ---- */
function initMobileFab() {
  const fab = document.getElementById("mobile-fab");
  const menu = document.getElementById("mobile-fab-menu");
  if (!fab || !menu) return;

  fab.addEventListener("click", () => menu.classList.toggle("hidden"));

  menu.addEventListener("click", (e) => {
    const action = e.target.dataset.fab;
    if (!action) return;
    menu.classList.add("hidden");
    if (action === "evaluate") document.getElementById("run-all")?.click();
    else if (action === "theme" && typeof toggleTheme === "function") toggleTheme();
    else if (action === "shortcuts" && typeof toggleShortcutHelp === "function") toggleShortcutHelp();
    else if (action === "top") window.scrollTo({ top: 0, behavior: "smooth" });
  });

  // Auto-hide FAB menu on scroll + scroll-to-top button
  const scrollTopBtn = document.getElementById("scroll-top");
  let scrollTimer;
  window.addEventListener("scroll", () => {
    clearTimeout(scrollTimer);
    scrollTimer = setTimeout(() => menu.classList.add("hidden"), 200);
    if (scrollTopBtn) {
      scrollTopBtn.classList.toggle("visible", window.scrollY > 500);
    }
  }, { passive: true });

  if (scrollTopBtn) {
    scrollTopBtn.addEventListener("click", () => {
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }
}

/* ---- Touch swipe to cycle presets on mobile ---- */
function initSwipePresets() {
  const editor = document.querySelector(".CodeMirror");
  if (!editor || !("ontouchstart" in window)) return;

  let startX = 0;
  let startY = 0;
  editor.addEventListener("touchstart", (e) => {
    startX = e.touches[0].clientX;
    startY = e.touches[0].clientY;
  }, { passive: true });

  editor.addEventListener("touchend", (e) => {
    const dx = e.changedTouches[0].clientX - startX;
    const dy = e.changedTouches[0].clientY - startY;
    if (Math.abs(dx) < 60 || Math.abs(dy) > Math.abs(dx)) return; // not a horizontal swipe

    const btns = _getPresetBtns();
    const activeIdx = btns.findIndex((b) => b.classList.contains("active"));

    if (dx < 0 && activeIdx < btns.length - 1) {
      btns[activeIdx + 1].click(); // swipe left → next
    } else if (dx > 0 && activeIdx > 0) {
      btns[activeIdx - 1].click(); // swipe right → prev
    }
  }, { passive: true });
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

  // Trigger arch-flow and decision-matrix stagger animations on scroll
  const scrollTargets = document.querySelectorAll(".arch-flow, .decision-matrix");
  if (scrollTargets.length) {
    const scrollObs = new IntersectionObserver((entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) {
          e.target.classList.add("animate-flow");
          scrollObs.unobserve(e.target);
        }
      });
    }, { threshold: 0.3 });
    scrollTargets.forEach((t) => scrollObs.observe(t));
  }
}

/* ---- CodeMirror Setup ---- */
const YAML_HINTS = {
  version: "Policy version — use \"1\"",
  rules: "List of governance rules, evaluated top to bottom",
  name: "Unique rule name for audit trail",
  match: "Conditions: type, target (glob patterns supported)",
  risk_level: "Risk classification: low | medium | high | critical",
  approval: "Decision: auto | approve | block",
  conditions: "Extra match conditions (time_after, time_before, max_params)",
  description: "Human-readable rule explanation",
  type: "Action type pattern (supports * wildcard)",
  target: "Action target pattern (supports * wildcard)",
};

function initEditor() {
  editor = CodeMirror.fromTextArea(document.getElementById("policy-editor"), {
    mode: "yaml",
    theme: "dracula",
    lineNumbers: true,
    tabSize: 2,
    indentWithTabs: false,
    lineWrapping: true,
    matchBrackets: true,
    styleActiveLine: true,
    viewportMargin: 50,
    extraKeys: {
      Tab: (cm) => cm.execCommand("indentMore"),
      "Shift-Tab": (cm) => cm.execCommand("indentLess"),
    },
  });
  editor.setValue(POLICY_PRESETS.default);
  initTheme();
  setupThemeLongPress();

  // Show field hints on cursor activity (cached DOM ref for hot path)
  const $hint = document.getElementById("editor-hint");
  editor.on("cursorActivity", () => {
    if (!$hint || $hint.dataset.disabled === "true") return;
    const line = editor.getLine(editor.getCursor().line) || "";
    const keyMatch = line.match(/^\s*(\w[\w_]*):/);
    const hint = keyMatch && YAML_HINTS[keyMatch[1]];
    if (hint) {
      $hint.textContent = hint;
      $hint.style.display = "";
    } else {
      $hint.style.display = "none";
    }
  });
}

/* ---- URL State (share policies via URL hash) ---- */
function loadPolicyFromURL() {
  const hash = window.location.hash;
  if (hash && hash.startsWith("#policy=")) {
    try {
      const encoded = hash.slice("#policy=".length);
      if (encoded.length > 100000) throw new Error("Policy too large");
      const yaml = decodeURIComponent(atob(encoded));
      if (yaml.length > 200000) throw new Error("Decoded policy too large");
      editor.setValue(yaml);
      // Deactivate all preset buttons
      _getPresetBtns().forEach((b) => b.classList.remove("active"));
      return;
    } catch {
      // Ignore invalid hash
    }
  }

  // Restore last edited policy from localStorage
  const saved = localStorage.getItem("aegis-last-policy");
  if (saved && saved !== POLICY_PRESETS.default) {
    editor.setValue(saved);
    _getPresetBtns().forEach((b) => b.classList.remove("active"));
  }
}

// Auto-save policy to localStorage on change (debounced)
let saveTimer = null;
let _$ruleCount = null;
function updateRuleCount() {
  const rc = _$ruleCount || (_$ruleCount = document.getElementById("rule-count"));
  if (!rc) return;
  const yaml = editor.getValue();
  const count = (yaml.match(/- name:/g) || []).length;
  const lines = editor.lineCount();
  // Complexity score: rules × avg conditions per rule
  const matchCount = (yaml.match(/match:/g) || []).length;
  const hasWildcard = /type:\s*["']?\*["']?/.test(yaml);
  const hasRiskLevels = new Set((yaml.match(/risk_level:\s*(\w+)/g) || []).map((m) => m.split(":")[1]?.trim())).size;
  const complexity = Math.min(count * (matchCount + 1) + hasRiskLevels * 2 + (hasWildcard ? 5 : 0), 99);
  const label = complexity <= 10 ? "simple" : complexity <= 30 ? "moderate" : "complex";
  rc.textContent = `${count} rule${count !== 1 ? "s" : ""} · ${lines} lines · ${label}`;
  rc.title = `Complexity score: ${complexity}/99 (${count} rules, ${matchCount} match patterns, ${hasRiskLevels} risk levels)`;
}

let _ruleCountTimer = null;
function setupPolicySave() {
  editor.on("change", () => {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      try { localStorage.setItem("aegis-last-policy", editor.getValue()); }
      catch { /* QuotaExceededError — silently skip save */ }
    }, 1000);
    // Debounce rule count to avoid 4 regex scans on every keystroke
    clearTimeout(_ruleCountTimer);
    _ruleCountTimer = setTimeout(updateRuleCount, 300);
  });
  updateRuleCount(); // initial count
}

/* ---- YAML Comment Toggle ---- */
function toggleYamlComment() {
  const from = editor.getCursor("from");
  const to = editor.getCursor("to");
  const startLine = from.line;
  const endLine = to.line;

  // Check if all selected lines are commented
  let allCommented = true;
  for (let i = startLine; i <= endLine; i++) {
    const text = editor.getLine(i);
    if (text.trim() && !text.match(/^\s*#/)) {
      allCommented = false;
      break;
    }
  }

  editor.operation(() => {
    for (let i = startLine; i <= endLine; i++) {
      const text = editor.getLine(i);
      if (allCommented) {
        // Uncomment: remove first # (and optional space after)
        const newText = text.replace(/^(\s*)# ?/, "$1");
        editor.replaceRange(newText, { line: i, ch: 0 }, { line: i, ch: text.length });
      } else {
        // Comment: add # after leading whitespace
        if (text.trim()) {
          const indent = text.match(/^(\s*)/)[1];
          const rest = text.slice(indent.length);
          editor.replaceRange(indent + "# " + rest, { line: i, ch: 0 }, { line: i, ch: text.length });
        }
      }
    }
  });
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
        <div style="display:flex;gap:6px;margin-top:8px">
          <button id="share-embed-btn" class="action-btn action-low" style="flex:1">Copy Embed</button>
          <button id="share-docker-btn" class="action-btn action-low" style="flex:1">Copy Docker</button>
        </div>
        <p class="share-hint">Anyone with this link can load your policy in the playground</p>
      </div>`;
    document.body.appendChild(modal);

    const urlInput = modal.querySelector("#share-url-input");
    const copyBtn = modal.querySelector("#share-copy-btn");
    const embedBtn = modal.querySelector("#share-embed-btn");
    const dockerBtn = modal.querySelector("#share-docker-btn");
    const twitterLink = modal.querySelector("#share-twitter");
    const linkedinLink = modal.querySelector("#share-linkedin");

    modal.addEventListener("click", (e) => {
      if (e.target === modal) modal.classList.add("hidden");
    });
    modal.querySelector(".shortcut-close").addEventListener("click", () => {
      modal.classList.add("hidden");
    });
    copyBtn.addEventListener("click", () => {
      copyToClipboard(urlInput.value, copyBtn);
    });
    embedBtn.addEventListener("click", () => {
      const iframe = `<iframe src="${_esc(urlInput.value)}" width="100%" height="600" frameborder="0" title="Aegis Playground"></iframe>`;
      copyToClipboard(iframe, embedBtn);
      showToast("Embed code copied!");
    });
    dockerBtn.addEventListener("click", () => {
      const cmd = `echo '${editor.getValue().replace(/'/g, "'\\''")}' > policy.yaml && docker run -d -p 8000:8000 -v $(pwd)/policy.yaml:/app/policy.yaml ghcr.io/acacian/aegis:latest`;
      copyToClipboard(cmd, dockerBtn);
      showToast("Docker command copied!");
    });

    // Store refs on modal for reuse
    modal._urlInput = urlInput;
    modal._twitterLink = twitterLink;
    modal._linkedinLink = linkedinLink;
  }

  // Update dynamic content
  const enc = encodeURIComponent;
  modal._urlInput.value = url;
  modal._twitterLink.href =
    `https://x.com/intent/tweet?text=${enc(text)}&url=${enc(url)}`;
  modal._linkedinLink.href =
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
        <div class="shortcut-group">Evaluation</div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>Enter</kbd><span>Evaluate custom action</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>Enter</kbd><span>Run all actions</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>R</kbd><span>Fresh re-evaluate all</span></div>
        <div class="shortcut-row"><kbd>r</kbd><span>Re-run last action</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>K</kbd><span>Focus custom action input</span></div>
        <div class="shortcut-group">Editor</div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>N</kbd><span>New blank policy</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>H</kbd><span>Toggle YAML hints</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>S</kbd><span>Copy policy to clipboard</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>/</kbd><span>Toggle YAML comment</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>G</kbd> / <kbd>Ctrl</kbd>+<kbd>L</kbd><span>Go to line</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>D</kbd><span>Duplicate line</span></div>
        <div class="shortcut-group">Navigation</div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>P</kbd><span>Command palette</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>[</kbd> / <kbd>]</kbd><span>Previous / next preset</span></div>
        <div class="shortcut-row"><kbd>0</kbd>-<kbd>9</kbd><span>Switch preset (by position)</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>J</kbd><span>Jump to latest result</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>F</kbd><span>Focus audit search</span></div>
        <div class="shortcut-group">Export &amp; Data</div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>E</kbd><span>Export audit log (JSON)</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>S</kbd><span>Save snapshot (JSON)</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>I</kbd><span>Import policy from clipboard</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>C</kbd><span>Copy latest result</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>X</kbd><span>Full reset</span></div>
        <div class="shortcut-group">View</div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>D</kbd><span>Toggle theme</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>B</kbd><span>Toggle audit panel</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>F</kbd><span>Editor focus mode</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd><span>Print audit log</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>,</kbd><span>Jump to How It Works</span></div>
        <div class="shortcut-row"><kbd>?</kbd><span>Show this help</span></div>
        <div class="shortcut-row"><kbd>Esc</kbd><span>Close dialogs / clear results</span></div>
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
function getSystemTheme() {
  if (window.matchMedia("(prefers-contrast: more)").matches) return "high-contrast";
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

const THEMES = ["dark", "light", "high-contrast"];
let _$themeToggle = null;

const THEME_META = {
  dark: { color: "#0d1117", icon: "\u{1F319}", label: "Dark" },
  light: { color: "#ffffff", icon: "\u2600\uFE0F", label: "Light" },
  "high-contrast": { color: "#000000", icon: "\u{1F506}", label: "High Contrast" },
};

function applyTheme(theme) {
  document.documentElement.classList.add("theme-transition");
  document.documentElement.removeAttribute("data-theme");
  if (theme === "light") {
    document.documentElement.setAttribute("data-theme", "light");
    if (editor) editor.setOption("theme", "default");
  } else if (theme === "high-contrast") {
    document.documentElement.setAttribute("data-theme", "high-contrast");
    if (editor) editor.setOption("theme", "dracula");
  } else {
    if (editor) editor.setOption("theme", "dracula");
  }
  setTimeout(() => document.documentElement.classList.remove("theme-transition"), 400);

  // Update all meta theme-color tags (dark + light variants)
  if (THEME_META[theme]) {
    document.querySelectorAll('meta[name="theme-color"]').forEach((m) => {
      m.content = THEME_META[theme].color;
    });
  }

  // Update toggle button label and show correct icon
  const btn = _$themeToggle || (_$themeToggle = document.getElementById("theme-toggle"));
  if (btn && THEME_META[theme]) {
    btn.setAttribute("aria-label", `Current: ${THEME_META[theme].label}. Click to switch.`);
    btn.title = `Theme: ${THEME_META[theme].label}`;
    // Show only the active theme icon
    btn.querySelectorAll("[class^='theme-icon-']").forEach((el) => el.style.display = "none");
    const iconClass = theme === "high-contrast" ? "theme-icon-hc" : `theme-icon-${theme}`;
    const activeIcon = btn.querySelector(`.${iconClass}`);
    if (activeIcon) activeIcon.style.display = "";
  }
}

function getTimeBasedTheme() {
  const hour = new Date().getHours();
  // 7am–7pm: light, otherwise dark
  return (hour >= 7 && hour < 19) ? "light" : "dark";
}

function initTheme() {
  const saved = localStorage.getItem("aegis-theme");
  const theme = saved || getSystemTheme();
  applyTheme(theme);
  _updateNextThemeHint(theme);

  window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", (e) => {
    if (!localStorage.getItem("aegis-theme")) {
      applyTheme(e.matches ? "light" : "dark");
    }
  });

  // Auto-switch theme at dawn/dusk if user hasn't manually set one
  if (!saved) {
    const checkTime = () => {
      if (localStorage.getItem("aegis-theme")) return; // user chose manually
      const timeTheme = getTimeBasedTheme();
      const current = document.documentElement.getAttribute("data-theme") || "dark";
      if (timeTheme !== current) applyTheme(timeTheme);
    };
    setInterval(checkTime, 60000); // check every minute
  }
}

function _updateNextThemeHint(current) {
  const btn = _$themeToggle || (_$themeToggle = document.getElementById("theme-toggle"));
  if (!btn) return;
  const idx = THEMES.indexOf(current);
  const next = THEMES[(idx + 1) % THEMES.length];
  const hint = THEME_META[next];
  if (hint) btn.dataset.nextTheme = `${hint.icon} ${hint.label}`;
}

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  const idx = THEMES.indexOf(current);
  const next = THEMES[(idx + 1) % THEMES.length];
  try { localStorage.setItem("aegis-theme", next); } catch { /* quota */ }

  // Flash overlay for smooth perceived transition
  const flash = document.createElement("div");
  flash.className = "theme-flash";
  flash.style.background = next === "light" ? "rgba(255,255,255,0.15)" : "rgba(0,0,0,0.15)";
  document.body.appendChild(flash);
  requestAnimationFrame(() => {
    flash.style.opacity = "0";
    flash.addEventListener("transitionend", () => flash.remove());
  });

  applyTheme(next);
  _updateNextThemeHint(next);
  showToast(`${THEME_META[next]?.icon || ""} Theme: ${THEME_META[next]?.label || next}`);
}

function resetThemeToAuto() {
  localStorage.removeItem("aegis-theme");
  const autoTheme = getSystemTheme();
  applyTheme(autoTheme);
  showToast(`Theme reset to auto (${THEME_META[autoTheme]?.label || autoTheme})`);
}

// Long-press on theme toggle → reset to auto
function setupThemeLongPress() {
  const btn = _$themeToggle || (_$themeToggle = document.getElementById("theme-toggle"));
  if (!btn) return;
  let pressTimer = null;
  btn.addEventListener("pointerdown", () => {
    pressTimer = setTimeout(() => {
      pressTimer = null;
      resetThemeToAuto();
    }, 800);
  });
  btn.addEventListener("pointerup", () => { if (pressTimer) clearTimeout(pressTimer); });
  btn.addEventListener("pointerleave", () => { if (pressTimer) clearTimeout(pressTimer); });
}

/* ---- Event Binding ---- */
function bindEvents() {
  // Theme toggle
  (_$themeToggle || (_$themeToggle = document.getElementById("theme-toggle"))).addEventListener("click", (ev) => {
    if (ev.isTrusted) showShortcutHint("theme", "Ctrl+D to toggle theme");
    toggleTheme();
  });

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

  // Action buttons — parse JSON once, cache on element
  document.querySelectorAll(".action-btn").forEach((btn) => {
    btn._action = JSON.parse(btn.dataset.action);
    btn.addEventListener("click", () => evaluateAction(btn._action));
  });

  // Custom action
  document.getElementById("run-custom").addEventListener("click", (ev) => {
    if (ev.isTrusted) showShortcutHint("run-custom", "Ctrl+Enter to evaluate");
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
  document.getElementById("run-all").addEventListener("click", (ev) => {
    if (ev.isTrusted) showShortcutHint("run-all", "Ctrl+Shift+Enter to run all");
    runAllActions();
  });

  // Delegated copy handler for result cards (single listener instead of 11 per card)
  $result.addEventListener("click", (e) => {
    const btn = e.target.closest(".copy-code-btn");
    if (!btn) return;
    const card = btn.closest(".result-card");
    if (!card || !card._resultData) return;
    const code = generateCode(btn.dataset.fmt, card._resultData);
    copyToClipboard(code, btn);
  });

  function goToLine() {
    const lineCount = editor.lineCount();
    const line = prompt(`Go to line (1-${lineCount}):`);
    if (line) {
      const n = Math.max(0, Math.min(parseInt(line) - 1, lineCount - 1));
      editor.setCursor(n, 0);
      editor.focus();
      editor.scrollIntoView({ line: n, ch: 0 }, 100);
    }
  }

  // Keyboard shortcuts
  document.addEventListener("keydown", (e) => {
    // Ignore when typing in inputs
    const tag = document.activeElement?.tagName;
    const isInput = tag === "INPUT" || tag === "TEXTAREA";

    // Ctrl/Cmd + Shift + I → import snapshot from clipboard
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === "I" || e.key === "i")) {
      e.preventDefault();
      (async () => {
        try {
          const text = await navigator.clipboard.readText();
          const snap = JSON.parse(text);
          if (snap.policy) {
            editor.setValue(snap.policy);
            showToast("Imported policy from clipboard");
          } else {
            showToast("Clipboard JSON has no 'policy' field");
          }
        } catch {
          showToast("Could not import — paste valid JSON");
        }
      })();
      return;
    }
    // Ctrl/Cmd + Shift + S → save snapshot (policy + audit as JSON)
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === "S" || e.key === "s")) {
      e.preventDefault();
      const snapshot = {
        saved_at: new Date().toISOString(),
        policy: editor.getValue(),
        stats: { ...stats },
        audit_entries: auditEntries,
      };
      downloadBlob(JSON.stringify(snapshot, null, 2), "application/json", "json");
      showToast("Snapshot saved");
      return;
    }
    // Ctrl/Cmd + Shift + X → full reset: clear results, audit, and stats
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === "X" || e.key === "x")) {
      e.preventDefault();
      // clear-audit handler already resets stats, auditEntries, actionCount, and display
      document.getElementById("clear-result")?.click();
      document.getElementById("clear-audit")?.click();
      showToast("Full reset: results, audit, and stats cleared");
      return;
    }
    // Ctrl/Cmd + G → go to line in editor
    if ((e.ctrlKey || e.metaKey) && (e.key === "g" || e.key === "G") && !e.shiftKey) {
      e.preventDefault();
      goToLine();
      return;
    }
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
    // Ctrl/Cmd + P → open command palette
    if ((e.ctrlKey || e.metaKey) && e.key === "p") {
      e.preventDefault();
      toggleCommandPalette();
      return;
    }
    // ? → toggle keyboard shortcut help overlay
    if (e.key === "?" && !isInput) {
      e.preventDefault();
      toggleShortcutHelp();
      return;
    }
    // Ctrl/Cmd + S → copy policy to clipboard (prevent browser save dialog)
    if ((e.ctrlKey || e.metaKey) && e.key === "s") {
      e.preventDefault();
      copyToClipboard(editor.getValue(), document.getElementById("copy-policy"));
      showToast("Policy copied to clipboard");
      return;
    }
    // Ctrl/Cmd + / → toggle YAML comment on selected lines
    if ((e.ctrlKey || e.metaKey) && e.key === "/") {
      e.preventDefault();
      toggleYamlComment();
      return;
    }
    // Escape → close overlays, then clear results
    if (e.key === "Escape") {
      const cmdPalette = document.getElementById("command-palette");
      if (cmdPalette && !cmdPalette.classList.contains("hidden")) {
        cmdPalette.classList.add("hidden");
        return;
      }
      const shortcutOv = document.getElementById("shortcut-overlay");
      if (shortcutOv && !shortcutOv.classList.contains("hidden")) {
        shortcutOv.classList.add("hidden");
        return;
      }
      const shareOv = document.getElementById("share-modal");
      if (shareOv && !shareOv.classList.contains("hidden")) {
        shareOv.classList.add("hidden");
        return;
      }
      const exportMenu = document.getElementById("export-menu");
      if (exportMenu) { exportMenu.remove(); return; }
      // If nothing open, clear results
      if (!isInput) {
        document.getElementById("clear-result").click();
        return;
      }
    }
    // Ctrl/Cmd + E → export audit log as JSON
    if ((e.ctrlKey || e.metaKey) && e.key === "e") {
      e.preventDefault();
      if (typeof exportAuditJSON === "function") exportAuditJSON();
      return;
    }
    // Ctrl/Cmd + D → toggle theme
    if ((e.ctrlKey || e.metaKey) && e.key === "d") {
      e.preventDefault();
      if (typeof toggleTheme === "function") toggleTheme();
      return;
    }
    // Ctrl/Cmd + B → toggle audit panel visibility
    if ((e.ctrlKey || e.metaKey) && e.key === "b" && !e.shiftKey) {
      e.preventDefault();
      const auditPanel = document.querySelector(".bottom-section .panel:last-child");
      if (auditPanel) {
        const isHidden = auditPanel.style.display === "none";
        auditPanel.style.display = isHidden ? "" : "none";
        showToast(isHidden ? "Audit panel shown" : "Audit panel hidden");
      }
      return;
    }
    // Ctrl/Cmd + L → go to line in editor (alternate binding)
    if ((e.ctrlKey || e.metaKey) && e.key === "l" && !e.shiftKey) {
      e.preventDefault();
      goToLine();
      return;
    }
    // Ctrl/Cmd + K → focus custom action input (command palette style)
    if ((e.ctrlKey || e.metaKey) && e.key === "k") {
      e.preventDefault();
      const customInput = document.getElementById("custom-type");
      if (customInput) { customInput.focus(); customInput.select(); }
      return;
    }
    // Ctrl/Cmd + J → scroll to latest result card
    if ((e.ctrlKey || e.metaKey) && e.key === "j" && !e.shiftKey) {
      e.preventDefault();
      const firstCard = $result.querySelector(".result-card");
      if (firstCard) {
        firstCard.scrollIntoView({ behavior: "smooth", block: "center" });
        firstCard.classList.add("flash-auto");
        firstCard.addEventListener("animationend", () => firstCard.classList.remove("flash-auto"), { once: true });
      }
      return;
    }
    // Ctrl/Cmd + F → focus audit search filter
    if ((e.ctrlKey || e.metaKey) && e.key === "f" && !e.shiftKey) {
      const searchEl = _$auditSearch || (_$auditSearch = document.getElementById("audit-search"));
      if (searchEl) {
        e.preventDefault();
        searchEl.focus();
        searchEl.select();
        return;
      }
    }
    // Ctrl/Cmd + Shift + D → duplicate current line in editor
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === "D" || e.key === "d")) {
      e.preventDefault();
      const cursor = editor.getCursor();
      const line = editor.getLine(cursor.line);
      editor.replaceRange("\n" + line, { line: cursor.line, ch: line.length });
      editor.setCursor(cursor.line + 1, cursor.ch);
      return;
    }
    // Ctrl/Cmd + [ / ] → navigate presets back/forward
    if ((e.ctrlKey || e.metaKey) && (e.key === "[" || e.key === "]")) {
      e.preventDefault();
      const btns = _getPresetBtns();
      const activeIdx = btns.findIndex((b) => b.classList.contains("active"));
      const dir = e.key === "]" ? 1 : -1;
      const nextIdx = (activeIdx + dir + btns.length) % btns.length;
      btns[nextIdx].click();
      return;
    }
    // Ctrl/Cmd + Shift + C → copy latest result as one-liner
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === "C" || e.key === "c")) {
      const latestCard = $result.querySelector(".result-card");
      if (latestCard && latestCard._resultData) {
        e.preventDefault();
        const code = generateCode("oneliner", latestCard._resultData);
        copyToClipboard(code, latestCard);
        showToast("Copied latest result");
      }
      return;
    }
    // Ctrl/Cmd + H → toggle YAML hints in editor
    if ((e.ctrlKey || e.metaKey) && e.key === "h" && !e.shiftKey) {
      e.preventDefault();
      const hintEl = document.getElementById("editor-hint");
      if (hintEl) {
        const hidden = hintEl.dataset.disabled === "true";
        hintEl.dataset.disabled = hidden ? "" : "true";
        hintEl.style.display = hidden ? "" : "none";
        showToast(hidden ? "YAML hints enabled" : "YAML hints hidden");
      }
      return;
    }
    // Ctrl/Cmd + Shift + F → toggle editor focus mode (expand editor, hide other panels)
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === "F" || e.key === "f")) {
      e.preventDefault();
      document.body.classList.toggle("editor-focus-mode");
      showToast(document.body.classList.contains("editor-focus-mode") ? "Focus mode ON" : "Focus mode OFF");
      editor.refresh();
      return;
    }
    // Ctrl/Cmd + Shift + P → print audit log
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === "P" || e.key === "p")) {
      e.preventDefault();
      if (typeof printAuditLog === "function") printAuditLog();
      return;
    }
    // Ctrl/Cmd + , → scroll to and flash the how-it-works section (settings-like discoverability)
    if ((e.ctrlKey || e.metaKey) && e.key === ",") {
      e.preventDefault();
      const hiw = document.querySelector(".how-it-works");
      if (hiw) {
        hiw.scrollIntoView({ behavior: "smooth", block: "start" });
        hiw.style.outline = "2px solid var(--accent)";
        setTimeout(() => { hiw.style.outline = ""; }, 1500);
      }
      return;
    }
    // Ctrl/Cmd + N → new blank policy
    if ((e.ctrlKey || e.metaKey) && e.key === "n" && !e.shiftKey) {
      e.preventDefault();
      editor.setValue("policies:\n  - name: my_policy\n    rules:\n      - action_type: \"*\"\n        approval: auto\n        risk_level: low\n");
      editor.setCursor(0, 0);
      editor.focus();
      showToast("New blank policy created");
      return;
    }
    // Ctrl/Cmd + Shift + R → re-evaluate all with stats reset
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === "R" || e.key === "r")) {
      e.preventDefault();
      // clear-audit handler resets stats, auditEntries, actionCount, and display
      document.getElementById("clear-result")?.click();
      document.getElementById("clear-audit")?.click();
      setTimeout(() => document.getElementById("run-all")?.click(), 100);
      showToast("Fresh evaluation started");
      return;
    }
    // r → re-run last evaluated action (when not in input)
    if (!isInput && e.key === "r" && !e.ctrlKey && !e.metaKey) {
      const latestCard = $result.querySelector(".result-card");
      if (latestCard && latestCard._resultData) {
        evaluateAction({
          action_type: latestCard._resultData.action_type,
          target: latestCard._resultData.target,
          params: latestCard._resultData.params || {},
          description: latestCard._resultData.description || "",
        });
      }
      return;
    }
    // 1-9, 0 → switch preset (when not in input)
    if (!isInput && e.key >= "0" && e.key <= "9" && !e.ctrlKey && !e.metaKey) {
      const btns = _getPresetBtns();
      const idx = e.key === "0" ? 9 : parseInt(e.key) - 1;
      if (idx < btns.length) {
        btns[idx].click();
      }
    }
  });

  // Quickstart code tabs
  document.querySelectorAll(".code-tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelector(".code-tab.active")?.classList.remove("active");
      document.querySelector(".code-panel.active")?.classList.remove("active");
      tab.classList.add("active");
      document.querySelector(`.code-panel[data-panel="${tab.dataset.tab}"]`)?.classList.add("active");
    });
  });
  const codeCopyBtn = document.querySelector(".code-copy-btn");
  if (codeCopyBtn) {
    codeCopyBtn.addEventListener("click", (e) => {
      const active = document.querySelector(".code-panel.active code");
      const activeTab = document.querySelector(".code-tab.active");
      if (active) {
        copyToClipboard(active.textContent, e.target);
        const tabName = activeTab?.textContent || "code";
        showToast(`Copied ${tabName} snippet`);
      }
    });
  }

  // "Try it" button — scrolls to editor and runs a demo action
  const tryItBtn = document.getElementById("try-it-btn");
  if (tryItBtn) {
    tryItBtn.addEventListener("click", () => {
      document.querySelector("main")?.scrollIntoView({ behavior: "smooth" });
      // Load default preset and auto-run after scroll
      setTimeout(() => {
        const firstPreset = document.querySelector(".preset-btn");
        if (firstPreset) firstPreset.click();
        setTimeout(() => document.getElementById("run-all")?.click(), 400);
      }, 600);
    });
  }

  // Build shortcut help overlay
  buildShortcutOverlay();

  // Clear buttons
  document.getElementById("copy-all-results").addEventListener("click", (e) => {
    if (auditEntries.length === 0) {
      showToast("No results to copy");
      return;
    }
    const entries = getFilteredEntries();
    // Rich Markdown report with stats + entries table
    const avgMs = stats.total > 0 ? (stats.totalMs / stats.total).toFixed(1) : "0";
    const filter = getActiveFilter();
    const md = [
      "# Aegis Evaluation Report",
      `Generated: ${new Date().toISOString()}`,
      "",
      "## Summary",
      `| Total | Auto | Approve | Block | Avg Latency |`,
      `|-------|------|---------|-------|-------------|`,
      `| ${stats.total} | ${stats.auto} | ${stats.approve} | ${stats.block} | ${avgMs}ms |`,
      "",
      filter !== "all" ? `> Filter: **${filter}** (${entries.length} of ${auditEntries.length} entries)\n` : "",
      "## Evaluations",
      `| Time | Action | Risk | Decision | Rule |`,
      `|------|--------|------|----------|------|`,
      ...entries.map((e) => `| ${e.time || ""} | ${e.type || ""} | ${e.risk || ""} | ${e.decision || ""} | ${e.rule || ""} |`),
    ].join("\n");
    copyToClipboard(md, e.target);
    showToast(`Copied ${entries.length} results as Markdown`);
  });

  document.getElementById("clear-result").addEventListener("click", (ev) => {
    if (ev.isTrusted) showShortcutHint("clear-result", "Esc to clear results");
    const cards = $result.querySelectorAll(".result-card");
    if (cards.length === 0) {
      $result.innerHTML =
        '<div class="empty-state">Click an action above to see the policy evaluation result</div>';
      return;
    }
    const animCount = Math.min(cards.length, 8);
    for (let i = 0; i < animCount; i++) {
      cards[i].style.transition = `opacity 0.2s ${i * 40}ms, transform 0.2s ${i * 40}ms`;
      cards[i].style.opacity = "0";
      cards[i].style.transform = "translateY(-8px) scale(0.97)";
    }
    setTimeout(() => {
      $result.innerHTML =
        '<div class="empty-state">Click an action above to see the policy evaluation result</div>';
    }, animCount * 40 + 220);
  });

  // Import snapshot
  document.getElementById("import-snapshot").addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;
    if (file.size > 10 * 1024 * 1024) {
      showToast("Snapshot too large (max 10 MB)");
      e.target.value = "";
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const snap = JSON.parse(reader.result);
        if (typeof snap.policy === "string") editor.setValue(snap.policy);
        if (Array.isArray(snap.audit_entries)) {
          auditEntries = snap.audit_entries;
          // Rebuild audit DOM rows from imported entries
          $audit.innerHTML = "";
          const limit = Math.min(auditEntries.length, 200);
          for (let i = auditEntries.length - 1; i >= auditEntries.length - limit; i--) {
            const entry = auditEntries[i];
            if (!addAuditEntry._tpl) {
              const t = document.createElement("template");
              t.innerHTML = `<div class="audit-entry audit-row">
                <span class="audit-time"></span>
                <span class="audit-type"></span>
                <span class="audit-risk"></span>
                <span class="audit-decision"></span>
                <span class="audit-rule"></span>
              </div>`;
              addAuditEntry._tpl = t;
            }
            const row = addAuditEntry._tpl.content.firstElementChild.cloneNode(true);
            const riskClass = (entry.risk || "").toLowerCase();
            const decisionClass = (entry.decision || "").toLowerCase();
            row.dataset.approval = decisionClass;
            const spans = row.children;
            spans[0].textContent = entry.time || "";
            spans[1].textContent = entry.type || "";
            spans[2].textContent = entry.risk || "";
            spans[2].className = `audit-risk ${riskClass}`;
            spans[3].textContent = entry.decision || "";
            spans[3].className = `audit-decision ${decisionClass}`;
            spans[4].textContent = entry.rule || "";
            $audit.prepend(row);
          }
          $auditCount.textContent = `${auditEntries.length} entries`;
        }
        // Restore stats if present
        if (snap.stats && typeof snap.stats === "object") {
          Object.assign(stats, snap.stats);
          if (_$statTotal) _$statTotal.textContent = String(stats.total);
          if (_$statAuto) _$statAuto.textContent = String(stats.auto);
          if (_$statApprove) _$statApprove.textContent = String(stats.approve);
          if (_$statBlock) _$statBlock.textContent = String(stats.block);
          if (_$statLatency) _$statLatency.textContent = stats.total > 0 ? (stats.totalMs / stats.total).toFixed(1) + " ms" : "\u2014";
        }
        showToast(`Loaded snapshot (${auditEntries.length} entries)`);
      } catch {
        showToast("Invalid snapshot file");
      }
    };
    reader.readAsText(file);
    e.target.value = ""; // reset for re-import
  });

  document.getElementById("clear-audit").addEventListener("click", () => {
    auditEntries = [];
    stats = { total: 0, auto: 0, approve: 0, block: 0, totalMs: 0 };
    actionCount = 0;
    $audit.innerHTML =
      '<div class="empty-state">Audit entries will appear here as you evaluate actions</div>';
    $auditCount.textContent = "0 entries";
    // Reset stat display
    if (_$statTotal) _$statTotal.textContent = "0";
    if (_$statAuto) _$statAuto.textContent = "0";
    if (_$statApprove) _$statApprove.textContent = "0";
    if (_$statBlock) _$statBlock.textContent = "0";
    if (_$statLatency) _$statLatency.textContent = "—";
    if (_$actionCounter) _$actionCounter.textContent = "0";
    const chart = document.getElementById("audit-chart");
    if (chart) chart.innerHTML = "";
    _chartEls = null; // reset cached chart refs so they're rebuilt on next use
  });

  // Audit filters
  const auditFilterBtns = document.querySelectorAll(".audit-filter");
  auditFilterBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      auditFilterBtns.forEach((b) => b.setAttribute("aria-pressed", "false"));
      document.querySelector(".audit-filter.active")?.classList.remove("active");
      btn.classList.add("active");
      btn.setAttribute("aria-pressed", "true");
      filterAuditLog(btn.dataset.filter);
    });
  });

  // Audit search (debounced for performance)
  const auditSearch = document.getElementById("audit-search");
  let auditSearchTimer = null;
  if (auditSearch) {
    auditSearch.addEventListener("input", () => {
      clearTimeout(auditSearchTimer);
      auditSearchTimer = setTimeout(() => {
        const activeFilter = document.querySelector(".audit-filter.active")?.dataset.filter || "all";
        filterAuditLog(activeFilter);
      }, 150);
    });
  }

  // Copy buttons
  document.getElementById("copy-policy").addEventListener("click", (e) => {
    if (e.isTrusted) showShortcutHint("copy-policy", "Ctrl+S to copy policy");
    copyToClipboard(editor.getValue(), e.target);
  });

  document.getElementById("download-policy").addEventListener("click", () => {
    const yaml = editor.getValue();
    downloadBlob(yaml, "text/yaml", "yaml");
    const sizeB = new Blob([yaml]).size;
    const sizeStr = sizeB > 1024 ? (sizeB / 1024).toFixed(1) + " KB" : sizeB + " B";
    showToast(`Downloaded policy.yaml (${sizeStr})`);
  });

  document.getElementById("copy-pip").addEventListener("click", (e) => {
    copyToClipboard("pip install agent-aegis", e.target);
  });

  const copyPipFooter = document.getElementById("copy-pip-footer");
  if (copyPipFooter) copyPipFooter.addEventListener("click", (e) => {
    copyToClipboard("pip install agent-aegis", e.target.closest("button"));
  });

  const copyPyprojectBtn = document.getElementById("copy-pyproject");
  if (copyPyprojectBtn) copyPyprojectBtn.addEventListener("click", (e) => {
    copyToClipboard('dependencies = [\n    "agent-aegis>=0.1.3",\n]', e.target);
    showToast("pyproject.toml dependency copied");
  });

  const copyDockerBtn = document.getElementById("copy-docker");
  if (copyDockerBtn) copyDockerBtn.addEventListener("click", (e) => {
    copyToClipboard("docker run --rm -p 8000:8000 ghcr.io/acacian/aegis:latest", e.target);
    showToast("Docker command copied");
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

  // Close dropdown on outside click — listener added/removed with menu lifecycle
  // (moved to toggleExportMenu to avoid permanent global click handler)
}

/* ---- Export Menu ---- */
function getActiveFilter() {
  return document.querySelector(".audit-filter.active")?.dataset.filter || "all";
}

function getFilteredEntries() {
  const filter = getActiveFilter();
  if (filter === "all") return auditEntries;
  return auditEntries.filter((e) => {
    const decision = (e.decision || e.approval || "").toLowerCase();
    return decision === filter;
  });
}

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
  const total = auditEntries.length;
  const filtered = getFilteredEntries();
  const filterLabel = getActiveFilter();
  const countLabel = filterLabel !== "all" && filtered.length !== total
    ? `${filtered.length} of ${total} entries (${filterLabel})`
    : `${total} entries`;
  menu.innerHTML = `
    <div class="export-header">${countLabel}</div>
    <button class="export-option" data-format="json">Export as JSON</button>
    <button class="export-option" data-format="csv">Export as CSV</button>
    <button class="export-option" data-format="yaml">Export as YAML report</button>
    <button class="export-option" data-format="html">Export as HTML report</button>
    <button class="export-option" data-format="markdown">Copy as Markdown</button>
    <button class="export-option" data-format="clipboard">Copy to clipboard</button>
    <button class="export-option" data-format="print">Print audit log</button>
    <button class="export-option" data-format="ndjson">Export as NDJSON (streaming)</button>
    <div class="export-header" style="margin-top:4px;border-top:1px solid var(--border);padding-top:6px">Quick</div>
    <button class="export-option" data-format="summary">Copy summary one-liner</button>`;
  document.body.appendChild(menu);

  // Scoped outside-click listener — auto-removes when menu closes
  requestAnimationFrame(() => {
    const dismiss = (e) => {
      if (!menu.contains(e.target) && e.target.id !== "export-audit") {
        menu.remove();
        document.removeEventListener("click", dismiss, true);
      }
    };
    document.addEventListener("click", dismiss, true);
    // Also clean up if menu is removed by its own click handler
    const obs = new MutationObserver(() => {
      if (!menu.parentNode) {
        document.removeEventListener("click", dismiss, true);
        obs.disconnect();
      }
    });
    obs.observe(document.body, { childList: true });
  });

  menu.addEventListener("click", (e) => {
    const format = e.target.dataset.format;
    if (format === "json") exportAuditJSON();
    else if (format === "csv") exportAuditCSV();
    else if (format === "yaml") exportAuditYAML();
    else if (format === "markdown") copyAuditAsMarkdown();
    else if (format === "html") exportAuditHTML();
    else if (format === "clipboard") copyAuditToClipboard();
    else if (format === "print") printAuditLog();
    else if (format === "ndjson") exportAuditNDJSON();
    else if (format === "summary") {
      const avgMs = stats.total > 0 ? (stats.totalMs / stats.total).toFixed(1) : "0";
      const line = `Aegis: ${stats.total} evals (${stats.auto} auto, ${stats.approve} approve, ${stats.block} block) avg ${avgMs}ms`;
      copyToClipboard(line, e.target);
      showToast("Summary copied");
    }
    menu.remove();
  });
}

function _downloadBlobDirect(blob, ext) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `aegis-audit-${new Date().toISOString().slice(0, 10)}.${ext}`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function downloadBlob(content, type, ext) {
  _downloadBlobDirect(new Blob([content], { type }), ext);
}

function exportAuditJSON() {
  const entries = getFilteredEntries();
  if (!entries.length) { showToast("No audit entries to export"); return; }
  const filter = getActiveFilter();
  const report = {
    meta: {
      exported_at: new Date().toISOString(),
      policy_yaml: editor.getValue(),
      version: "0.1.4",
      entry_count: entries.length,
      total_entries: auditEntries.length,
      filter: filter !== "all" ? filter : undefined,
    },
    summary: { ...stats, avg_latency_ms: stats.total > 0 ? +(stats.totalMs / stats.total).toFixed(2) : 0 },
    entries,
  };
  const json = JSON.stringify(report, null, 2);
  const blob = new Blob([json], { type: "application/json" });
  const sizeKb = (blob.size / 1024).toFixed(1);
  _downloadBlobDirect(blob, "json");
  const filterNote = filter !== "all" ? ` (${filter} only)` : "";
  showToast(`Exported ${entries.length} entries${filterNote} (${sizeKb} KB)`);
}

function exportAuditCSV() {
  const entries = getFilteredEntries();
  if (!entries.length) { showToast("No audit entries to export"); return; }
  const headers = ["time", "type", "risk", "decision", "rule", "allowed"];
  const displayHeaders = ["timestamp", "action_type", "risk", "approval", "rule", "allowed"];
  const csvEsc = (v) => {
    const s = String(v ?? "");
    return s.includes(",") || s.includes('"') || s.includes("\n") ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const rows = entries.map((e) => headers.map((h) => csvEsc(e[h])).join(","));
  const bom = "\uFEFF";
  downloadBlob(bom + [displayHeaders.join(","), ...rows].join("\n"), "text/csv;charset=utf-8", "csv");
  const filterNote = getActiveFilter() !== "all" ? ` (${getActiveFilter()})` : "";
  showToast(`Exported ${entries.length} entries as CSV${filterNote}`);
}

function exportAuditYAML() {
  const entries = getFilteredEntries();
  if (!entries.length) { showToast("No audit entries to export"); return; }
  const filter = getActiveFilter();
  const yamlLines = ["# Aegis Audit Report", `# Generated: ${new Date().toISOString()}`];
  if (filter !== "all") yamlLines.push(`# Filter: ${filter}`);
  yamlLines.push("");
  yamlLines.push("policy: |");
  editor.getValue().split("\n").forEach((l) => yamlLines.push("  " + l));
  yamlLines.push("", "evaluations:");
  entries.forEach((e) => {
    yamlLines.push(`  - action: ${e.type || e.action_type || ""}`);
    yamlLines.push(`    risk: ${e.risk || ""}`);
    yamlLines.push(`    decision: ${e.decision || e.approval || ""}`);
    yamlLines.push(`    rule: ${e.rule || "(default)"}`);
    yamlLines.push(`    time: "${e.time || e.timestamp || ""}"`);
  });
  const avgMs = stats.total > 0 ? (stats.totalMs / stats.total).toFixed(2) : "0";
  yamlLines.push("", "summary:");
  yamlLines.push(`  total: ${stats.total}`);
  yamlLines.push(`  auto: ${stats.auto}`);
  yamlLines.push(`  approve: ${stats.approve}`);
  yamlLines.push(`  block: ${stats.block}`);
  yamlLines.push(`  avg_latency_ms: ${avgMs}`);
  downloadBlob(yamlLines.join("\n"), "text/yaml", "yaml");
  const filterNote = filter !== "all" ? ` (${filter})` : "";
  showToast(`Exported ${entries.length} entries as YAML${filterNote}`);
}

function exportAuditHTML() {
  const entries = getFilteredEntries();
  if (!entries.length) { showToast("No audit entries to export"); return; }
  const rows = entries.map((e) =>
    `<tr><td>${_esc(e.time || e.timestamp)}</td><td>${_esc(e.type || e.action_type)}</td><td class="${_esc((e.risk || "").toLowerCase())}">${_esc(e.risk)}</td><td><strong>${_esc(e.decision || e.approval)}</strong></td><td>${_esc(e.rule)}</td></tr>`
  ).join("");
  const avgMs = stats.total > 0 ? (stats.totalMs / stats.total).toFixed(1) : "0";
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Aegis Audit Report</title>
<style>body{font-family:system-ui;max-width:900px;margin:2rem auto;color:#e6edf3;background:#0d1117}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #30363d;padding:8px 12px;text-align:left}
th{background:#161b22}h1{color:#58a6ff}.low{color:#3fb950}.medium{color:#d29922}.high{color:#f0883e}.critical{color:#f85149}
.summary{display:flex;gap:16px;margin:12px 0;font-size:0.9rem}</style></head><body>
<h1>Aegis Audit Report</h1><p>Generated: ${new Date().toISOString()}</p>
<div class="summary"><span>Total: <strong>${stats.total}</strong></span><span>Auto: <strong>${stats.auto}</strong></span><span>Approve: <strong>${stats.approve}</strong></span><span>Block: <strong>${stats.block}</strong></span><span>Avg: <strong>${avgMs}ms</strong></span></div>
<table><tr><th>Time</th><th>Action</th><th>Risk</th><th>Decision</th><th>Rule</th></tr>${rows}</table></body></html>`;
  downloadBlob(html, "text/html", "html");
  const filterNote = getActiveFilter() !== "all" ? ` (${getActiveFilter()})` : "";
  showToast(`Exported ${entries.length} entries as HTML${filterNote}`);
}

function exportAuditNDJSON() {
  const entries = getFilteredEntries();
  if (!entries.length) { showToast("No audit entries to export"); return; }
  const lines = entries.map((e) => JSON.stringify(e));
  downloadBlob(lines.join("\n") + "\n", "application/x-ndjson", "ndjson");
  const filterNote = getActiveFilter() !== "all" ? ` (${getActiveFilter()})` : "";
  showToast(`Exported ${entries.length} entries as NDJSON${filterNote}`);
}

async function copyAuditToClipboard() {
  const entries = getFilteredEntries();
  if (!entries.length) { showToast("No audit entries to copy"); return; }
  const lines = entries.map((e) =>
    `[${e.time || e.timestamp || ""}] ${e.type || e.action_type || ""} → ${e.target || ""} | ${e.decision || e.approval || ""} (${e.risk || e.risk_level || ""}) ${e.rule || e.matched_rule ? "rule:" + (e.rule || e.matched_rule) : ""}`
  );
  const filterNote = getActiveFilter() !== "all" ? ` (${getActiveFilter()})` : "";
  const header = `Aegis Audit Log — ${entries.length} entries${filterNote}, ${new Date().toISOString()}`;
  const text = header + "\n" + "=".repeat(header.length) + "\n" + lines.join("\n");
  await copyToClipboard(text);
  showToast(`Copied ${entries.length} entries to clipboard`);
}

async function copyAuditAsMarkdown() {
  const entries = getFilteredEntries();
  if (!entries.length) { showToast("No audit entries to copy"); return; }
  const rows = entries.map((e) =>
    `| ${e.time || ""} | ${e.type || ""} | ${e.risk || ""} | **${e.decision || ""}** | ${e.rule || ""} |`
  );
  const filterNote = getActiveFilter() !== "all" ? ` (${getActiveFilter()})` : "";
  const md = `### Aegis Audit Log\n\n| Time | Action | Risk | Decision | Rule |\n|------|--------|------|----------|------|\n${rows.join("\n")}\n\n_${entries.length} entries${filterNote} — ${new Date().toISOString()}_`;
  await copyToClipboard(md);
  showToast(`Copied ${entries.length} entries as Markdown`);
}

const _ESC_MAP = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const _ESC_RE = /[&<>"']/g;
function _esc(s) {
  const str = String(s || "");
  return _ESC_RE.test(str) ? str.replace(_ESC_RE, (c) => _ESC_MAP[c]) : str;
}

function printAuditLog() {
  const w = window.open("", "_blank");
  if (!w) { showToast("Pop-up blocked — allow pop-ups to print"); return; }
  const entries = getFilteredEntries();
  const rows = entries.map((e) =>
    `<tr><td>${_esc(e.timestamp || e.time)}</td><td>${_esc(e.action_type || e.type)}</td><td>${_esc(e.target)}</td><td>${_esc(e.risk)}</td><td>${_esc(e.approval || e.decision)}</td></tr>`
  ).join("");
  const filterNote = getActiveFilter() !== "all" ? ` (filter: ${_esc(getActiveFilter())})` : "";
  w.document.write(`<html><head><title>Aegis Audit</title><style>body{font-family:system-ui;max-width:900px;margin:2rem auto}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px 10px;text-align:left}th{background:#f0f0f0}@media print{button{display:none}}</style></head><body>
<h1>Aegis Audit Log</h1><p>${_esc(new Date().toLocaleString())} &mdash; ${entries.length} entries${filterNote}</p>
<table><tr><th>Time</th><th>Action</th><th>Target</th><th>Risk</th><th>Decision</th></tr>${rows}</table></body></html>`);
  w.document.close();
  w.print();
}

/* ---- Pyodide Init ---- */
let pyodideInitPromise = null;

async function initPyodide() {
  // Prevent double init
  if (pyodideInitPromise) return pyodideInitPromise;
  pyodideInitPromise = _initPyodideInner();
  return pyodideInitPromise;
}

async function _initPyodideInner() {
  const t0 = performance.now();
  try {
    setProgress(10, "Loading Python runtime...");
    pyodide = await loadPyodide();

    setProgress(40, "Installing dependencies...");
    await pyodide.loadPackage("micropip");
    const micropip = pyodide.pyimport("micropip");

    setProgress(60, "Installing packages (parallel)...");
    await Promise.all([
      micropip.install("pyyaml"),
      micropip.install("agent-aegis"),
    ]);

    setProgress(90, "Setting up evaluation engine...");
    await pyodide.runPythonAsync(AEGIS_SETUP_CODE);

    const loadTime = ((performance.now() - t0) / 1000).toFixed(1);
    setProgress(100, `Ready! (loaded in ${loadTime}s)`);
    console.log(`[Aegis] Pyodide loaded in ${loadTime}s`);
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
    const isOffline = !navigator.onLine;
    const hint = isOffline
      ? "You appear to be offline. Pyodide requires an internet connection on first load."
      : "Try refreshing the page. If the issue persists, check your network or ad-blocker settings.";
    setProgress(0, `Load failed: ${err.message}`);
    $status.title = err.stack || err.message;
    const helpEl = document.createElement("p");
    helpEl.style.cssText = "font-size:0.8rem;color:var(--text-muted);margin-top:8px";
    helpEl.textContent = hint;
    $status.parentNode.appendChild(helpEl);
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
let lastValidatedYaml = "";

let _$validationBadge = null;
function setValidationStatus(state, text) {
  const badge = _$validationBadge || (_$validationBadge = document.getElementById("validation-status"));
  if (!badge) return;
  badge.className = "validation-status" + (state === "error" ? " status-error" : state === "checking" ? " status-checking" : state === "warn" ? " status-warn" : "");
  if (state === "error") badge.textContent = "\u274C " + text;
  else if (state === "warn") badge.textContent = "\u26A0\uFE0F " + text;
  else if (state === "checking") badge.textContent = "\u23F3 Checking...";
  else { badge.textContent = "\u2705 Valid"; badge.title = ""; }
  // Click badge to jump to first error widget
  badge.style.cursor = (state === "error" || state === "warn") ? "pointer" : "";
  badge.onclick = (state === "error" || state === "warn") ? () => {
    if (activeLineWidgets.length > 0) {
      const firstWidget = activeLineWidgets[0];
      const line = firstWidget.line?.lineNo?.() ?? 0;
      editor.setCursor(line, 0);
      editor.scrollIntoView({ line, ch: 0 }, 100);
      editor.focus();
    }
  } : null;
}

function findWarningLine(yaml, warning, _lines) {
  const lines = _lines || yaml.split("\n");
  const lower = warning.toLowerCase();
  if (lower.includes("wildcard")) {
    return lines.findIndex((l) => /approval:\s*\*/.test(l));
  }
  if (lower.includes("over 20 rules")) {
    return lines.filter((l) => /- name:/.test(l)).length > 20 ? lines.length - 1 : -1;
  }
  if (lower.includes("critical risk")) {
    return lines.findIndex((l) => /risk_level:\s*critical/.test(l));
  }
  if (lower.includes("duplicate rule name")) {
    const match = warning.match(/: (\S+)$/);
    if (match) {
      const name = match[1];
      let found = -1;
      lines.forEach((l, i) => { if (l.includes("- name: " + name)) found = i; });
      return found;
    }
  }
  if (lower.includes("no match pattern")) {
    const lineMatch = warning.match(/line (\d+)/);
    if (lineMatch) return parseInt(lineMatch[1]) - 1;
  }
  if (lower.includes("empty rule name")) {
    return lines.findIndex((l) => /- name:\s*$/.test(l));
  }
  if (lower.includes("version should be quoted")) {
    return lines.findIndex((l) => /^version:\s*\d+\s*$/.test(l));
  }
  // Generic fallback: any warning containing "line N" can be located
  const lineMatch = warning.match(/line (\d+)/);
  if (lineMatch) return parseInt(lineMatch[1]) - 1;
  return -1;
}

function lintPolicyWarnings(yaml) {
  const warnings = [];
  if (/approval:\s*\*/m.test(yaml)) warnings.push("Wildcard approval pattern detected");
  if ((yaml.match(/- name:/g) || []).length > 20) warnings.push("Over 20 rules — consider splitting");
  if (/risk_level:\s*critical/m.test(yaml) && !/approval:\s*block/m.test(yaml)) {
    warnings.push("Critical risk without any block rule");
  }
  const names = (yaml.match(/- name:\s*(\S+)/g) || []).map((m) => m.replace("- name:", "").trim());
  const nameSet = new Set();
  for (const n of names) {
    if (nameSet.has(n)) { warnings.push(`Duplicate rule name: ${n}`); break; }
    nameSet.add(n);
  }

  // Empty or whitespace-only rule names
  if (/- name:\s*$/m.test(yaml)) warnings.push("Empty rule name detected");

  // Version should be a string "1", not integer
  if (/^version:\s*\d+\s*$/m.test(yaml)) warnings.push("Version should be quoted: version: \"1\"");

  // Single-pass per-line analysis
  const lines = yaml.split("\n");
  const indents = new Set();
  const validApprovals = ["auto", "approve", "block"];
  const validRisks = ["low", "medium", "high", "critical"];
  let inRule = false, hasMatch = false, ruleLine = -1;
  let inRuleBlock = false, hasRisk = false, hasApproval = false, ruleStart = -1;

  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];

    // Indentation tracking
    const indentMatch = l.match(/^( +)\S/);
    if (indentMatch) indents.add(indentMatch[1].length);

    // Rule boundary: "- name:"
    if (/^\s*- name:/.test(l)) {
      // Close previous rule checks
      if (inRule && !hasMatch && ruleLine >= 0) {
        warnings.push(`Rule at line ${ruleLine + 1} has no match pattern`);
      }
      if (inRuleBlock && hasApproval && !hasRisk && ruleStart >= 0) {
        warnings.push(`Rule at line ${ruleStart + 1} has no risk_level — consider adding one`);
      }
      inRule = true; hasMatch = false; ruleLine = i;
      inRuleBlock = true; hasRisk = false; hasApproval = false; ruleStart = i;
    } else if (inRule) {
      if (/^\s+match:/.test(l)) hasMatch = true;
      if (/^\s+risk_level:/.test(l)) hasRisk = true;
      if (/^\s+approval:/.test(l)) hasApproval = true;
    }

    // Invalid approval values
    const am = l.match(/approval:\s*["']?(\w+)["']?/);
    if (am && !validApprovals.includes(am[1].toLowerCase())) {
      warnings.push(`Invalid approval "${am[1]}" at line ${i + 1} — use auto, approve, or block`);
    }

    // Invalid risk_level values
    const rm = l.match(/risk_level:\s*["']?(\w+)["']?/);
    if (rm && !validRisks.includes(rm[1].toLowerCase())) {
      warnings.push(`Invalid risk_level "${rm[1]}" at line ${i + 1} — use low, medium, high, or critical`);
    }
  }
  // Close final rule
  if (inRule && !hasMatch && ruleLine >= 0) {
    warnings.push(`Rule at line ${ruleLine + 1} has no match pattern`);
  }
  if (inRuleBlock && hasApproval && !hasRisk && ruleStart >= 0) {
    warnings.push(`Rule at line ${ruleStart + 1} has no risk_level — consider adding one`);
  }

  // Mixed indentation
  if (indents.has(2) && indents.has(4)) {
    warnings.push("Mixed indentation detected (2 and 4 spaces) — use consistent 2-space indent");
  }

  // Catch-all rule with type: "*" and auto/approve (shadows later rules)
  if (/type:\s*["']?\*["']?\s*$/m.test(yaml) && /target:\s*["']?\*["']?\s*$/m.test(yaml)) {
    const catchAllApproval = yaml.match(/type:\s*["']?\*["']?[\s\S]*?approval:\s*(\w+)/);
    if (catchAllApproval && catchAllApproval[1] === "auto") {
      warnings.push("Catch-all rule (type: *, target: *) with auto-approve — later rules are shadowed");
    }
  }

  // All rules auto-approve — policy provides no guardrails
  const approvals = yaml.match(/approval:\s*(\w+)/g) || [];
  if (approvals.length > 1 && approvals.every((a) => /auto/.test(a))) {
    warnings.push("All rules auto-approve — consider adding review or block rules");
  }

  return { warnings, lines };
}

function setupPolicyValidation() {
  editor.on("change", () => {
    clearTimeout(validationTimer);
    setValidationStatus("checking");
    validationTimer = setTimeout(() => {
      const current = editor.getValue();
      if (current === lastValidatedYaml) { setValidationStatus("ok"); return; }
      lastValidatedYaml = current;
      validatePolicy();
    }, 600);
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
      setValidationStatus("error", result.error.slice(0, 40));
    } else {
      clearEditorErrors();
      // Check for warnings — show inline
      const lint = lintPolicyWarnings(yaml);
      const warns = lint.warnings;
      const yamlLines = lint.lines;
      if (warns.length) {
        setValidationStatus("warn", warns[0]);
        // Set tooltip with all warnings
        if (_$validationBadge) _$validationBadge.title = warns.join("\n");
        let fixableCount = 0;
        warns.forEach((w) => {
          const warnEl = document.createElement("div");
          warnEl.className = "cm-warn-widget";
          const fix = suggestFix(w, null, yaml, yamlLines);
          const warnText = document.createElement("span");
          warnText.className = "warn-text";
          warnText.textContent = "\u26A0 " + w;
          const dismissBtn = document.createElement("button");
          dismissBtn.className = "warn-dismiss-btn";
          dismissBtn.title = "Dismiss";
          dismissBtn.textContent = "\u00D7";
          if (fix) {
            fixableCount++;
            const fixBtn = document.createElement("button");
            fixBtn.className = "warn-fix-btn";
            fixBtn.textContent = fix.label;
            fixBtn.addEventListener("click", () => {
              editor.setValue(fix.result);
              clearEditorErrors();
            });
            warnEl.append(warnText, fixBtn, dismissBtn);
          } else {
            warnEl.append(warnText, dismissBtn);
          }
          const wLine = findWarningLine(yaml, w, yamlLines);
          if (wLine >= 0) {
            const widget = editor.addLineWidget(wLine, warnEl, { coverGutter: false, noHScroll: true });
            activeLineWidgets.push(widget);
            dismissBtn.addEventListener("click", () => {
              const idx = activeLineWidgets.indexOf(widget);
              if (idx >= 0) activeLineWidgets.splice(idx, 1);
              editor.removeLineWidget(widget);
            });
          }
        });
        // Show "Fix All" when 2+ warnings are fixable
        if (fixableCount >= 2 && _$validationBadge) {
          let fixAllBtn = _$validationBadge.parentNode.querySelector(".fix-all-btn");
          if (!fixAllBtn) {
            fixAllBtn = document.createElement("button");
            fixAllBtn.className = "fix-all-btn";
            _$validationBadge.parentNode.insertBefore(fixAllBtn, _$validationBadge.nextSibling);
          }
          fixAllBtn.textContent = `Fix all (${fixableCount})`;
          fixAllBtn.onclick = () => {
            let currentYaml = editor.getValue();
            warns.forEach((w) => {
              const f = suggestFix(w, null, currentYaml);
              if (f) currentYaml = f.result;
            });
            editor.setValue(currentYaml);
            clearEditorErrors();
            fixAllBtn.remove();
            showToast(`Applied ${fixableCount} fixes`);
          };
        }
      } else {
        setValidationStatus("ok");
        // Remove any lingering Fix All button
        document.querySelector(".fix-all-btn")?.remove();
      }
    }
  } catch (err) {
    setValidationStatus("ok"); // parsing errors during typing are ok
  }
}

let activeLineWidgets = [];

function clearEditorErrors() {
  activeLineWidgets.forEach((w) => editor.removeLineWidget(w));
  activeLineWidgets = [];
  const errorEl = document.getElementById("editor-error");
  if (errorEl) errorEl.remove();
}

function showEditorError(msg, line) {
  clearEditorErrors();

  // Highlight error line + add inline widget
  if (line !== undefined && line !== null && line >= 0) {
    const lineIdx = Math.max(0, line - 1);
    editor.markText(
      { line: lineIdx, ch: 0 },
      { line: lineIdx, ch: editor.getLine(lineIdx)?.length || 0 },
      { className: "cm-error-line" }
    );

    // Inline error widget at the error line
    const widgetEl = document.createElement("div");
    widgetEl.className = "cm-error-widget";
    widgetEl.textContent = msg;
    const widget = editor.addLineWidget(lineIdx, widgetEl, { coverGutter: false, noHScroll: true });
    activeLineWidgets.push(widget);
  }

  // Check for auto-fixable patterns
  const fix = suggestFix(msg, line, editor.getValue());

  // Show error banner below editor
  const wrapper = document.querySelector(".editor-wrapper");
  let errorEl = document.getElementById("editor-error");
  if (!errorEl) {
    errorEl = document.createElement("div");
    errorEl.id = "editor-error";
    errorEl.className = "editor-error";
    wrapper.parentNode.insertBefore(errorEl, wrapper.nextSibling);
  }

  errorEl.replaceChildren();
  const msgSpan = document.createElement("span");
  msgSpan.textContent = msg;
  errorEl.appendChild(msgSpan);

  if (fix) {
    const fixBtn = document.createElement("button");
    fixBtn.className = "error-fix-btn";
    fixBtn.textContent = fix.label;
    fixBtn.title = fix.description;
    fixBtn.addEventListener("click", () => {
      editor.setValue(fix.result);
      clearEditorErrors();
    });
    errorEl.appendChild(fixBtn);
  }
}

function suggestFix(msg, line, yaml, _lines) {
  const lines = _lines || yaml.split("\n");
  const lower = msg.toLowerCase();

  // Missing version field
  if (lower.includes("version") && !yaml.includes('version:')) {
    return {
      label: "Add version",
      description: 'Add missing version: "1" at top',
      result: 'version: "1"\n' + yaml,
    };
  }

  // Tab character in YAML (common mistake)
  if (lower.includes("tab") || (line && lines[line - 1]?.includes("\t"))) {
    return {
      label: "Fix tabs",
      description: "Replace tabs with spaces",
      result: yaml.replace(/\t/g, "  "),
    };
  }

  // Missing rules field
  if (lower.includes("rules") && !yaml.includes("rules:")) {
    return {
      label: "Add rules section",
      description: "Add empty rules array",
      result: yaml.trimEnd() + "\n\nrules:\n  - name: default_rule\n    match: { type: \"*\" }\n    risk_level: medium\n    approval: approve\n",
    };
  }

  // Indentation error — try re-indenting the error line
  if (lower.includes("indent") && line && line > 0) {
    const idx = line - 1;
    if (idx < lines.length) {
      const prevIndent = lines[Math.max(0, idx - 1)].match(/^(\s*)/)[1].length;
      lines[idx] = " ".repeat(prevIndent + 2) + lines[idx].trim();
      return {
        label: "Fix indentation",
        description: `Re-indent line ${line}`,
        result: lines.join("\n"),
      };
    }
  }

  // Unquoted version number (version: 1 instead of version: "1")
  if (lower.includes("version") && yaml.match(/version:\s*\d+\s*$/m)) {
    return {
      label: "Quote version",
      description: 'Wrap version number in quotes',
      result: yaml.replace(/version:\s*(\d+)/m, 'version: "$1"'),
    };
  }

  // Duplicate key detection
  if (lower.includes("duplicate")) {
    const seen = {};
    const deduped = [];
    for (const l of lines) {
      const m = l.match(/^(\s*)([\w-]+):/);
      if (m) {
        const key = m[1].length + ":" + m[2];
        if (seen[key]) { deduped.push("# REMOVED DUPLICATE: " + l.trim()); continue; }
        seen[key] = true;
      }
      deduped.push(l);
    }
    return { label: "Remove duplicates", description: "Comment out duplicate keys", result: deduped.join("\n") };
  }

  // Trailing whitespace causing parse issues
  if (lower.includes("mapping") || lower.includes("expected") || lower.includes("syntax")) {
    const trimmed = lines.map((l) => l.trimEnd()).join("\n");
    if (trimmed !== yaml) {
      return {
        label: "Trim whitespace",
        description: "Remove trailing whitespace from all lines",
        result: trimmed,
      };
    }
  }

  // Invalid approval value
  const invalidApproval = yaml.match(/approval:\s*(\S+)/);
  if (invalidApproval && !["auto", "approve", "block"].includes(invalidApproval[1].replace(/"/g, ""))) {
    return {
      label: "Fix approval",
      description: `Replace "${invalidApproval[1]}" with "approve"`,
      result: yaml.replace(invalidApproval[0], "approval: approve"),
    };
  }

  return null;
}

/* ---- Dynamic Action Buttons for Industry Presets ---- */
const RISK_CLASSES = { low: "risk-low", medium: "risk-medium", high: "risk-high", critical: "risk-critical" };
const RISK_ICONS = {
  low: "\u{1F4D6}", medium: "\u270F\uFE0F", high: "\u26A1", critical: "\u{1F6A8}",
  navigate: "\u{1F310}", read: "\u{1F4D6}", read_file: "\u{1F4C4}", search: "\u{1F50D}",
  create: "\u2795", update: "\u270F\uFE0F", write: "\u270F\uFE0F", write_file: "\u{1F4DD}",
  export: "\u{1F4E4}", delete: "\u{1F6A8}", merge: "\u{1F500}", shell: "\u{1F4BB}",
  git_push: "\u{1F680}", deploy: "\u{1F6AB}", install: "\u{1F4E6}",
  view: "\u{1F441}\uFE0F", report: "\u{1F4CA}", create_invoice: "\u{1F9FE}",
  payment: "\u{1F4B3}", refund: "\u{1F4B8}", transfer: "\u{1F3E6}",
  screenshot: "\u{1F4F7}", scroll: "\u2195\uFE0F", click: "\u{1F5B1}\uFE0F",
  fill: "\u{1F4DD}", submit: "\u{1F4E8}", upload: "\u{1F4E4}", eval: "\u26D4", execute_js: "\u26D4",
  select: "\u{1F50E}", insert: "\u2795", alter_table: "\u{1F527}", drop: "\u{1F4A3}", truncate: "\u{1F4A3}",
  bulk_update: "\u26A1", bulk_delete: "\u{1F6A8}",
};

function guessRisk(actionType) {
  if (["read", "read_file", "view", "report", "navigate", "search", "screenshot", "scroll", "select", "list_dir"].includes(actionType)) return "low";
  if (["delete", "drop", "truncate", "deploy", "eval", "execute_js", "transfer"].includes(actionType)) return "critical";
  if (["shell", "bulk_update", "export", "install", "payment", "refund", "upload", "submit", "alter_table"].includes(actionType)) return "high";
  return "medium";
}

let _$quickActions = null;
function updateActionButtons(preset) {
  const actions = typeof PRESET_ACTIONS !== "undefined" && PRESET_ACTIONS[preset];
  if (!actions) return; // keep default buttons for non-industry presets

  const container = _$quickActions || (_$quickActions = document.querySelector(".quick-actions"));
  const frag = document.createDocumentFragment();
  actions.forEach((a) => {
    const risk = guessRisk(a.action_type);
    const icon = RISK_ICONS[a.action_type] || RISK_ICONS[risk];
    const btn = document.createElement("button");
    btn.className = `action-btn ${RISK_CLASSES[risk]}`;
    btn._action = a;
    btn.dataset.action = JSON.stringify(a);
    const iconSpan = document.createElement("span");
    iconSpan.className = "action-icon";
    iconSpan.textContent = icon;
    const labelSpan = document.createElement("span");
    labelSpan.className = "action-label";
    labelSpan.textContent = a.description;
    const riskSpan = document.createElement("span");
    riskSpan.className = "action-risk";
    riskSpan.textContent = risk.toUpperCase();
    btn.append(iconSpan, labelSpan, riskSpan);
    btn.addEventListener("click", (ev) => {
      const rect = btn.getBoundingClientRect();
      const ripple = document.createElement("span");
      ripple.className = "btn-ripple";
      ripple.style.left = ev.clientX - rect.left + "px";
      ripple.style.top = ev.clientY - rect.top + "px";
      btn.appendChild(ripple);
      ripple.addEventListener("animationend", () => ripple.remove());
      evaluateAction(a);
    });
    frag.appendChild(btn);
  });
  container.replaceChildren(frag);
}

/* ---- Evaluate Action ---- */
let _$actionCounter = null;
const _deferIdle = window.requestIdleCallback || ((cb) => setTimeout(cb, 16));

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
  json.loads(${JSON.stringify(JSON.stringify(action))})
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
    actionCount++;
    const counter = _$actionCounter || (_$actionCounter = document.getElementById("action-counter"));
    if (counter) counter.textContent = actionCount;
    updateStats(result);

    // Defer non-critical audit log updates to idle time
    // (addAuditEntry already calls updateAuditChart internally)
    _deferIdle(() => addAuditEntry(result));
  } catch (err) {
    showToast(`Evaluation error: ${err.message}`);
    console.error(err);
  }
}

/* ---- Run All Actions ---- */
async function runAllActions() {
  const buttons = document.querySelectorAll(".action-btn");
  const runAllBtn = document.getElementById("run-all");
  const origText = runAllBtn?.textContent || "Run All";

  // Show running state
  if (runAllBtn) {
    runAllBtn.disabled = true;
    runAllBtn.textContent = `Running 0/${buttons.length}...`;
  }

  let i = 0;
  for (const btn of buttons) {
    const action = btn._action || JSON.parse(btn.dataset.action);
    btn.classList.add("action-running");
    await evaluateAction(action);
    btn.classList.remove("action-running");
    i++;
    if (runAllBtn) runAllBtn.textContent = `Running ${i}/${buttons.length}...`;
    // Stagger delay decreases as batch progresses for a "speeding up" feel
    await new Promise((r) => setTimeout(r, Math.max(80, 200 - i * 15)));
  }

  // Restore button
  if (runAllBtn) {
    runAllBtn.disabled = false;
    runAllBtn.textContent = origText;
  }
}

/* ---- Render Result ---- */
// Template for result cards — parsed once, cloned on each render
let _cardTemplate = null;
function _getCardTemplate() {
  if (_cardTemplate) return _cardTemplate;
  const t = document.createElement("template");
  t.innerHTML = `<div class="result-card">
    <div class="result-header">
      <span class="result-action-type"></span>
      <span class="result-target"></span>
      <div class="result-badges">
        <span class="risk-badge"></span>
        <span class="approval-badge"></span>
      </div>
    </div>
    <div class="result-details">
      <div class="result-detail"><span class="label">Matched Rule: </span><span class="value _rule"></span></div>
      <div class="result-detail"><span class="label">Description: </span><span class="value _desc"></span></div>
    </div>
    <div class="result-footer">
      <div class="result-allowed"></div>
      <div class="result-copy-group">
        <button class="copy-code-btn" data-fmt="python" title="Copy as Python snippet">Python</button>
        <button class="copy-code-btn" data-fmt="pytest" title="Copy as pytest test case">pytest</button>
        <button class="copy-code-btn" data-fmt="curl" title="Copy as cURL command">cURL</button>
        <button class="copy-code-btn" data-fmt="httpie" title="Copy as HTTPie command">HTTPie</button>
        <button class="copy-code-btn" data-fmt="docker" title="Copy as Docker + curl command">Docker</button>
        <button class="copy-code-btn" data-fmt="markdown" title="Copy as Markdown table">MD</button>
        <button class="copy-code-btn" data-fmt="ci" title="Copy as GitHub Actions step">CI</button>
        <button class="copy-code-btn" data-fmt="github" title="Copy as GitHub issue template">Issue</button>
        <button class="copy-code-btn" data-fmt="yaml" title="Copy as YAML test case">YAML</button>
        <button class="copy-code-btn" data-fmt="env" title="Copy as .env config">ENV</button>
        <button class="copy-code-btn" data-fmt="oneliner" title="Copy one-line summary">TL;DR</button>
        <button class="copy-code-btn" data-fmt="make" title="Copy as Makefile target">Make</button>
        <button class="copy-code-btn" data-fmt="json-schema" title="Copy as JSON Schema">Schema</button>
      </div>
    </div>
  </div>`;
  _cardTemplate = t;
  return t;
}

function renderResult(r) {
  const riskClass = r.risk_level.toLowerCase();
  const approvalClass = r.approval.toLowerCase();
  const isAllowed = r.is_allowed;

  const card = _getCardTemplate().content.firstElementChild.cloneNode(true);
  const decisionClass = `result-${approvalClass}`;
  card.className = `result-card ${isAllowed ? "result-allowed" : "result-blocked"} ${decisionClass}`;

  // Populate using textContent (faster than innerHTML, auto-escaped)
  card.querySelector(".result-action-type").textContent = r.action_type;
  card.querySelector(".result-target").textContent = r.target;
  const riskBadge = card.querySelector(".risk-badge");
  riskBadge.textContent = r.risk_level;
  riskBadge.classList.add(riskClass);
  const approvalBadge = card.querySelector(".approval-badge");
  approvalBadge.textContent = r.approval;
  approvalBadge.classList.add(approvalClass);
  card.querySelector("._rule").textContent = r.matched_rule || "(default)";
  card.querySelector("._desc").textContent = r.description || "-";
  const allowedDiv = card.querySelector(".result-allowed");
  allowedDiv.className = `result-allowed ${isAllowed ? "yes" : "no"}`;
  allowedDiv.textContent = isAllowed ? "\u2705 ALLOWED" : "\uD83D\uDEAB BLOCKED" +
    (r.approval === "block" ? " \u2014 Policy explicitly blocks this action" : "");

  // Store result data on card for delegated copy handler
  card._resultData = r;

  // Prepend (latest first) and cap result cards to prevent DOM bloat
  const MAX_RESULT_CARDS = 50;
  const empty = $result.querySelector(".empty-state");
  if (empty) empty.remove();
  $result.prepend(card);

  // Remove oldest cards beyond limit (lastElementChild avoids querySelectorAll)
  while ($result.children.length > MAX_RESULT_CARDS) {
    $result.lastElementChild.remove();
  }

  // Decision-specific visual feedback
  if (r.approval === "block") {
    spawnBlockParticles(card);
    showBlockedEffect(card);
  } else if (r.approval === "auto") {
    card.classList.add("flash-auto");
    card.addEventListener("animationend", () => card.classList.remove("flash-auto"), { once: true });
    spawnAutoCheckmarks(card);
  } else if (r.approval === "approve") {
    card.classList.add("flash-approve");
    card.addEventListener("animationend", () => card.classList.remove("flash-approve"), { once: true });
    showPulseRing(card);
  }
}

/* ---- Block Particles (visual feedback for blocked actions) ---- */
const _prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

function spawnBlockParticles(card) {
  if (_prefersReducedMotion.matches) return;
  const symbols = ["\u{1F6E1}", "\u{1F6AB}", "\u{26D4}", "\u{2716}"];
  const rect = card.getBoundingClientRect();
  const frag = document.createDocumentFragment();

  for (let i = 0; i < 8; i++) {
    const p = document.createElement("div");
    p.className = "block-particle";
    p.textContent = symbols[i % symbols.length];
    p.style.left = rect.left + Math.random() * rect.width + "px";
    p.style.top = rect.top + "px";
    p.style.setProperty("--dx", (Math.random() - 0.5) * 120 + "px");
    p.style.setProperty("--dy", -(40 + Math.random() * 80) + "px");
    p.addEventListener("animationend", () => p.remove());
    frag.appendChild(p);
  }
  document.body.appendChild(frag);
}

/* ---- Auto-Approve Checkmark Burst ---- */
function spawnAutoCheckmarks(card) {
  if (_prefersReducedMotion.matches) return;
  const rect = card.getBoundingClientRect();
  const frag = document.createDocumentFragment();
  for (let i = 0; i < 5; i++) {
    const p = document.createElement("div");
    p.className = "auto-checkmark";
    p.textContent = "\u2713";
    p.style.left = rect.left + Math.random() * rect.width + "px";
    p.style.top = rect.top + rect.height / 2 + "px";
    p.style.setProperty("--dx", (Math.random() - 0.5) * 80 + "px");
    p.style.setProperty("--dy", -(20 + Math.random() * 60) + "px");
    p.addEventListener("animationend", () => p.remove());
    frag.appendChild(p);
  }
  document.body.appendChild(frag);
}

/* ---- Approve Pulse Ring ---- */
function showPulseRing(card) {
  const ring = document.createElement("div");
  ring.className = "approve-pulse-ring";
  card.style.position = "relative";
  card.appendChild(ring);
  ring.addEventListener("animationend", () => ring.remove());
}

/* ---- Celebration (milestone at 50 & 100 evals) ---- */
function spawnCelebration() {
  if (_prefersReducedMotion.matches) return;
  const symbols = ["\u2B50", "\u{1F389}", "\u{1F38A}", "\u2728", "\u{1F3C6}", "\u{1F680}", "\u{1F31F}"];
  const count = 16;
  const frag = document.createDocumentFragment();
  for (let i = 0; i < count; i++) {
    const p = document.createElement("div");
    p.className = "block-particle";
    p.textContent = symbols[i % symbols.length];
    p.style.left = (10 + Math.random() * 80) + "vw";
    p.style.top = window.innerHeight + "px";
    p.style.setProperty("--dx", (Math.random() - 0.5) * 250 + "px");
    p.style.setProperty("--dy", -(250 + Math.random() * 350) + "px");
    p.style.setProperty("--rot", (Math.random() * 360 - 180) + "deg");
    p.style.fontSize = (1.2 + Math.random() * 0.8) + "rem";
    p.style.animationDuration = (0.7 + Math.random() * 0.4) + "s";
    p.style.animationDelay = (i * 0.03) + "s";
    p.addEventListener("animationend", () => p.remove());
    frag.appendChild(p);
  }
  document.body.appendChild(frag);
}

/* ---- Blocked Effect (CSS-only particle burst + screen shake) ---- */
let _$resultPanel = null;
function showBlockedEffect(card) {
  card.classList.add("blocked-effect");
  card.addEventListener(
    "animationend",
    () => card.classList.remove("blocked-effect"),
    { once: true }
  );
  // Brief screen shake on the result panel
  const rp = _$resultPanel || (_$resultPanel = document.getElementById("result"));
  if (rp) {
    rp.classList.add("shake");
    rp.addEventListener("animationend", () => rp.classList.remove("shake"), { once: true });
  }
}

/* ---- Audit Log ---- */
/* ---- Stats Bar ---- */
// Cache stat DOM elements to avoid repeated getElementById calls
let _$statTotal, _$statAuto, _$statApprove, _$statBlock, _$statLatency;
function _cacheStatEls() {
  _$statTotal = document.getElementById("stat-total");
  _$statAuto = document.getElementById("stat-auto");
  _$statApprove = document.getElementById("stat-approve");
  _$statBlock = document.getElementById("stat-block");
  _$statLatency = document.getElementById("stat-latency");
}

function updateStats(result) {
  if (!_$statTotal) _cacheStatEls();
  stats.total++;
  const approval = (result.approval || "").toLowerCase();
  if (approval === "auto") stats.auto++;
  else if (approval === "approve") stats.approve++;
  else if (approval === "block") stats.block++;
  if (result.latency_ms) stats.totalMs += result.latency_ms;

  const $t = _$statTotal;
  const $a = _$statAuto;
  const $ap = _$statApprove;
  const $b = _$statBlock;
  const $l = _$statLatency;
  const animate = (el, val) => {
    if (!el) return;
    // Rolling counter: quickly count up from previous value
    const prev = parseInt(el.textContent) || 0;
    if (val - prev <= 1) {
      el.textContent = val;
    } else {
      let current = prev;
      const step = Math.max(1, Math.floor((val - prev) / 6));
      const tick = () => {
        current = Math.min(current + step, val);
        el.textContent = current;
        if (current < val) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    }
    el.classList.remove("stat-pop");
    void el.offsetWidth;
    el.classList.add("stat-pop");
  };
  animate($t, stats.total);
  if (approval === "auto") animate($a, stats.auto);
  else if (approval === "approve") animate($ap, stats.approve);
  else if (approval === "block") animate($b, stats.block);
  if ($l && stats.total > 0) {
    $l.textContent = (stats.totalMs / stats.total).toFixed(1) + "ms";
  }

  // Milestone glow on multiples of 10
  if (stats.total % 10 === 0 && $t) {
    $t.parentElement.classList.add("stat-milestone");
    setTimeout(() => $t.parentElement.classList.remove("stat-milestone"), 1500);
    // Big milestone celebration at 50 and 100
    if (stats.total === 50 || stats.total === 100) {
      showToast(`${stats.total} evaluations! You're a governance pro.`);
      spawnCelebration();
    }
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

  // Template-cloned audit row (faster than innerHTML per row)
  if (!addAuditEntry._tpl) {
    const t = document.createElement("template");
    t.innerHTML = `<div class="audit-entry audit-row">
      <span class="audit-time"></span>
      <span class="audit-type"></span>
      <span class="audit-risk"></span>
      <span class="audit-decision"></span>
      <span class="audit-rule"></span>
    </div>`;
    addAuditEntry._tpl = t;
  }
  const row = addAuditEntry._tpl.content.firstElementChild.cloneNode(true);
  row.dataset.approval = decisionClass;
  const spans = row.children;
  spans[0].textContent = entry.time;
  spans[1].textContent = entry.type;
  spans[2].textContent = entry.risk;
  spans[2].className = `audit-risk ${riskClass}`;
  spans[3].textContent = entry.decision;
  spans[3].className = `audit-decision ${decisionClass}`;
  spans[4].textContent = entry.rule;

  // CSS-based filter respects data-filter attribute on container — no inline style needed

  const MAX_AUDIT_ROWS = 200;
  const empty = $audit.querySelector(".empty-state");
  if (empty) empty.remove();
  $audit.prepend(row);

  // Cap audit DOM rows (use lastElementChild to avoid querySelectorAll)
  while ($audit.children.length > MAX_AUDIT_ROWS) {
    $audit.lastElementChild.remove();
  }

  const countParts = [`${auditEntries.length} entries`];
  if (stats.auto) countParts.push(`${stats.auto} auto`);
  if (stats.approve) countParts.push(`${stats.approve} review`);
  if (stats.block) countParts.push(`${stats.block} block`);
  $auditCount.textContent = countParts.join(" · ");
  updateAuditChart();
}

let _$auditSearch = null;
function filterAuditLog(filter) {
  const search = ((_$auditSearch || (_$auditSearch = document.getElementById("audit-search")))?.value || "").toLowerCase();
  // Use CSS class on container for type filtering (avoids iterating all rows)
  $audit.dataset.filter = filter;
  if (search) {
    // Text search still requires row iteration, but only for text matching
    const rows = $audit.querySelectorAll(".audit-row");
    rows.forEach((row) => {
      row.classList.toggle("search-hidden", !row.textContent.toLowerCase().includes(search));
    });
  } else {
    // Clear any search-hidden classes
    $audit.querySelectorAll(".search-hidden").forEach((r) => r.classList.remove("search-hidden"));
  }
}

let _chartEls = null;
function _ensureChart() {
  if (_chartEls) return _chartEls;
  let chart = document.getElementById("audit-chart");
  if (!chart) {
    chart = document.createElement("div");
    chart.id = "audit-chart";
    chart.className = "audit-chart";
    chart.innerHTML = `
      <div class="chart-bar">
        <div class="chart-seg chart-auto"></div>
        <div class="chart-seg chart-approve"></div>
        <div class="chart-seg chart-block"></div>
      </div>
      <div class="chart-legend">
        <span class="legend-auto"></span>
        <span class="legend-approve"></span>
        <span class="legend-block"></span>
      </div>`;
    $auditCount.parentNode.insertBefore(chart, $auditCount.nextSibling);
  }
  _chartEls = {
    root: chart,
    segAuto: chart.querySelector(".chart-auto"),
    segApprove: chart.querySelector(".chart-approve"),
    segBlock: chart.querySelector(".chart-block"),
    legAuto: chart.querySelector(".legend-auto"),
    legApprove: chart.querySelector(".legend-approve"),
    legBlock: chart.querySelector(".legend-block"),
  };
  return _chartEls;
}

function updateAuditChart() {
  const c = _ensureChart();
  const total = stats.total;
  if (total === 0) {
    c.segAuto.style.width = c.segApprove.style.width = c.segBlock.style.width = "0%";
    c.legAuto.textContent = c.legApprove.textContent = c.legBlock.textContent = "";
    return;
  }
  c.segAuto.style.width = (stats.auto / total) * 100 + "%";
  c.segApprove.style.width = (stats.approve / total) * 100 + "%";
  c.segBlock.style.width = (stats.block / total) * 100 + "%";
  c.legAuto.textContent = stats.auto + " auto";
  c.legApprove.textContent = stats.approve + " approve";
  c.legBlock.textContent = stats.block + " block";
}

/* ---- Toast ---- */
let _toastEl = null;
let _toastTimer = null;
/* ---- Shortcut Discovery Hints ---- */
const _shortcutHintSeen = {};
const isMac = navigator.platform?.includes("Mac");
const _mod = isMac ? "Cmd" : "Ctrl";
function showShortcutHint(id, shortcut) {
  if (!shortcut) return;
  const count = _shortcutHintSeen[id] || 0;
  if (count >= 3) return; // only show 3 times per action
  _shortcutHintSeen[id] = count + 1;
  showToast(`Tip: ${shortcut.replace("Ctrl", _mod)}`);
}

const _toastQueue = [];
let _toastBusy = false;

function showToast(msg) {
  if (!_toastEl) {
    _toastEl = document.createElement("div");
    _toastEl.className = "toast";
    document.body.appendChild(_toastEl);
  }
  // If same message is already showing, just reset timer
  if (_toastEl.style.display !== "none" && _toastEl.textContent === msg) {
    clearTimeout(_toastTimer);
    _toastTimer = setTimeout(_nextToast, 3000);
    return;
  }
  _toastQueue.push(msg);
  if (!_toastBusy) _drainToast();
}

function _drainToast() {
  if (_toastQueue.length === 0) { _toastBusy = false; return; }
  _toastBusy = true;
  const msg = _toastQueue.shift();
  _toastEl.textContent = msg;
  _toastEl.style.display = "";
  _toastEl.style.animation = "none";
  void _toastEl.offsetWidth;
  _toastEl.style.animation = "";
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(_nextToast, 3000);
}

function _nextToast() {
  _toastEl.style.display = "none";
  if (_toastQueue.length > 0) setTimeout(_drainToast, 200);
  else _toastBusy = false;
}

/* ---- Utils ---- */
async function copyToClipboard(text, btn) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      // Fallback for older browsers / insecure contexts
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.cssText = "position:fixed;left:-9999px";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
    if (btn) {
      const orig = btn.textContent;
      btn.textContent = "\u2713 Copied!";
      btn.classList.add("copy-success");
      setTimeout(() => {
        btn.textContent = orig;
        btn.classList.remove("copy-success");
      }, 1500);
    }
  } catch {
    showToast("Failed to copy — try manually");
  }
}

/* ---- Code Generation for Copy Buttons ---- */
const _SAFE_MAP = { "\\": "\\\\", '"': '\\"', "'": "\\'", "\n": "\\n", "\r": "\\r", "`": "\\`", "$": "\\$" };
const _SAFE_RE = /[\\"'\n\r`$]/g;
function _safeStr(s) {
  const str = String(s || "");
  return _SAFE_RE.test(str) ? str.replace(_SAFE_RE, (c) => _SAFE_MAP[c]) : str;
}

function generateCode(fmt, r) {
  const params = JSON.stringify(r.params || {});
  if (fmt === "python") {
    return `from aegis import Action, Policy, Runtime

policy = Policy.from_yaml("policy.yaml")
async with Runtime(executor=your_executor, policy=policy) as rt:
    result = await rt.run_one(
        Action("${_safeStr(r.action_type)}", "${_safeStr(r.target)}", params=${params})
    )
    # Expected: ${r.is_allowed ? "ALLOWED" : "BLOCKED"} (${r.risk_level}, ${r.approval})`;
  }

  if (fmt === "pytest") {
    return `import pytest
from aegis import Action, Policy

@pytest.fixture
def policy():
    return Policy.from_yaml("policy.yaml")

def test_${_safeStr(r.action_type)}_${_safeStr(r.approval)}(policy):
    \"\"\"${_safeStr(r.action_type)} on ${_safeStr(r.target)} should be ${_safeStr(r.approval)}.\"\"\"
    action = Action("${_safeStr(r.action_type)}", "${_safeStr(r.target)}", params=${params})
    decision = policy.evaluate(action)
    assert decision.approval.value == "${_safeStr(r.approval)}"
    assert decision.risk_level.value == "${_safeStr(r.risk_level.toLowerCase())}"
    assert decision.is_allowed is ${r.is_allowed ? "True" : "False"}`;
  }

  if (fmt === "curl") {
    const body = JSON.stringify({
      action_type: r.action_type,
      target: r.target,
      params: r.params || {},
    });
    return `curl -X POST http://localhost:8000/api/v1/evaluate \\
  -H "Content-Type: application/json" \\
  -d '${body}'
# Expected: ${r.approval} (${r.risk_level})`;
  }

  if (fmt === "httpie") {
    return `http POST http://localhost:8000/api/v1/evaluate \\
  action_type="${_safeStr(r.action_type)}" \\
  target="${_safeStr(r.target)}" \\
  params:='${params}'
# Expected: ${r.approval} (${r.risk_level})`;
  }

  if (fmt === "docker") {
    const body = JSON.stringify({
      action_type: r.action_type,
      target: r.target,
      params: r.params || {},
    });
    return `# Run Aegis REST API in Docker
docker run -d -p 8000:8000 -v $(pwd)/policy.yaml:/app/policy.yaml \\
  ghcr.io/acacian/aegis:latest

# Test this action
curl -s http://localhost:8000/api/v1/evaluate \\
  -H "Content-Type: application/json" \\
  -d '${body}' | python3 -m json.tool
# Expected: ${r.approval} (${r.risk_level})`;
  }

  if (fmt === "ci") {
    return `# GitHub Actions step — Aegis policy check
- name: Check ${_safeStr(r.action_type)} policy
  run: |
    pip install agent-aegis
    python -c "
    from aegis import Action, Policy
    p = Policy.from_yaml('policy.yaml')
    r = p.evaluate(Action('${_safeStr(r.action_type)}', '${_safeStr(r.target)}'))
    assert r.approval.value == '${_safeStr(r.approval)}', f'Expected ${r.approval}, got {r.approval.value}'
    print('Policy check passed: ${_safeStr(r.action_type)} → ${r.approval}')
    "`;
  }

  if (fmt === "github") {
    return `### Bug Report / Discussion

**Policy evaluation result:**
- Action: \`${r.action_type}\` on \`${r.target}\`
- Expected: \`${r.approval}\` (${r.risk_level})
- Allowed: ${r.is_allowed ? "Yes" : "No"}
- Matched Rule: \`${r.matched_rule || "(default)"}\`

<details>
<summary>Policy YAML</summary>

\`\`\`yaml
${editor.getValue()}
\`\`\`
</details>

**Environment:** Aegis Playground (browser, Pyodide)
**Version:** 0.1.4`;
  }

  if (fmt === "markdown") {
    return `### Aegis Policy Evaluation

| Field | Value |
|-------|-------|
| Action | \`${r.action_type}\` |
| Target | \`${r.target}\` |
| Risk | **${r.risk_level}** |
| Decision | **${r.approval}** |
| Allowed | ${r.is_allowed ? "Yes" : "No"} |

\`\`\`yaml
# Policy used:
${(() => { const ls = editor.getValue().split("\n"); return ls.slice(0, 10).join("\n") + (ls.length > 10 ? "\n# ..." : ""); })()}
\`\`\``;
  }

  if (fmt === "yaml") {
    return `# Aegis test case — ${_safeStr(r.action_type)}
test_case:
  action:
    type: "${_safeStr(r.action_type)}"
    target: "${_safeStr(r.target)}"
    params: ${params === "{}" ? "{}" : params}
  expected:
    approval: ${r.approval}
    risk_level: ${r.risk_level.toLowerCase()}
    is_allowed: ${r.is_allowed}
    matched_rule: "${r.matched_rule || ""}"`;
  }

  if (fmt === "make") {
    return `.PHONY: test-${_safeStr(r.action_type)}
test-${_safeStr(r.action_type)}: ## Test ${_safeStr(r.action_type)} policy evaluation
\t@python -c "from aegis import Action, Policy; \\
\t  p = Policy.from_yaml('policy.yaml'); \\
\t  r = p.evaluate(Action('${_safeStr(r.action_type)}', '${_safeStr(r.target)}')); \\
\t  assert r.approval.value == '${_safeStr(r.approval)}', f'Expected ${r.approval}, got {r.approval.value}'; \\
\t  print('PASS: ${_safeStr(r.action_type)} → ${r.approval}')"`;
  }

  if (fmt === "oneliner") {
    return `${r.action_type} → ${r.target} | ${r.approval.toUpperCase()} (${r.risk_level}) ${r.is_allowed ? "ALLOWED" : "BLOCKED"} ${r.matched_rule ? "via " + r.matched_rule : ""}`.trim();
  }

  if (fmt === "env") {
    return `# Aegis environment config for ${r.action_type}
AEGIS_POLICY_PATH=./policy.yaml
AEGIS_ACTION_TYPE=${r.action_type}
AEGIS_ACTION_TARGET=${r.target}
AEGIS_EXPECTED_APPROVAL=${r.approval}
AEGIS_EXPECTED_RISK=${r.risk_level.toLowerCase()}
AEGIS_LOG_LEVEL=INFO`;
  }

  if (fmt === "json-schema") {
    return JSON.stringify({
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "title": `Aegis evaluation: ${r.action_type}`,
      "type": "object",
      "properties": {
        "action_type": { "const": r.action_type },
        "target": { "const": r.target },
        "approval": { "enum": ["auto", "approve", "block"], "default": r.approval },
        "risk_level": { "enum": ["low", "medium", "high", "critical"], "default": r.risk_level.toLowerCase() },
        "is_allowed": { "type": "boolean", "default": r.is_allowed },
      },
      "required": ["action_type", "approval", "risk_level", "is_allowed"],
    }, null, 2);
  }

  return "";
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
        # Use cache — if this YAML was already parsed successfully, skip re-parse
        key = hashlib.md5(yaml_str.encode()).hexdigest()
        if key in _policy_cache:
            return json.dumps({"ok": True})
        data = yaml.safe_load(yaml_str)
        if data is None:
            return json.dumps({"ok": True})
        policy = Policy.from_dict(data)
        # Warm the cache for evaluate_action
        _policy_cache[key] = policy
        if len(_policy_cache) > 20:
            oldest = next(iter(_policy_cache))
            del _policy_cache[oldest]
        return json.dumps({"ok": True})
    except yaml.YAMLError as e:
        line = None
        if hasattr(e, 'problem_mark') and e.problem_mark:
            line = e.problem_mark.line + 1
        return json.dumps({"error": f"YAML syntax error: {e}", "line": line})
    except Exception as e:
        return json.dumps({"error": f"Policy error: {e}", "line": None})
`;
