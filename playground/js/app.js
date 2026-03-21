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

/* ---- Init ---- */
document.addEventListener("DOMContentLoaded", async () => {
  initEditor();
  loadPolicyFromURL();
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
  }
  palette.classList.remove("hidden");
  const input = palette.querySelector(".command-input");
  input.value = "";
  input.focus();
  renderCommands(input, "");

  input.addEventListener("input", () => renderCommands(input, input.value));
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const first = palette.querySelector(".command-item");
      if (first) first.click();
    }
  });
}

function getCommandItems() {
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
  // Add presets
  const presetBtns = document.querySelectorAll(".preset-btn:not(.preset-divider)");
  presetBtns.forEach((btn) => {
    items.push({ label: `Preset: ${btn.textContent.trim()}`, icon: "\uD83D\uDCD1", action: () => btn.click() });
  });
  return items;
}

function renderCommands(input, query) {
  const list = document.querySelector(".command-list");
  const items = getCommandItems().filter((i) =>
    !query || i.label.toLowerCase().includes(query.toLowerCase())
  );
  list.innerHTML = items.slice(0, 12).map((i, idx) =>
    `<button class="command-item" data-idx="${idx}">${i.icon} ${i.label}</button>`
  ).join("");
  list.querySelectorAll(".command-item").forEach((el) => {
    el.addEventListener("click", () => {
      const idx = parseInt(el.dataset.idx);
      items[idx]?.action();
      document.getElementById("command-palette")?.classList.add("hidden");
    });
  });
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

  // Auto-hide FAB menu on scroll
  let scrollTimer;
  window.addEventListener("scroll", () => {
    clearTimeout(scrollTimer);
    scrollTimer = setTimeout(() => menu.classList.add("hidden"), 200);
  }, { passive: true });
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

    const presetBtns = [...document.querySelectorAll(".preset-btn:not(.preset-divider)")];
    const activeIdx = presetBtns.findIndex((b) => b.classList.contains("active"));

    if (dx < 0 && activeIdx < presetBtns.length - 1) {
      presetBtns[activeIdx + 1].click(); // swipe left → next
    } else if (dx > 0 && activeIdx > 0) {
      presetBtns[activeIdx - 1].click(); // swipe right → prev
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

  // Trigger arch-flow stagger animation on scroll
  const archFlow = document.querySelector(".arch-flow");
  if (archFlow) {
    const archObs = new IntersectionObserver((entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) {
          e.target.classList.add("animate-flow");
          archObs.unobserve(e.target);
        }
      });
    }, { threshold: 0.3 });
    archObs.observe(archFlow);
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
    viewportMargin: Infinity,
  });
  editor.setValue(POLICY_PRESETS.default);
  initTheme();

  // Show field hints on cursor activity
  editor.on("cursorActivity", () => {
    const line = editor.getLine(editor.getCursor().line) || "";
    const keyMatch = line.match(/^\s*(\w[\w_]*):/);
    const hint = keyMatch && YAML_HINTS[keyMatch[1]];
    const hintEl = document.getElementById("editor-hint");
    if (hint && hintEl) {
      hintEl.textContent = hint;
      hintEl.style.display = "";
    } else if (hintEl) {
      hintEl.style.display = "none";
    }
  });
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
      return;
    } catch {
      // Ignore invalid hash
    }
  }

  // Restore last edited policy from localStorage
  const saved = localStorage.getItem("aegis-last-policy");
  if (saved && saved !== POLICY_PRESETS.default) {
    editor.setValue(saved);
    document.querySelectorAll(".preset-btn").forEach((b) => b.classList.remove("active"));
  }
}

// Auto-save policy to localStorage on change (debounced)
let saveTimer = null;
function updateRuleCount() {
  const rc = document.getElementById("rule-count");
  if (!rc) return;
  const count = (editor.getValue().match(/- name:/g) || []).length;
  rc.textContent = `${count} rule${count !== 1 ? "s" : ""}`;
}

function setupPolicySave() {
  editor.on("change", () => {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      localStorage.setItem("aegis-last-policy", editor.getValue());
    }, 1000);
    updateRuleCount();
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
        <button id="share-embed-btn" class="action-btn action-low" style="margin-top:8px;width:100%">Copy Embed Code</button>
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
    document.getElementById("share-embed-btn").addEventListener("click", () => {
      const embedUrl = document.getElementById("share-url-input").value;
      const iframe = `<iframe src="${embedUrl}" width="100%" height="600" frameborder="0" title="Aegis Playground"></iframe>`;
      copyToClipboard(iframe, document.getElementById("share-embed-btn"));
      showToast("Embed code copied!");
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
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>S</kbd><span>Save snapshot (JSON)</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>X</kbd><span>Clear results + audit</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>P</kbd><span>Command palette</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>K</kbd><span>Focus custom action input</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>S</kbd><span>Copy policy to clipboard</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>/</kbd><span>Toggle YAML comment</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>G</kbd><span>Go to line</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>E</kbd><span>Export audit log (JSON)</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>F</kbd><span>Focus audit search</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>D</kbd><span>Toggle theme</span></div>
        <div class="shortcut-row"><kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>D</kbd><span>Duplicate line</span></div>
        <div class="shortcut-row"><kbd>0</kbd>-<kbd>9</kbd><span>Switch preset (by position)</span></div>
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
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

const THEMES = ["dark", "light", "high-contrast"];

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

  // Update meta theme-color
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta && THEME_META[theme]) meta.content = THEME_META[theme].color;

  // Update toggle button label and show correct icon
  const btn = document.getElementById("theme-toggle");
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

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  const idx = THEMES.indexOf(current);
  const next = THEMES[(idx + 1) % THEMES.length];
  localStorage.setItem("aegis-theme", next);
  applyTheme(next);
  showToast(`${THEME_META[next]?.icon || ""} Theme: ${THEME_META[next]?.label || next}`);
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
    // Ctrl/Cmd + Shift + X → clear all results + audit
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === "X" || e.key === "x")) {
      e.preventDefault();
      document.getElementById("clear-result")?.click();
      document.getElementById("clear-audit")?.click();
      showToast("Cleared results and audit log");
      return;
    }
    // Ctrl/Cmd + G → go to line in editor
    if ((e.ctrlKey || e.metaKey) && (e.key === "g" || e.key === "G") && !e.shiftKey) {
      e.preventDefault();
      const lineCount = editor.lineCount();
      const line = prompt(`Go to line (1-${lineCount}):`);
      if (line) {
        const n = Math.max(0, Math.min(parseInt(line) - 1, lineCount - 1));
        editor.setCursor(n, 0);
        editor.focus();
        editor.scrollIntoView({ line: n, ch: 0 }, 100);
      }
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
    // Ctrl/Cmd + K → focus custom action input (command palette style)
    if ((e.ctrlKey || e.metaKey) && e.key === "k") {
      e.preventDefault();
      const customInput = document.getElementById("custom-type");
      if (customInput) { customInput.focus(); customInput.select(); }
      return;
    }
    // Ctrl/Cmd + F → focus audit search filter
    if ((e.ctrlKey || e.metaKey) && e.key === "f" && !e.shiftKey) {
      const auditSearch = document.getElementById("audit-search");
      if (auditSearch) {
        e.preventDefault();
        auditSearch.focus();
        auditSearch.select();
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
    // 1-9, 0 → switch preset (when not in input)
    if (!isInput && e.key >= "0" && e.key <= "9" && !e.ctrlKey && !e.metaKey) {
      const presetBtns = document.querySelectorAll(".preset-btn:not(.preset-divider)");
      const idx = e.key === "0" ? 9 : parseInt(e.key) - 1;
      if (idx < presetBtns.length) {
        presetBtns[idx].click();
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
      if (active) copyToClipboard(active.textContent, e.target);
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
    copyToClipboard(JSON.stringify(auditEntries, null, 2), e.target);
    showToast(`Copied ${auditEntries.length} results as JSON`);
  });

  document.getElementById("clear-result").addEventListener("click", () => {
    $result.innerHTML =
      '<div class="empty-state">Click an action above to see the policy evaluation result</div>';
  });

  // Import snapshot
  document.getElementById("import-snapshot").addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const snap = JSON.parse(reader.result);
        if (snap.policy) editor.setValue(snap.policy);
        if (snap.audit_entries) {
          auditEntries = snap.audit_entries;
          $auditCount.textContent = `${auditEntries.length} entries`;
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
    $audit.innerHTML =
      '<div class="empty-state">Audit entries will appear here as you evaluate actions</div>';
    $auditCount.textContent = "0 entries";
    const chart = document.getElementById("audit-chart");
    if (chart) chart.innerHTML = "";
  });

  // Audit filters
  document.querySelectorAll(".audit-filter").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelector(".audit-filter.active")?.classList.remove("active");
      btn.classList.add("active");
      filterAuditLog(btn.dataset.filter);
    });
  });

  // Audit search
  const auditSearch = document.getElementById("audit-search");
  if (auditSearch) {
    auditSearch.addEventListener("input", () => {
      const activeFilter = document.querySelector(".audit-filter.active")?.dataset.filter || "all";
      filterAuditLog(activeFilter);
    });
  }

  // Copy buttons
  document.getElementById("copy-policy").addEventListener("click", (e) => {
    copyToClipboard(editor.getValue(), e.target);
  });

  document.getElementById("download-policy").addEventListener("click", () => {
    downloadBlob(editor.getValue(), "text/yaml", "yaml");
    showToast("Downloaded policy.yaml");
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
    <button class="export-option" data-format="csv">Export as CSV</button>
    <button class="export-option" data-format="yaml">Export as YAML report</button>
    <button class="export-option" data-format="html">Export as HTML report</button>
    <button class="export-option" data-format="print">Print audit log</button>`;
  document.body.appendChild(menu);

  menu.addEventListener("click", (e) => {
    const format = e.target.dataset.format;
    if (format === "json") exportAuditJSON();
    else if (format === "csv") exportAuditCSV();
    else if (format === "yaml") exportAuditYAML();
    else if (format === "html") exportAuditHTML();
    else if (format === "print") printAuditLog();
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
  const report = {
    meta: {
      exported_at: new Date().toISOString(),
      policy_yaml: editor.getValue(),
      version: "0.1.4",
    },
    summary: { ...stats, avg_latency_ms: stats.total > 0 ? +(stats.totalMs / stats.total).toFixed(2) : 0 },
    entries: auditEntries,
  };
  downloadBlob(JSON.stringify(report, null, 2), "application/json", "json");
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

function exportAuditYAML() {
  const yamlLines = ["# Aegis Audit Report", `# Generated: ${new Date().toISOString()}`, `# Policy:`, ""];
  yamlLines.push("policy: |");
  editor.getValue().split("\n").forEach((l) => yamlLines.push("  " + l));
  yamlLines.push("", "evaluations:");
  auditEntries.forEach((e) => {
    yamlLines.push(`  - action: ${e.action_type}`);
    yamlLines.push(`    target: ${e.target}`);
    yamlLines.push(`    risk: ${e.risk}`);
    yamlLines.push(`    approval: ${e.approval}`);
    yamlLines.push(`    rule: ${e.rule || "N/A"}`);
    yamlLines.push(`    timestamp: "${e.timestamp}"`);
  });
  yamlLines.push("", `summary:`, `  total: ${stats.total}`, `  auto: ${stats.auto}`, `  approve: ${stats.approve}`, `  block: ${stats.block}`);
  downloadBlob(yamlLines.join("\n"), "text/yaml", "yaml");
}

function exportAuditHTML() {
  const rows = auditEntries.map((e) =>
    `<tr><td>${e.timestamp}</td><td>${e.action_type}</td><td>${e.target}</td><td>${e.risk}</td><td><strong>${e.approval}</strong></td></tr>`
  ).join("");
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Aegis Audit Report</title>
<style>body{font-family:system-ui;max-width:900px;margin:2rem auto;color:#e6edf3;background:#0d1117}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #30363d;padding:8px 12px;text-align:left}
th{background:#161b22}h1{color:#58a6ff}</style></head><body>
<h1>Aegis Audit Report</h1><p>Generated: ${new Date().toISOString()}</p>
<p>Total: ${stats.total} | Auto: ${stats.auto} | Approve: ${stats.approve} | Block: ${stats.block}</p>
<table><tr><th>Time</th><th>Action</th><th>Target</th><th>Risk</th><th>Decision</th></tr>${rows}</table></body></html>`;
  downloadBlob(html, "text/html", "html");
}

function printAuditLog() {
  const w = window.open("", "_blank");
  if (!w) { showToast("Pop-up blocked — allow pop-ups to print"); return; }
  const rows = auditEntries.map((e) =>
    `<tr><td>${e.timestamp}</td><td>${e.action_type}</td><td>${e.target}</td><td>${e.risk}</td><td>${e.approval}</td></tr>`
  ).join("");
  w.document.write(`<html><head><title>Aegis Audit</title><style>body{font-family:system-ui}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px 10px}th{background:#f0f0f0}</style></head><body>
<h1>Aegis Audit Log</h1><p>${new Date().toLocaleString()} &mdash; ${stats.total} evaluations</p>
<table><tr><th>Time</th><th>Action</th><th>Target</th><th>Risk</th><th>Decision</th></tr>${rows}</table></body></html>`);
  w.document.close();
  w.print();
}

/* ---- Pyodide Init ---- */
async function initPyodide() {
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
let lastValidatedYaml = "";

function setValidationStatus(state, text) {
  const badge = document.getElementById("validation-status");
  if (!badge) return;
  badge.className = "validation-status" + (state === "error" ? " status-error" : state === "checking" ? " status-checking" : state === "warn" ? " status-warn" : "");
  if (state === "error") badge.innerHTML = "\u274C " + text;
  else if (state === "warn") badge.innerHTML = "\u26A0\uFE0F " + text;
  else if (state === "checking") badge.innerHTML = "\u23F3 Checking...";
  else badge.innerHTML = "\u2705 Valid";
}

function findWarningLine(yaml, warning) {
  const lines = yaml.split("\n");
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
  const dupes = names.filter((n, i) => names.indexOf(n) !== i);
  if (dupes.length) warnings.push(`Duplicate rule name: ${dupes[0]}`);
  return warnings;
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
      const warns = lintPolicyWarnings(yaml);
      if (warns.length) {
        setValidationStatus("warn", warns[0]);
        warns.forEach((w) => {
          const warnEl = document.createElement("div");
          warnEl.className = "cm-warn-widget";
          warnEl.textContent = w;
          const wLine = findWarningLine(yaml, w);
          if (wLine >= 0) {
            const widget = editor.addLineWidget(wLine, warnEl, { coverGutter: false, noHScroll: true });
            activeLineWidgets.push(widget);
          }
        });
      } else {
        setValidationStatus("ok");
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

  errorEl.innerHTML = "";
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

function suggestFix(msg, line, yaml) {
  const lines = yaml.split("\n");
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
    btn.addEventListener("click", (ev) => {
      // Ripple effect
      const rect = btn.getBoundingClientRect();
      const ripple = document.createElement("span");
      ripple.className = "btn-ripple";
      ripple.style.left = ev.clientX - rect.left + "px";
      ripple.style.top = ev.clientY - rect.top + "px";
      btn.appendChild(ripple);
      ripple.addEventListener("animationend", () => ripple.remove());
      evaluateAction(a);
    });
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
    actionCount++;
    const counter = document.getElementById("action-counter");
    if (counter) counter.textContent = actionCount;
    updateStats(result);

    // Defer non-critical audit log updates to idle time
    const deferFn = window.requestIdleCallback || ((cb) => setTimeout(cb, 16));
    deferFn(() => {
      addAuditEntry(result);
      updateAuditChart();
    });
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
    const action = JSON.parse(btn.dataset.action);
    // Highlight current button
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
function renderResult(r) {
  const riskClass = r.risk_level.toLowerCase();
  const approvalClass = r.approval.toLowerCase();
  const isAllowed = r.is_allowed;

  const card = document.createElement("div");
  const decisionClass = `result-${approvalClass}`;
  card.className = `result-card ${isAllowed ? "result-allowed" : "result-blocked"} ${decisionClass}`;
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
      <div class="result-copy-group">
        <button class="copy-code-btn" data-fmt="python" title="Copy as Python snippet">Python</button>
        <button class="copy-code-btn" data-fmt="pytest" title="Copy as pytest test case">pytest</button>
        <button class="copy-code-btn" data-fmt="curl" title="Copy as cURL command">cURL</button>
        <button class="copy-code-btn" data-fmt="docker" title="Copy as Docker + curl command">Docker</button>
        <button class="copy-code-btn" data-fmt="markdown" title="Copy as Markdown table">MD</button>
        <button class="copy-code-btn" data-fmt="ci" title="Copy as GitHub Actions step">CI</button>
        <button class="copy-code-btn" data-fmt="github" title="Copy as GitHub issue template">Issue</button>
        <button class="copy-code-btn" data-fmt="yaml" title="Copy as YAML test case">YAML</button>
      </div>
    </div>
  `;

  // Copy code handlers
  card.querySelectorAll(".copy-code-btn").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      const fmt = btn.dataset.fmt;
      const code = generateCode(fmt, r);
      copyToClipboard(code, e.target);
    });
  });

  // Prepend (latest first) and cap result cards to prevent DOM bloat
  const MAX_RESULT_CARDS = 50;
  const empty = $result.querySelector(".empty-state");
  if (empty) empty.remove();
  $result.prepend(card);

  // Remove oldest cards beyond limit
  const cards = $result.querySelectorAll(".result-card");
  if (cards.length > MAX_RESULT_CARDS) {
    for (let i = MAX_RESULT_CARDS; i < cards.length; i++) {
      cards[i].remove();
    }
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

/* ---- Auto-Approve Checkmark Burst ---- */
function spawnAutoCheckmarks(card) {
  const rect = card.getBoundingClientRect();
  for (let i = 0; i < 5; i++) {
    const p = document.createElement("div");
    p.className = "auto-checkmark";
    p.textContent = "\u2713";
    p.style.left = rect.left + Math.random() * rect.width + "px";
    p.style.top = rect.top + rect.height / 2 + "px";
    p.style.setProperty("--dx", (Math.random() - 0.5) * 80 + "px");
    p.style.setProperty("--dy", -(20 + Math.random() * 60) + "px");
    document.body.appendChild(p);
    p.addEventListener("animationend", () => p.remove());
  }
}

/* ---- Approve Pulse Ring ---- */
function showPulseRing(card) {
  const ring = document.createElement("div");
  ring.className = "approve-pulse-ring";
  card.style.position = "relative";
  card.appendChild(ring);
  ring.addEventListener("animationend", () => ring.remove());
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
  const animate = (el, val) => {
    if (!el) return;
    el.textContent = val;
    el.classList.remove("stat-pop");
    void el.offsetWidth; // force reflow
    el.classList.add("stat-pop");
  };
  animate($t, stats.total);
  if (approval === "auto") animate($a, stats.auto);
  else if (approval === "approve") animate($ap, stats.approve);
  else if (approval === "block") animate($b, stats.block);
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
  row.className = "audit-entry audit-row";
  row.dataset.approval = decisionClass;
  row.innerHTML = `
    <span class="audit-time">${entry.time}</span>
    <span class="audit-type">${escHtml(entry.type)}</span>
    <span class="audit-risk ${riskClass}">${entry.risk}</span>
    <span class="audit-decision ${decisionClass}">${entry.decision}</span>
    <span class="audit-rule">${escHtml(entry.rule)}</span>
  `;

  // Respect active filter
  const activeFilter = document.querySelector(".audit-filter.active")?.dataset.filter || "all";
  if (activeFilter !== "all" && activeFilter !== decisionClass) {
    row.style.display = "none";
  }

  const MAX_AUDIT_ROWS = 200;
  const empty = $audit.querySelector(".empty-state");
  if (empty) empty.remove();
  $audit.prepend(row);

  // Cap audit DOM rows
  const auditRows = $audit.querySelectorAll(".audit-row");
  if (auditRows.length > MAX_AUDIT_ROWS) {
    for (let i = MAX_AUDIT_ROWS; i < auditRows.length; i++) {
      auditRows[i].remove();
    }
  }

  $auditCount.textContent = `${auditEntries.length} entries`;
  updateAuditChart();
}

function filterAuditLog(filter) {
  const search = (document.getElementById("audit-search")?.value || "").toLowerCase();
  const rows = $audit.querySelectorAll(".audit-row");
  rows.forEach((row) => {
    const matchFilter = filter === "all" || row.dataset.approval === filter;
    const matchSearch = !search || row.textContent.toLowerCase().includes(search);
    row.style.display = matchFilter && matchSearch ? "" : "none";
  });
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

/* ---- Code Generation for Copy Buttons ---- */
function generateCode(fmt, r) {
  const params = JSON.stringify(r.params || {});
  if (fmt === "python") {
    return `from aegis import Action, Policy, Runtime

policy = Policy.from_yaml("policy.yaml")
async with Runtime(executor=your_executor, policy=policy) as rt:
    result = await rt.run_one(
        Action("${r.action_type}", "${r.target}", params=${params})
    )
    # Expected: ${r.is_allowed ? "ALLOWED" : "BLOCKED"} (${r.risk_level}, ${r.approval})`;
  }

  if (fmt === "pytest") {
    return `import pytest
from aegis import Action, Policy

@pytest.fixture
def policy():
    return Policy.from_yaml("policy.yaml")

def test_${r.action_type}_${r.approval}(policy):
    \"\"\"${r.action_type} on ${r.target} should be ${r.approval}.\"\"\"
    action = Action("${r.action_type}", "${r.target}", params=${params})
    decision = policy.evaluate(action)
    assert decision.approval.value == "${r.approval}"
    assert decision.risk_level.value == "${r.risk_level.toLowerCase()}"
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
- name: Check ${r.action_type} policy
  run: |
    pip install agent-aegis
    python -c "
    from aegis import Action, Policy
    p = Policy.from_yaml('policy.yaml')
    r = p.evaluate(Action('${r.action_type}', '${r.target}'))
    assert r.approval.value == '${r.approval}', f'Expected ${r.approval}, got {r.approval.value}'
    print('Policy check passed: ${r.action_type} → ${r.approval}')
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
${editor.getValue().split("\n").slice(0, 10).join("\n")}${editor.getValue().split("\n").length > 10 ? "\n# ..." : ""}
\`\`\``;
  }

  if (fmt === "yaml") {
    return `# Aegis test case — ${r.action_type}
test_case:
  action:
    type: "${r.action_type}"
    target: "${r.target}"
    params: ${params === "{}" ? "{}" : params}
  expected:
    approval: ${r.approval}
    risk_level: ${r.risk_level.toLowerCase()}
    is_allowed: ${r.is_allowed}
    matched_rule: "${r.matched_rule || ""}"`;
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
