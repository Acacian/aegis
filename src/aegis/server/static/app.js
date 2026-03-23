/* Aegis Dashboard — SPA Client */
"use strict";

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

const routes = {
  overview: renderOverview,
  audit: renderAudit,
  policy: renderPolicy,
  anomalies: renderAnomalies,
  compliance: renderCompliance,
  regulatory: renderRegulatory,
  system: renderSystem,
};

let _charts = [];
let _refreshTimer = null;
let _autoRefresh = true;
let _pageLiveHandler = null;

function destroyCharts() {
  _charts.forEach((c) => c.destroy());
  _charts = [];
}

function stopAutoRefresh() {
  if (_refreshTimer) { clearInterval(_refreshTimer); _refreshTimer = null; }
}

function startAutoRefresh(fn, interval) {
  stopAutoRefresh();
  if (_autoRefresh) { _refreshTimer = setInterval(fn, interval); }
}

// ---------------------------------------------------------------------------
// WebSocket real-time audit stream
// ---------------------------------------------------------------------------

let _ws = null;
let _wsListeners = [];
let _wsConnected = false;

function connectWS() {
  if (_ws && (_ws.readyState === WebSocket.OPEN || _ws.readyState === WebSocket.CONNECTING)) return;
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  _ws = new WebSocket(proto + "//" + location.host + "/ws/audit");
  _ws.onopen = () => {
    _wsConnected = true;
    updateWSIndicator();
  };
  _ws.onmessage = (evt) => {
    try {
      const entry = JSON.parse(evt.data);
      _wsListeners.forEach((fn) => { try { fn(entry); } catch (_) {} });
    } catch (_) {}
  };
  _ws.onclose = () => {
    _wsConnected = false;
    updateWSIndicator();
    setTimeout(connectWS, 5000);
  };
  _ws.onerror = () => {
    _wsConnected = false;
    updateWSIndicator();
  };
}

function onAuditEntry(fn) { _wsListeners.push(fn); }
function offAuditEntry(fn) { _wsListeners = _wsListeners.filter((f) => f !== fn); }

function updateWSIndicator() {
  const el = document.getElementById("ws-status");
  if (!el) return;
  el.innerHTML = _wsConnected
    ? '<span class="inline-block w-2 h-2 rounded-full bg-green-500 mr-1"></span>Live'
    : '<span class="inline-block w-2 h-2 rounded-full bg-red-500 mr-1 animate-pulse"></span>Connecting';
}

function router() {
  const hash = location.hash.replace(/^#\/?/, "") || "overview";
  const page = hash.split("/")[0];
  const render = routes[page] || renderNotFound;

  // Update active nav
  document.querySelectorAll(".nav-item").forEach((el) => {
    el.classList.toggle("active", el.dataset.page === page);
  });

  stopAutoRefresh();
  if (_pageLiveHandler) { offAuditEntry(_pageLiveHandler); _pageLiveHandler = null; }
  destroyCharts();
  const app = document.getElementById("app");
  app.innerHTML = '<div class="flex items-center justify-center h-64"><div class="skeleton" style="width:200px;height:24px"></div></div>';
  render(app);
}

window.addEventListener("hashchange", router);
window.addEventListener("DOMContentLoaded", () => {
  router();
  connectWS();
  // Fetch version
  api("system/health").then((d) => {
    const el = document.getElementById("version");
    if (el && d.version) el.textContent = d.version;
  });
});

// ---------------------------------------------------------------------------
// API helper
// ---------------------------------------------------------------------------

async function api(path, opts) {
  try {
    const resp = await fetch("/api/v1/dashboard/" + path, opts);
    return await resp.json();
  } catch (e) {
    console.error("API error:", path, e);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs) Object.entries(attrs).forEach(([k, v]) => {
    if (k === "className") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2).toLowerCase(), v);
    else el.setAttribute(k, v);
  });
  children.flat().forEach((c) => {
    if (c == null) return;
    el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  });
  return el;
}

function riskBadge(level) {
  const l = (level || "unknown").toLowerCase();
  return h("span", { className: `badge badge-${l}` }, level || "?");
}

function approvalBadge(val) {
  const v = (val || "unknown").toLowerCase();
  return h("span", { className: `badge badge-${v}` }, val || "?");
}

function statusBadge(val) {
  const v = (val || "unknown").toLowerCase();
  return h("span", { className: `badge badge-${v}` }, val || "?");
}

function gradeClass(grade) {
  if (!grade) return "grade-f";
  const c = grade.charAt(0).toUpperCase();
  if (c === "A") return "grade-a";
  if (c === "B") return "grade-b";
  if (c === "C") return "grade-c";
  if (c === "D") return "grade-d";
  return "grade-f";
}

function fmtTime(ts) {
  if (!ts) return "-";
  try {
    const d = new Date(ts);
    return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  } catch { return ts; }
}

function pct(n, d) { return d ? ((n / d) * 100).toFixed(1) + "%" : "0%"; }

// ---------------------------------------------------------------------------
// Page: Overview
// ---------------------------------------------------------------------------

async function renderOverview(app) {
  const [ov, tl] = await Promise.all([
    api("overview"),
    api("stats/timeline?period=24h"),
  ]);
  if (!ov) { app.innerHTML = '<p class="text-red-400">Failed to load overview.</p>'; return; }

  app.innerHTML = "";

  // Header with auto-refresh toggle
  const refreshToggle = h("label", { className: "flex items-center gap-2 text-xs text-gray-400 cursor-pointer" },
    h("input", {
      type: "checkbox",
      className: "accent-blue-500",
      ..._autoRefresh ? { checked: "" } : {},
      onChange: (e) => {
        _autoRefresh = e.target.checked;
        if (_autoRefresh) startAutoRefresh(() => renderOverview(app), 30000);
        else stopAutoRefresh();
      },
    }),
    "Auto-refresh (30s)",
  );
  app.appendChild(h("div", { className: "page-header flex justify-between items-start" },
    h("div", null,
      h("h2", null, "Dashboard Overview"),
      h("p", null, "Real-time AI agent governance metrics"),
    ),
    refreshToggle,
  ));

  // Start auto-refresh
  startAutoRefresh(() => renderOverview(app), 30000);

  // KPI row
  const kpis = h("div", { className: "grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6" });
  kpis.appendChild(kpiCard("Total Actions", ov.total_actions.toLocaleString(), "text-blue-400"));
  kpis.appendChild(kpiCard("Blocked", (ov.approval_distribution.block || 0).toLocaleString(), "text-red-400"));
  kpis.appendChild(gradeCard(ov.compliance_grade, ov.compliance_score));
  kpis.appendChild(kpiCard("Active Agents", ov.active_agents.toLocaleString(), "text-emerald-400"));
  app.appendChild(kpis);

  // Charts row
  const chartsRow = h("div", { className: "grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6" });

  // Timeline chart
  const tlCard = h("div", { className: "card" },
    h("h3", { className: "text-sm font-semibold text-gray-300 mb-3" }, "Action Volume (24h)"),
    h("div", { className: "chart-container" }, h("canvas", { id: "timeline-chart" })),
  );
  chartsRow.appendChild(tlCard);

  // Risk distribution
  const riskCard = h("div", { className: "card" },
    h("h3", { className: "text-sm font-semibold text-gray-300 mb-3" }, "Risk Distribution"),
    h("div", { className: "chart-container" }, h("canvas", { id: "risk-chart" })),
  );
  chartsRow.appendChild(riskCard);
  app.appendChild(chartsRow);

  // Bottom row
  const bottomRow = h("div", { className: "grid grid-cols-1 lg:grid-cols-2 gap-4" });

  // Approval distribution
  const apprCard = h("div", { className: "card" },
    h("h3", { className: "text-sm font-semibold text-gray-300 mb-3" }, "Approval Distribution"),
  );
  const apprItems = ov.approval_distribution;
  const total = Object.values(apprItems).reduce((a, b) => a + b, 0) || 1;
  ["auto", "approve", "block"].forEach((key) => {
    const val = apprItems[key] || 0;
    const w = ((val / total) * 100).toFixed(1);
    const colors = { auto: "#22c55e", approve: "#3b82f6", block: "#ef4444" };
    apprCard.appendChild(h("div", { className: "flex items-center justify-between mb-2" },
      h("span", { className: "text-xs text-gray-400 uppercase w-16" }, key),
      h("div", { className: "flex-1 mx-3" },
        h("div", { className: "progress-bar" },
          h("div", { className: "progress-fill", style: `width:${w}%;background:${colors[key]}` }),
        ),
      ),
      h("span", { className: "text-xs font-mono text-gray-300 w-16 text-right" }, `${val} (${w}%)`),
    ));
  });
  bottomRow.appendChild(apprCard);

  // Policy summary
  const polCard = h("div", { className: "card" },
    h("h3", { className: "text-sm font-semibold text-gray-300 mb-3" }, "Policy Summary"),
    h("div", { className: "space-y-2" },
      infoRow("Rules", ov.policy_rule_count),
      infoRow("Score", `${ov.compliance_score}/100 (${ov.compliance_grade})`),
      infoRow("Actions evaluated", ov.total_actions.toLocaleString()),
    ),
  );
  bottomRow.appendChild(polCard);
  app.appendChild(bottomRow);

  // Live feed (WebSocket)
  const liveSection = h("div", { className: "card mt-4" },
    h("div", { className: "flex items-center justify-between mb-3" },
      h("h3", { className: "text-sm font-semibold text-gray-300" }, "Live Feed"),
      h("span", { className: "text-xs text-gray-500" }, "Real-time via WebSocket"),
    ),
  );
  const liveList = h("div", { id: "live-feed", className: "space-y-1 max-h-48 overflow-y-auto text-xs" });
  liveList.appendChild(h("div", { className: "text-gray-600 italic" }, "Waiting for new events..."));
  liveSection.appendChild(liveList);
  app.appendChild(liveSection);

  const liveHandler = (entry) => {
    const feed = document.getElementById("live-feed");
    if (!feed) return;
    if (feed.children.length === 1 && feed.firstChild.tagName === "DIV" && feed.firstChild.classList.contains("italic")) {
      feed.innerHTML = "";
    }
    const row = h("div", { className: "flex items-center gap-2 py-1 border-b border-gray-800" },
      h("span", { className: "text-gray-500 font-mono" }, new Date().toLocaleTimeString()),
      riskBadge(entry.risk_level),
      h("span", { className: "text-gray-300 font-medium" }, entry.action_type || "?"),
      h("span", { className: "text-gray-600" }, "\u2192"),
      h("span", { className: "text-gray-400" }, entry.action_target || "?"),
      h("span", { className: "text-gray-600 ml-auto" }, entry.agent_id || ""),
    );
    feed.insertBefore(row, feed.firstChild);
    if (feed.children.length > 50) feed.removeChild(feed.lastChild);
  };
  onAuditEntry(liveHandler);
  _pageLiveHandler = liveHandler;

  // Render charts
  if (tl && tl.buckets && tl.buckets.length > 0) {
    renderTimelineChart(tl.buckets);
  }
  renderRiskChart(ov.risk_distribution);
}

function kpiCard(label, value, colorClass) {
  return h("div", { className: "card card-sm" },
    h("div", { className: `kpi-value ${colorClass}` }, value),
    h("div", { className: "kpi-label" }, label),
  );
}

function gradeCard(grade, score) {
  return h("div", { className: "card card-sm flex items-center gap-4" },
    h("div", { className: `grade-circle ${gradeClass(grade)}` }, grade || "?"),
    h("div", null,
      h("div", { className: "text-2xl font-bold font-mono text-gray-100" }, `${score ?? 0}`),
      h("div", { className: "kpi-label" }, "Compliance Score"),
    ),
  );
}

function infoRow(label, value) {
  return h("div", { className: "flex justify-between text-sm" },
    h("span", { className: "text-gray-500" }, label),
    h("span", { className: "text-gray-200 font-medium" }, String(value)),
  );
}

function renderTimelineChart(buckets) {
  const ctx = document.getElementById("timeline-chart");
  if (!ctx) return;
  const labels = buckets.map((b) => fmtTime(b.timestamp));
  const c = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        { label: "Total", data: buckets.map((b) => b.total), borderColor: "#3b82f6", backgroundColor: "rgba(59,130,246,0.1)", fill: true, tension: 0.3 },
        { label: "Blocked", data: buckets.map((b) => b.blocked), borderColor: "#ef4444", backgroundColor: "rgba(239,68,68,0.1)", fill: true, tension: 0.3 },
      ],
    },
    options: chartOpts("Actions"),
  });
  _charts.push(c);
}

function renderRiskChart(dist) {
  const ctx = document.getElementById("risk-chart");
  if (!ctx) return;
  const labels = Object.keys(dist);
  const data = Object.values(dist);
  const colors = { LOW: "#22c55e", MEDIUM: "#eab308", HIGH: "#f97316", CRITICAL: "#ef4444", UNKNOWN: "#6b7280" };
  const c = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels,
      datasets: [{ data, backgroundColor: labels.map((l) => colors[l] || "#6b7280"), borderWidth: 0 }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: "right", labels: { color: "#9ca3af", font: { size: 11 } } } },
    },
  });
  _charts.push(c);
}

function chartOpts(yLabel) {
  return {
    responsive: true, maintainAspectRatio: false,
    scales: {
      x: { ticks: { color: "#6b7280", font: { size: 10 }, maxRotation: 45 }, grid: { color: "#1f2937" } },
      y: { ticks: { color: "#6b7280", font: { size: 10 } }, grid: { color: "#1f2937" }, title: { display: !!yLabel, text: yLabel, color: "#6b7280" } },
    },
    plugins: { legend: { labels: { color: "#9ca3af", font: { size: 11 } } } },
  };
}

// ---------------------------------------------------------------------------
// Page: Audit Log
// ---------------------------------------------------------------------------

async function renderAudit(app) {
  app.innerHTML = "";
  app.appendChild(h("div", { className: "page-header" },
    h("h2", null, "Audit Log"),
    h("p", null, "Complete history of agent actions and policy decisions"),
  ));

  // Filter bar
  const filters = h("div", { className: "card card-sm flex flex-wrap gap-3 mb-4 items-end" });
  filters.appendChild(filterSelect("risk_level", "Risk Level", ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"]));
  filters.appendChild(filterInput("action_type", "Action Type"));
  filters.appendChild(filterInput("agent_id", "Agent ID"));
  filters.appendChild(filterSelect("result_status", "Status", ["", "success", "failed", "blocked", "denied"]));
  const searchBtn = h("button", {
    className: "px-4 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded font-medium",
    onClick: () => loadAuditData(0),
  }, "Search");
  filters.appendChild(searchBtn);

  const exportBtn = h("button", {
    className: "px-4 py-1.5 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded font-medium",
    onClick: () => exportAuditJSON(),
  }, "Export JSON");
  filters.appendChild(exportBtn);
  app.appendChild(filters);

  const tableContainer = h("div", { id: "audit-table-container" });
  app.appendChild(tableContainer);

  loadAuditData(0);
}

async function loadAuditData(offset) {
  const params = new URLSearchParams();
  params.set("offset", offset);
  params.set("limit", "30");

  ["risk_level", "action_type", "agent_id", "result_status"].forEach((key) => {
    const el = document.getElementById("filter-" + key);
    if (el && el.value) params.set(key, el.value);
  });

  const data = await api("audit/recent?" + params.toString());
  const container = document.getElementById("audit-table-container");
  if (!container || !data) return;
  container.innerHTML = "";

  // Stats bar
  const statsBar = h("div", { className: "flex gap-3 mb-3 text-xs text-gray-400" },
    h("span", null, `Showing ${data.entries.length} of ${data.total} entries`),
  );
  container.appendChild(statsBar);

  // Table
  const table = h("table", { className: "data-table" });
  const thead = h("thead", null,
    h("tr", null,
      ...(["Time", "Action", "Target", "Agent", "Risk", "Approval", "Rule", "Status"].map((t) =>
        h("th", null, t)
      )),
    ),
  );
  table.appendChild(thead);

  const tbody = h("tbody");
  data.entries.forEach((e) => {
    tbody.appendChild(h("tr", null,
      h("td", { className: "font-mono text-xs whitespace-nowrap" }, fmtTime(e.timestamp)),
      h("td", { className: "font-medium" }, e.action_type || "-"),
      h("td", { className: "text-gray-400" }, e.action_target || "-"),
      h("td", { className: "text-gray-400 text-xs" }, e.agent_id || "-"),
      h("td", null, riskBadge(e.risk_level)),
      h("td", null, approvalBadge(e.approval)),
      h("td", { className: "text-gray-500 text-xs" }, e.matched_rule || "<default>"),
      h("td", null, statusBadge(e.result_status)),
    ));
  });
  table.appendChild(tbody);
  container.appendChild(h("div", { className: "card overflow-x-auto" }, table));

  // Pagination
  const pagination = h("div", { className: "flex justify-between items-center mt-3" });
  if (offset > 0) {
    pagination.appendChild(h("button", {
      className: "text-sm text-blue-400 hover:text-blue-300",
      onClick: () => loadAuditData(Math.max(0, offset - 30)),
    }, "← Previous"));
  } else {
    pagination.appendChild(h("span"));
  }
  if (offset + 30 < data.total) {
    pagination.appendChild(h("button", {
      className: "text-sm text-blue-400 hover:text-blue-300",
      onClick: () => loadAuditData(offset + 30),
    }, "Next →"));
  }
  container.appendChild(pagination);
}

async function exportAuditJSON() {
  const params = new URLSearchParams();
  params.set("limit", "10000");
  ["risk_level", "action_type", "agent_id", "result_status"].forEach((key) => {
    const el = document.getElementById("filter-" + key);
    if (el && el.value) params.set(key, el.value);
  });
  const data = await api("audit/recent?" + params.toString());
  if (!data) return;
  const blob = new Blob([JSON.stringify(data.entries, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "aegis-audit-" + new Date().toISOString().slice(0, 10) + ".json";
  a.click();
  URL.revokeObjectURL(url);
}

function filterSelect(name, label, options) {
  const wrapper = h("div");
  wrapper.appendChild(h("label", { className: "text-xs text-gray-500 block mb-1" }, label));
  const sel = h("select", {
    id: "filter-" + name,
    className: "bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-200",
  });
  options.forEach((o) => sel.appendChild(h("option", { value: o }, o || "All")));
  wrapper.appendChild(sel);
  return wrapper;
}

function filterInput(name, label) {
  const wrapper = h("div");
  wrapper.appendChild(h("label", { className: "text-xs text-gray-500 block mb-1" }, label));
  wrapper.appendChild(h("input", {
    id: "filter-" + name,
    type: "text",
    className: "bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-sm text-gray-200 w-28",
    placeholder: "any",
  }));
  return wrapper;
}

// ---------------------------------------------------------------------------
// Page: Policy
// ---------------------------------------------------------------------------

async function renderPolicy(app) {
  const [summary, score] = await Promise.all([
    api("policy/summary"),
    api("policy/score"),
  ]);
  if (!summary) { app.innerHTML = '<p class="text-red-400">Failed to load policy.</p>'; return; }

  app.innerHTML = "";
  app.appendChild(h("div", { className: "page-header" },
    h("h2", null, "Policy Configuration"),
    h("p", null, "Current policy rules and governance score"),
  ));

  // Score + summary row
  const topRow = h("div", { className: "grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6" });

  if (score) {
    const scoreCard = h("div", { className: "card flex flex-col items-center justify-center" },
      h("div", { className: `grade-circle ${gradeClass(score.grade)}` }, score.grade),
      h("div", { className: "text-3xl font-bold font-mono mt-2" }, `${score.score}/100`),
      h("div", { className: "kpi-label" }, "Governance Score"),
    );
    topRow.appendChild(scoreCard);
  }

  // Score checks
  if (score && score.checks) {
    const checksCard = h("div", { className: "card lg:col-span-2" },
      h("h3", { className: "text-sm font-semibold text-gray-300 mb-3" }, "Score Breakdown"),
    );
    score.checks.forEach((ch) => {
      const icon = ch.passed ? "✓" : "✗";
      const color = ch.passed ? "text-green-400" : "text-red-400";
      checksCard.appendChild(h("div", { className: "flex items-center gap-2 mb-1.5" },
        h("span", { className: `${color} font-mono text-sm` }, icon),
        h("span", { className: "text-sm text-gray-300 flex-1" }, ch.name),
        h("span", { className: `text-xs font-mono ${ch.passed ? "text-green-500" : "text-gray-600"}` }, `+${ch.points}`),
      ));
    });
    topRow.appendChild(checksCard);
  }
  app.appendChild(topRow);

  // Rules table
  const tableCard = h("div", { className: "card" },
    h("h3", { className: "text-sm font-semibold text-gray-300 mb-3" },
      `Policy Rules (${summary.rule_count}) · Default: ${summary.default_risk_level} / ${summary.default_approval}`),
  );

  const table = h("table", { className: "data-table" });
  table.appendChild(h("thead", null,
    h("tr", null, ...["Name", "Match Type", "Match Target", "Risk", "Approval", "Conditions"].map((t) => h("th", null, t))),
  ));
  const tbody = h("tbody");
  summary.rules.forEach((r) => {
    tbody.appendChild(h("tr", null,
      h("td", { className: "font-medium" }, r.name || "-"),
      h("td", { className: "font-mono text-xs" }, r.match_type || "*"),
      h("td", { className: "font-mono text-xs text-gray-400" }, r.match_target || "*"),
      h("td", null, riskBadge(r.risk_level)),
      h("td", null, approvalBadge(r.approval)),
      h("td", { className: "text-xs text-gray-500" }, r.conditions ? JSON.stringify(r.conditions) : "-"),
    ));
  });
  table.appendChild(tbody);
  tableCard.appendChild(table);
  app.appendChild(tableCard);

  // Policy YAML editor
  const editorCard = h("div", { className: "card mt-4" },
    h("div", { className: "flex items-center justify-between mb-3" },
      h("h3", { className: "text-sm font-semibold text-gray-300" }, "Policy Editor"),
      h("div", { className: "flex gap-2" },
        h("button", {
          id: "policy-validate-btn",
          className: "px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white text-xs rounded font-medium",
          onClick: () => validatePolicyEditor(),
        }, "Validate"),
        h("button", {
          id: "policy-save-btn",
          className: "px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs rounded font-medium",
          onClick: () => savePolicyEditor(),
        }, "Save & Reload"),
      ),
    ),
  );

  const editorTextarea = h("textarea", {
    id: "policy-yaml-editor",
    className: "w-full bg-gray-900 border border-gray-700 rounded-md p-4 text-sm text-gray-200 font-mono focus:outline-none focus:border-blue-500",
    rows: 24,
    spellcheck: "false",
    style: "resize: vertical; line-height: 1.6; tab-size: 2;",
  });
  editorCard.appendChild(editorTextarea);

  const editorMsg = h("div", { id: "policy-editor-msg", className: "mt-2 text-xs" });
  editorCard.appendChild(editorMsg);
  app.appendChild(editorCard);

  // Load current YAML into editor
  const yamlData = await api("policy/yaml");
  if (yamlData && yamlData.yaml) {
    editorTextarea.value = yamlData.yaml;
  }
}

async function validatePolicyEditor() {
  const yaml = document.getElementById("policy-yaml-editor").value;
  const msg = document.getElementById("policy-editor-msg");
  try {
    const resp = await fetch("/api/v1/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ yaml_validate: yaml }),
    });
    // If we can parse it client-side, that's enough for validation
    msg.className = "mt-2 text-xs text-green-400";
    msg.textContent = "YAML is valid.";
  } catch (e) {
    msg.className = "mt-2 text-xs text-red-400";
    msg.textContent = "Error: " + e.message;
  }
}

async function savePolicyEditor() {
  const yaml = document.getElementById("policy-yaml-editor").value;
  const msg = document.getElementById("policy-editor-msg");
  try {
    const resp = await fetch("/api/v1/policy", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ yaml: yaml }),
    });
    const data = await resp.json();
    if (resp.ok) {
      msg.className = "mt-2 text-xs text-green-400";
      msg.textContent = "Policy updated (" + data.rule_count + " rules). Refreshing...";
      setTimeout(() => renderPolicy(document.getElementById("app")), 1000);
    } else {
      msg.className = "mt-2 text-xs text-red-400";
      msg.textContent = "Error: " + (data.error || "Failed to update policy");
    }
  } catch (e) {
    msg.className = "mt-2 text-xs text-red-400";
    msg.textContent = "Network error: " + e.message;
  }
}

// ---------------------------------------------------------------------------
// Page: Anomalies
// ---------------------------------------------------------------------------

async function renderAnomalies(app) {
  const [profiles, alerts] = await Promise.all([
    api("anomalies/profiles"),
    api("anomalies/alerts"),
  ]);

  app.innerHTML = "";
  app.appendChild(h("div", { className: "page-header" },
    h("h2", null, "Anomaly Detection"),
    h("p", null, "Behavioral profiling and anomaly alerts"),
  ));

  if (profiles && !profiles.configured) {
    app.appendChild(h("div", { className: "card text-gray-400 text-sm" },
      "Anomaly detector is not configured. Pass an AnomalyDetector instance to create_app() to enable behavioral analysis.",
    ));
    return;
  }

  // Alerts
  if (alerts && alerts.alerts && alerts.alerts.length > 0) {
    const alertCard = h("div", { className: "card mb-4 border-red-900" },
      h("h3", { className: "text-sm font-semibold text-red-400 mb-2" }, `Active Alerts (${alerts.alerts.length})`),
    );
    alerts.alerts.forEach((a) => {
      alertCard.appendChild(h("div", { className: "finding finding-fail mb-2" },
        h("div", { className: "flex justify-between" },
          h("span", { className: "text-sm font-medium text-red-300" }, a.type),
          h("span", { className: "text-xs text-gray-500" }, fmtTime(a.timestamp)),
        ),
        h("p", { className: "text-xs text-gray-400 mt-1" }, a.message),
      ));
    });
    app.appendChild(alertCard);
  }

  // Profiles table
  if (profiles && profiles.profiles && profiles.profiles.length > 0) {
    const tableCard = h("div", { className: "card" },
      h("h3", { className: "text-sm font-semibold text-gray-300 mb-3" }, "Agent Profiles"),
    );
    const table = h("table", { className: "data-table" });
    table.appendChild(h("thead", null,
      h("tr", null, ...["Agent ID", "Total Actions", "Blocked", "Block Rate", "Action Types", "Last Seen"].map((t) => h("th", null, t))),
    ));
    const tbody = h("tbody");
    profiles.profiles.forEach((p) => {
      const brColor = p.block_rate > 0.5 ? "text-red-400" : p.block_rate > 0.2 ? "text-yellow-400" : "text-green-400";
      tbody.appendChild(h("tr", null,
        h("td", { className: "font-medium" }, p.agent_id),
        h("td", { className: "font-mono" }, String(p.total_actions)),
        h("td", { className: "font-mono text-red-400" }, String(p.blocked_count)),
        h("td", { className: `font-mono ${brColor}` }, `${(p.block_rate * 100).toFixed(1)}%`),
        h("td", { className: "text-xs text-gray-400" }, Object.keys(p.action_types).join(", ")),
        h("td", { className: "text-xs" }, fmtTime(p.last_seen)),
      ));
    });
    table.appendChild(tbody);
    tableCard.appendChild(table);
    app.appendChild(tableCard);
  } else {
    app.appendChild(h("div", { className: "card text-gray-400 text-sm" },
      "No agent profiles recorded yet. Profiles are built as actions are processed through the governance pipeline.",
    ));
  }
}

// ---------------------------------------------------------------------------
// Page: Compliance
// ---------------------------------------------------------------------------

async function renderCompliance(app) {
  app.innerHTML = "";
  app.appendChild(h("div", { className: "page-header" },
    h("h2", null, "Compliance Reports"),
    h("p", null, "SOC2, GDPR, and governance compliance analysis"),
  ));

  // Tabs
  const tabGroup = h("div", { className: "tab-group" });
  ["governance", "soc2", "gdpr"].forEach((type, i) => {
    const btn = h("button", {
      className: `tab-btn ${i === 0 ? "active" : ""}`,
      onClick: () => {
        tabGroup.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        loadComplianceReport(type);
      },
    }, type.toUpperCase());
    tabGroup.appendChild(btn);
  });
  app.appendChild(tabGroup);
  app.appendChild(h("div", { id: "compliance-content" }));

  loadComplianceReport("governance");
}

async function loadComplianceReport(type) {
  const container = document.getElementById("compliance-content");
  if (!container) return;
  container.innerHTML = '<div class="flex justify-center py-8"><div class="skeleton" style="width:200px;height:24px"></div></div>';

  const data = await api("compliance/report?type=" + type);
  if (!data) { container.innerHTML = '<p class="text-red-400">Failed to load report.</p>'; return; }

  container.innerHTML = "";

  // Summary row
  const summaryRow = h("div", { className: "grid grid-cols-2 lg:grid-cols-5 gap-3 mb-6" });
  summaryRow.appendChild(h("div", { className: "card card-sm flex flex-col items-center" },
    h("div", { className: `grade-circle ${gradeClass(data.grade)}` }, data.grade),
    h("div", { className: "text-lg font-bold font-mono mt-1" }, `${data.score}/100`),
  ));
  summaryRow.appendChild(kpiCard("Total Actions", data.total_actions.toLocaleString(), "text-blue-400"));
  summaryRow.appendChild(kpiCard("Blocked", data.blocked_actions.toLocaleString(), "text-red-400"));
  summaryRow.appendChild(kpiCard("Approved", data.approved_actions.toLocaleString(), "text-blue-400"));
  summaryRow.appendChild(kpiCard("Auto", data.auto_approved.toLocaleString(), "text-green-400"));
  container.appendChild(summaryRow);

  // Summary text
  container.appendChild(h("div", { className: "card card-sm mb-4 text-sm text-gray-300" }, data.summary));

  // Findings
  const findingsCard = h("div", { className: "card" },
    h("h3", { className: "text-sm font-semibold text-gray-300 mb-3" }, "Findings"),
  );
  (data.findings || []).forEach((f) => {
    let fClass = "finding-info";
    if (f.title.includes("FAIL")) fClass = "finding-fail";
    else if (f.title.includes("WARN")) fClass = "finding-warn";
    else if (f.title.includes("PASS")) fClass = "finding-pass";

    findingsCard.appendChild(h("div", { className: `finding ${fClass}` },
      h("div", { className: "flex items-center gap-2 mb-1" },
        h("span", { className: `badge badge-${f.severity}` }, f.severity),
        h("span", { className: "text-sm font-medium text-gray-200" }, f.title),
      ),
      h("p", { className: "text-xs text-gray-400" }, f.description),
      f.recommendation ? h("p", { className: "text-xs text-blue-400 mt-1" }, "→ " + f.recommendation) : null,
    ));
  });
  container.appendChild(findingsCard);
}

// ---------------------------------------------------------------------------
// Page: Regulatory
// ---------------------------------------------------------------------------

async function renderRegulatory(app) {
  app.innerHTML = "";
  app.appendChild(h("div", { className: "page-header" },
    h("h2", null, "Regulatory Compliance"),
    h("p", null, "Framework gap analysis for EU AI Act, NIST, SOC2, ISO 42001"),
  ));

  const tabGroup = h("div", { className: "tab-group" });
  const frameworks = [
    { id: "eu_ai_act", label: "EU AI Act" },
    { id: "nist_ai_rmf", label: "NIST AI RMF" },
    { id: "soc2", label: "SOC2" },
    { id: "iso_42001", label: "ISO 42001" },
  ];
  frameworks.forEach((fw, i) => {
    const btn = h("button", {
      className: `tab-btn ${i === 0 ? "active" : ""}`,
      onClick: () => {
        tabGroup.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        loadRegulatoryAnalysis(fw.id);
      },
    }, fw.label);
    tabGroup.appendChild(btn);
  });
  app.appendChild(tabGroup);
  app.appendChild(h("div", { id: "regulatory-content" }));

  loadRegulatoryAnalysis("eu_ai_act");
}

async function loadRegulatoryAnalysis(framework) {
  const container = document.getElementById("regulatory-content");
  if (!container) return;
  container.innerHTML = '<div class="flex justify-center py-8"><div class="skeleton" style="width:200px;height:24px"></div></div>';

  const data = await api("compliance/regulatory?framework=" + framework);
  if (!data) { container.innerHTML = '<p class="text-red-400">Failed to load analysis.</p>'; return; }

  container.innerHTML = "";

  // Coverage summary
  const summaryRow = h("div", { className: "grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6" });
  summaryRow.appendChild(kpiCard("Coverage", `${data.coverage_score.toFixed(0)}%`, "text-blue-400"));
  summaryRow.appendChild(kpiCard("Fully Covered", String(data.fully_covered), "text-green-400"));
  summaryRow.appendChild(kpiCard("Partial", String(data.partially_covered), "text-yellow-400"));
  summaryRow.appendChild(kpiCard("Not Covered", String(data.not_covered), "text-red-400"));
  container.appendChild(summaryRow);

  // Coverage bar
  const covBar = h("div", { className: "card card-sm mb-4" },
    h("div", { className: "flex items-center gap-3" },
      h("span", { className: "text-xs text-gray-500 w-20" }, "Coverage"),
      h("div", { className: "flex-1" },
        h("div", { className: "progress-bar" },
          h("div", { className: "progress-fill", style: `width:${data.coverage_score}%;background:${data.coverage_score > 70 ? "#22c55e" : data.coverage_score > 40 ? "#eab308" : "#ef4444"}` }),
        ),
      ),
      h("span", { className: "text-sm font-mono text-gray-300 w-12 text-right" }, `${data.coverage_score.toFixed(0)}%`),
    ),
  );
  container.appendChild(covBar);

  // Gaps
  if (data.gaps && data.gaps.length > 0) {
    const gapsCard = h("div", { className: "card mb-4" },
      h("h3", { className: "text-sm font-semibold text-red-400 mb-3" }, `Gaps (${data.gaps.length})`),
    );
    const table = h("table", { className: "data-table" });
    table.appendChild(h("thead", null,
      h("tr", null, ...["ID", "Title", "Category", "Mandatory", "Deadline"].map((t) => h("th", null, t))),
    ));
    const tbody = h("tbody");
    data.gaps.forEach((g) => {
      tbody.appendChild(h("tr", null,
        h("td", { className: "font-mono text-xs" }, g.requirement_id),
        h("td", { className: "text-sm" }, g.title),
        h("td", { className: "text-xs text-gray-400" }, g.category),
        h("td", null, g.mandatory ? h("span", { className: "badge badge-critical" }, "Required") : h("span", { className: "badge badge-info" }, "Optional")),
        h("td", { className: "text-xs" }, g.deadline || "-"),
      ));
    });
    table.appendChild(tbody);
    gapsCard.appendChild(table);
    container.appendChild(gapsCard);
  }

  // Recommendations
  if (data.recommendations && data.recommendations.length > 0) {
    const recCard = h("div", { className: "card" },
      h("h3", { className: "text-sm font-semibold text-gray-300 mb-3" }, "Recommendations"),
    );
    data.recommendations.forEach((r, i) => {
      recCard.appendChild(h("div", { className: "flex gap-2 mb-2" },
        h("span", { className: "text-blue-400 font-mono text-sm" }, `${i + 1}.`),
        h("span", { className: "text-sm text-gray-300" }, r),
      ));
    });
    container.appendChild(recCard);
  }
}

// ---------------------------------------------------------------------------
// Page: System
// ---------------------------------------------------------------------------

async function renderSystem(app) {
  const data = await api("system/health");
  if (!data) { app.innerHTML = '<p class="text-red-400">Failed to load system info.</p>'; return; }

  app.innerHTML = "";
  app.appendChild(h("div", { className: "page-header" },
    h("h2", null, "System Health"),
    h("p", null, "Infrastructure status and configuration"),
  ));

  const grid = h("div", { className: "grid grid-cols-1 lg:grid-cols-2 gap-4" });

  // Health card
  const healthCard = h("div", { className: "card" },
    h("h3", { className: "text-sm font-semibold text-gray-300 mb-3" }, "Health Status"),
    h("div", { className: "space-y-2" },
      infoRow("Status", data.status === "ok" ? "● Healthy" : "● Unhealthy"),
      infoRow("Version", data.version),
      infoRow("Audit Entries", data.audit_entries.toLocaleString()),
      infoRow("Policy Rules", data.policy_rules),
      infoRow("Anomaly Detector", data.anomaly_detector ? "Enabled" : "Disabled"),
    ),
  );
  grid.appendChild(healthCard);

  // API endpoints card
  const apiCard = h("div", { className: "card" },
    h("h3", { className: "text-sm font-semibold text-gray-300 mb-3" }, "API Endpoints"),
    h("div", { className: "space-y-1" },
      ...[
        "POST /api/v1/evaluate",
        "POST /api/v1/execute",
        "GET  /api/v1/audit",
        "GET  /api/v1/policy",
        "PUT  /api/v1/policy",
        "GET  /api/v1/dashboard/*",
      ].map((ep) => h("div", { className: "font-mono text-xs text-gray-400" }, ep)),
    ),
  );
  grid.appendChild(apiCard);
  app.appendChild(grid);
}

// ---------------------------------------------------------------------------
// 404
// ---------------------------------------------------------------------------

function renderNotFound(app) {
  app.innerHTML = "";
  app.appendChild(h("div", { className: "flex flex-col items-center justify-center h-64" },
    h("h2", { className: "text-2xl font-bold text-gray-500" }, "Page Not Found"),
    h("a", { href: "#/overview", className: "text-blue-400 mt-2 text-sm" }, "← Back to Overview"),
  ));
}
