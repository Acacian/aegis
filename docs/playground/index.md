---
description: "Interactive Aegis policy playground: write YAML policies, fire test actions, and see real-time governance decisions in your browser. No install needed."
title: Policy Playground
hide:
  - navigation
  - toc
---

<style>
  .md-content { max-width: 100%; padding: 0; }
  .md-main__inner { margin: 0; padding: 0; }
  .pg-wrap { background: #0a0f1a; padding: 24px; min-height: calc(100vh - 60px); }
  .pg-header h1 { font-size: 1.5rem; font-weight: 700; color: #fff; margin: 0 0 4px; }
  .pg-header p { color: #9ca3af; font-size: 0.875rem; margin: 0; }
  .pg-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-top: 20px; }
  @media (max-width: 1024px) { .pg-grid { grid-template-columns: 1fr; } }
  .pg-editor { background: #111827; border: 1px solid #1f2937; border-radius: 8px; }
  .pg-editor textarea {
    width: 100%; padding: 16px; background: transparent; border: none; color: #e5e7eb;
    font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.85rem;
    resize: none; outline: none; line-height: 1.6;
  }
  .pg-panel { background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 16px; }
  .pg-input {
    width: 100%; padding: 8px 12px; background: #1f2937; border: 1px solid #374151;
    border-radius: 6px; color: #e5e7eb; font-size: 0.85rem;
    font-family: 'JetBrains Mono', 'Fira Code', monospace; outline: none;
  }
  .pg-input:focus { border-color: #2563eb; }
  .pg-label { display: block; font-size: 0.75rem; color: #6b7280; margin-bottom: 4px; }
  .pg-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }
  .pg-btn-primary {
    background: #2563eb; color: #fff; border: none; border-radius: 8px;
    padding: 10px 20px; font-weight: 600; font-size: 0.875rem; cursor: pointer; flex: 1;
  }
  .pg-btn-primary:hover { background: #1d4ed8; }
  .pg-btn-secondary {
    background: #4f46e5; color: #fff; border: none; border-radius: 8px;
    padding: 10px 20px; font-weight: 600; font-size: 0.875rem; cursor: pointer; flex: 1;
  }
  .pg-btn-secondary:hover { background: #4338ca; }
  .pg-btn-row { display: flex; gap: 12px; }
  .pg-example {
    background: #1f2937; border: 1px solid #374151; border-radius: 6px;
    padding: 5px 12px; font-size: 0.75rem; cursor: pointer; color: #9ca3af;
  }
  .pg-example:hover { background: #374151; color: #e5e7eb; }
  .pg-examples { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-top: 16px; }
  .pg-result {
    background: #111827; border: 1px solid #1f2937; border-radius: 8px;
    padding: 16px; margin-bottom: 12px; transition: border-color 0.2s;
  }
  .pg-result:hover { border-color: #374151; }
  .pg-result-blocked { border-color: #991b1b; box-shadow: 0 0 20px rgba(153,27,27,0.15); }
  .pg-badge {
    display: inline-block; padding: 2px 10px; border-radius: 9999px;
    font-size: 0.7rem; font-weight: 600; text-transform: uppercase;
  }
  .pg-badge-low { background: #064e3b; color: #6ee7b7; }
  .pg-badge-medium { background: #78350f; color: #fcd34d; }
  .pg-badge-high { background: #7c2d12; color: #fb923c; }
  .pg-badge-critical { background: #7f1d1d; color: #fca5a5; }
  .pg-badge-auto { background: #1e3a5f; color: #93c5fd; }
  .pg-badge-approve { background: #3b2f63; color: #c4b5fd; }
  .pg-badge-block { background: #7f1d1d; color: #fca5a5; }
  .pg-allowed { color: #6ee7b7; font-weight: 700; }
  .pg-denied { color: #fca5a5; font-weight: 700; }
  .pg-error { background: #450a0a; border: 1px solid #991b1b; border-radius: 8px; padding: 12px; color: #fca5a5; font-size: 0.85rem; }
  .pg-result-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
  .pg-result-meta { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; font-size: 0.85rem; }
  .pg-result-meta span.lbl { display: block; font-size: 0.7rem; color: #6b7280; margin-bottom: 2px; }
  .pg-summary { text-align: center; padding: 10px; font-size: 0.85rem; }
  .pg-how { margin-top: 24px; }
  .pg-how summary { font-size: 0.875rem; font-weight: 600; color: #d1d5db; cursor: pointer; }
  .pg-how-body { margin-top: 12px; font-size: 0.85rem; color: #9ca3af; line-height: 1.7; }
  .pg-how-body ul { margin: 8px 0 8px 20px; }
  .pg-how-body li { margin-bottom: 4px; }
</style>

<div class="pg-wrap">
  <div class="pg-header">
    <h1>Aegis Policy Playground</h1>
    <p>Write YAML policies, test actions, see decisions — entirely in your browser. Press <kbd>Ctrl+Enter</kbd> to evaluate.</p>
  </div>

  <div class="pg-grid">
    <!-- Left: Editor -->
    <div>
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
        <span style="font-size:0.85rem;font-weight:600;color:#d1d5db;">Policy (YAML)</span>
        <button onclick="pgReset()" style="font-size:0.7rem;color:#6b7280;background:none;border:none;cursor:pointer;">Reset</button>
      </div>
      <div class="pg-editor">
        <textarea id="pg-policy" rows="28" spellcheck="false"></textarea>
      </div>
      <div id="pg-yaml-err" style="margin-top:8px;"></div>
    </div>

    <!-- Right: Action + Results -->
    <div>
      <div class="pg-panel">
        <div style="font-size:0.85rem;font-weight:600;color:#d1d5db;margin-bottom:12px;">Action</div>
        <div class="pg-row">
          <div><label class="pg-label">Action Type</label><input class="pg-input" id="pg-type" value="read_users"></div>
          <div><label class="pg-label">Target</label><input class="pg-input" id="pg-target" value="database"></div>
        </div>
        <div style="margin-bottom:12px;"><label class="pg-label">Parameters (JSON)</label><input class="pg-input" id="pg-params" value="{}"></div>
        <div class="pg-btn-row">
          <button class="pg-btn-primary" onclick="pgEval()">Evaluate</button>
          <button class="pg-btn-secondary" onclick="pgBatch()">Run Common Actions</button>
        </div>
      </div>

      <div class="pg-examples">
        <span style="font-size:0.75rem;color:#6b7280;">Try:</span>
        <button class="pg-example" onclick="pgSet('read_users','crm','{}')">read_users</button>
        <button class="pg-example" onclick="pgSet('write_config','database','{}')">write_config</button>
        <button class="pg-example" onclick="pgSet('bulk_update','crm','{&quot;count&quot;: 200}')">bulk_update</button>
        <button class="pg-example" onclick="pgSet('delete_all','storage','{}')">delete_all</button>
        <button class="pg-example" onclick="pgSet('deploy_prod','api','{}')">deploy_prod</button>
        <button class="pg-example" onclick="pgSet('get_metrics','analytics','{}')">get_metrics</button>
      </div>

      <div id="pg-results" style="margin-top:16px; min-height:100px;"></div>
    </div>
  </div>

  <details class="pg-editor pg-how" style="padding:16px;">
    <summary class="pg-how" style="font-size:0.85rem;font-weight:600;color:#d1d5db;cursor:pointer;">How this playground works</summary>
    <div class="pg-how-body">
      <p>This playground runs <strong>entirely in your browser</strong> — no server, no Python, no install. It reimplements Aegis's core policy engine in JavaScript:</p>
      <ul>
        <li><strong>YAML parsing</strong> via js-yaml (same spec as PyYAML)</li>
        <li><strong>Glob matching</strong> via fnmatch-style patterns (*, ?, [abc])</li>
        <li><strong>First-match-wins</strong> rule evaluation (like firewall rules)</li>
        <li><strong>Conditions</strong>: param_gt, param_lt, param_eq, param_contains, weekdays, time_after, time_before</li>
        <li><strong>Risk levels</strong>: LOW → MEDIUM → HIGH → CRITICAL</li>
        <li><strong>Approval modes</strong>: AUTO (execute), APPROVE (human gate), BLOCK (deny)</li>
      </ul>
      <p>For the full engine with audit logging, framework adapters, and approval handlers: <code>pip install agent-aegis</code></p>
    </div>
  </details>
</div>

<script src="https://cdn.jsdelivr.net/npm/js-yaml@4.1.0/dist/js-yaml.min.js"></script>
<script>
const PG_DEFAULT = `version: "1"

defaults:
  risk_level: medium
  approval: approve

rules:
  # Read operations: auto-execute (low risk)
  - name: read_auto
    match:
      type: "read*"
    risk_level: low
    approval: auto

  - name: get_auto
    match:
      type: "get*"
    risk_level: low
    approval: auto

  # Write operations: require approval
  - name: write_approve
    match:
      type: "write*"
    risk_level: medium
    approval: approve

  - name: update_approve
    match:
      type: "update*"
    risk_level: medium
    approval: approve

  # Bulk operations: high risk (with condition)
  - name: bulk_high
    match:
      type: "bulk_*"
    conditions:
      param_gt:
        count: 100
    risk_level: high
    approval: approve

  # Destructive operations: always blocked
  - name: delete_block
    match:
      type: "delete*"
    risk_level: critical
    approval: block

  # Deploy: high risk, needs approval
  - name: deploy_review
    match:
      type: "deploy*"
    risk_level: high
    approval: approve
`;

function pgGlob(pattern, value) {
  let re = "^";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "*") re += ".*";
    else if (c === "?") re += ".";
    else if (c === "[") { let j = i + 1; while (j < pattern.length && pattern[j] !== "]") j++; re += "[" + pattern.slice(i+1, j) + "]"; i = j; }
    else re += c.replace(/[\\^$.|+(){}]/g, "\\$&");
  }
  return new RegExp(re + "$", "i").test(value);
}

function pgCond(cond, params) {
  if (!cond) return true;
  const checks = [
    ["param_gt", (a, b) => a > b], ["param_lt", (a, b) => a < b],
    ["param_gte", (a, b) => a >= b], ["param_lte", (a, b) => a <= b],
    ["param_eq", (a, b) => a === b],
  ];
  for (const [key, fn] of checks) {
    if (cond[key]) { for (const [k, v] of Object.entries(cond[key])) { if (params[k] === undefined || !fn(params[k], v)) return false; } }
  }
  if (cond.param_contains) { for (const [k, v] of Object.entries(cond.param_contains)) { if (typeof params[k] !== "string" || !params[k].includes(v)) return false; } }
  if (cond.param_matches) { for (const [k, v] of Object.entries(cond.param_matches)) { if (typeof params[k] !== "string" || !new RegExp(v).test(params[k])) return false; } }
  if (cond.weekdays) { const d = ["mon","tue","wed","thu","fri","sat","sun"]; const t = d[new Date().getDay() === 0 ? 6 : new Date().getDay()-1]; if (!cond.weekdays.includes(t)) return false; }
  if (cond.time_after) { if (new Date().toTimeString().slice(0,5) < cond.time_after) return false; }
  if (cond.time_before) { if (new Date().toTimeString().slice(0,5) >= cond.time_before) return false; }
  return true;
}

function pgEvalPolicy(yaml, type, target, params) {
  const doc = jsyaml.load(yaml);
  if (!doc || !doc.rules) throw new Error("Policy must have a 'rules' list.");
  const defs = doc.defaults || {};
  const dRisk = (defs.risk_level || "medium").toUpperCase();
  const dAppr = (defs.approval || "approve").toUpperCase();
  for (const r of doc.rules) {
    const m = r.match || {};
    if (m.type && !pgGlob(m.type, type)) continue;
    if (m.target && !pgGlob(m.target, target)) continue;
    if (r.conditions && !pgCond(r.conditions, params)) continue;
    const risk = (r.risk_level || dRisk).toUpperCase();
    const appr = (r.approval || dAppr).toUpperCase();
    return { matched_rule: r.name || "(unnamed)", risk_level: risk, approval: appr, allowed: appr !== "BLOCK" };
  }
  return { matched_rule: "<default>", risk_level: dRisk, approval: dAppr, allowed: dAppr !== "BLOCK" };
}

function pgCard(res, type, target) {
  const icon = res.allowed ? "&#x2705;" : "&#x1F6D1;";
  const cls = res.allowed ? "" : " pg-result-blocked";
  const st = res.allowed ? '<span class="pg-allowed">ALLOWED</span>' : '<span class="pg-denied">DENIED</span>';
  return `<div class="pg-result${cls}">
    <div class="pg-result-header"><div>${icon} <strong style="color:#fff">${type}</strong> <span style="color:#6b7280">&rarr;</span> <span style="color:#9ca3af">${target}</span></div>${st}</div>
    <div class="pg-result-meta">
      <div><span class="lbl">Risk Level</span><span class="pg-badge pg-badge-${res.risk_level.toLowerCase()}">${res.risk_level}</span></div>
      <div><span class="lbl">Approval</span><span class="pg-badge pg-badge-${res.approval.toLowerCase()}">${res.approval}</span></div>
      <div><span class="lbl">Matched Rule</span><span style="color:#d1d5db;font-family:monospace;font-size:0.8rem;">${res.matched_rule}</span></div>
    </div>
  </div>`;
}

function pgSet(t, tgt, p) {
  document.getElementById("pg-type").value = t;
  document.getElementById("pg-target").value = tgt;
  document.getElementById("pg-params").value = p;
}

function pgReset() {
  document.getElementById("pg-policy").value = PG_DEFAULT;
  document.getElementById("pg-yaml-err").innerHTML = "";
}

function pgEval() {
  const yaml = document.getElementById("pg-policy").value;
  const type = document.getElementById("pg-type").value.trim();
  const target = document.getElementById("pg-target").value.trim();
  const pStr = document.getElementById("pg-params").value.trim();
  const errEl = document.getElementById("pg-yaml-err");
  const resEl = document.getElementById("pg-results");
  if (!type) { resEl.innerHTML = '<div class="pg-error">Please enter an action type.</div>'; return; }
  let params = {};
  try { if (pStr && pStr !== "{}") params = JSON.parse(pStr); } catch(e) { resEl.innerHTML = '<div class="pg-error">Invalid JSON: ' + e.message + '</div>'; return; }
  try { errEl.innerHTML = ""; resEl.innerHTML = pgCard(pgEvalPolicy(yaml, type, target, params), type, target); }
  catch(e) { errEl.innerHTML = '<div class="pg-error">Policy error: ' + e.message + '</div>'; resEl.innerHTML = ""; }
}

function pgBatch() {
  const yaml = document.getElementById("pg-policy").value;
  const errEl = document.getElementById("pg-yaml-err");
  const resEl = document.getElementById("pg-results");
  const actions = [
    ["read_users", "crm", {}], ["get_metrics", "analytics", {}],
    ["write_config", "database", {}], ["update_record", "crm", {id: 42}],
    ["bulk_update", "crm", {count: 150}], ["deploy_prod", "api", {}],
    ["delete_all", "storage", {}],
  ];
  try {
    errEl.innerHTML = "";
    let html = '<div style="font-size:0.85rem;color:#9ca3af;margin-bottom:12px;font-weight:600;">Batch: ' + actions.length + ' actions</div>';
    let ok = 0, no = 0;
    for (const [t, tgt, p] of actions) {
      const r = pgEvalPolicy(yaml, t, tgt, p);
      html += pgCard(r, t, tgt);
      if (r.allowed) ok++; else no++;
    }
    html += '<div class="pg-result pg-summary"><span class="pg-allowed">' + ok + ' allowed</span> &middot; <span class="pg-denied">' + no + ' blocked</span></div>';
    resEl.innerHTML = html;
  } catch(e) { errEl.innerHTML = '<div class="pg-error">Policy error: ' + e.message + '</div>'; resEl.innerHTML = ""; }
}

document.addEventListener("DOMContentLoaded", () => { document.getElementById("pg-policy").value = PG_DEFAULT; });
document.addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); pgEval(); } });
</script>
