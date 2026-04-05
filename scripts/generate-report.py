#!/usr/bin/env python3
"""Generate scan-report.html from scan JSON data.

Usage:
    python scripts/generate-report.py /tmp/scan-full.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def generate(data: list[dict]) -> str:
    """Generate the full HTML report from scan data."""
    total_findings = sum(r["findings"] for r in data)
    total_files = sum(r["files"] for r in data)
    total_repos = len(data)
    grade_f = sum(1 for r in data if r["grade"] == "F")
    grade_d = sum(1 for r in data if r["grade"] == "D")
    grade_c = sum(1 for r in data if r["grade"] == "C")
    grade_b = sum(1 for r in data if r["grade"] == "B")
    grade_a = sum(1 for r in data if r["grade"] == "A")

    # All OWASP categories across all repos
    all_owasp: dict[str, int] = {}
    for r in data:
        for cat, count in r.get("categories", {}).items():
            all_owasp[cat] = all_owasp.get(cat, 0) + count

    data_json = json.dumps(data, ensure_ascii=False)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Agent Security Report — aegis scan results for {total_repos} repos</title>
  <meta name="description" content="We scanned {total_repos} AI agent repos for ungoverned tool calls. {grade_f}/{total_repos} scored F. {total_findings:,} findings total.">
  <meta property="og:title" content="AI Agent Security Report — {total_repos} Repos, {grade_f} Scored F">
  <meta property="og:description" content="{total_findings:,} ungoverned tool calls across {total_repos} major AI agent frameworks. Selection governance: 0/{total_repos}.">
  <meta property="og:url" content="https://acacian.github.io/aegis/playground/scan-report.html">
  <meta property="og:type" content="article">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="AI Agent Security Report — {total_repos} Repos, {grade_f} Scored F">
  <meta name="twitter:description" content="{total_findings:,} ungoverned tool calls found across {total_repos} major AI agent frameworks.">
  <link rel="canonical" href="https://acacian.github.io/aegis/playground/scan-report.html">
  <style>
    :root {{
      --bg-primary: #0d1117;
      --bg-secondary: #161b22;
      --bg-panel: #1c2128;
      --bg-hover: #21262d;
      --border: #30363d;
      --text-primary: #e6edf3;
      --text-secondary: #8b949e;
      --text-muted: #6e7681;
      --accent: #58a6ff;
      --risk-high: #f85149;
      --risk-high-bg: rgba(248, 81, 73, 0.12);
      --risk-medium: #d29922;
      --risk-medium-bg: rgba(210, 153, 34, 0.12);
      --risk-low: #3fb950;
      --risk-low-bg: rgba(63, 185, 80, 0.12);
      --radius: 8px;
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
    }}
    .container {{ max-width: 1100px; margin: 0 auto; padding: 40px 20px; }}
    h1 {{ font-size: 28px; margin-bottom: 8px; }}
    .subtitle {{ color: var(--text-secondary); font-size: 16px; margin-bottom: 32px; }}
    .stat-bar {{
      display: flex; gap: 16px; margin-bottom: 32px; flex-wrap: wrap;
    }}
    .stat-card {{
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 16px 20px;
      flex: 1; min-width: 120px;
    }}
    .stat-num {{ font-size: 28px; font-weight: 700; }}
    .stat-num.red {{ color: var(--risk-high); }}
    .stat-num.yellow {{ color: var(--risk-medium); }}
    .stat-num.green {{ color: var(--risk-low); }}
    .stat-label {{ font-size: 12px; color: var(--text-muted); }}

    .key-finding {{
      background: var(--risk-high-bg);
      border: 1px solid rgba(248, 81, 73, 0.3);
      border-radius: var(--radius);
      padding: 20px 24px;
      margin-bottom: 32px;
    }}
    .key-finding h2 {{ font-size: 16px; color: var(--risk-high); margin-bottom: 8px; }}
    .key-finding p {{ font-size: 14px; color: var(--text-secondary); margin-bottom: 4px; }}
    .key-finding strong {{ color: var(--text-primary); }}

    table {{ width: 100%; border-collapse: collapse; margin-bottom: 32px; }}
    th {{
      text-align: left; padding: 10px 12px; font-size: 12px;
      color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px;
      border-bottom: 1px solid var(--border); cursor: pointer;
    }}
    th:hover {{ color: var(--accent); }}
    td {{
      padding: 12px; border-bottom: 1px solid var(--border);
      font-size: 14px;
    }}
    tr:hover {{ background: var(--bg-hover); }}
    .repo-name {{ font-weight: 600; }}
    .repo-name a {{ color: var(--accent); text-decoration: none; }}
    .repo-name a:hover {{ text-decoration: underline; }}
    .stars {{ color: var(--text-muted); font-size: 13px; }}
    .grade {{
      display: inline-block; padding: 2px 10px; border-radius: 12px;
      font-weight: 700; font-size: 13px;
    }}
    .grade-a {{ background: var(--risk-low-bg); color: var(--risk-low); }}
    .grade-b {{ background: var(--risk-low-bg); color: var(--risk-low); }}
    .grade-c {{ background: var(--risk-medium-bg); color: var(--risk-medium); }}
    .grade-d {{ background: var(--risk-medium-bg); color: var(--risk-medium); }}
    .grade-f {{ background: var(--risk-high-bg); color: var(--risk-high); }}
    .finding-count {{ font-weight: 600; color: var(--risk-high); font-size: 16px; }}
    .finding-count.low {{ color: var(--risk-low); }}
    .cat-tags {{ display: flex; gap: 4px; flex-wrap: wrap; }}
    .cat-tag {{
      font-size: 11px; padding: 2px 8px; border-radius: 10px;
      background: var(--bg-panel); border: 1px solid var(--border);
      color: var(--text-secondary); white-space: nowrap;
    }}

    .detail-row {{ display: none; }}
    .detail-row.open {{ display: table-row; }}
    .detail-row td {{
      padding: 0 12px 16px 12px;
      background: var(--bg-secondary);
    }}
    .detail-list {{ list-style: none; padding: 12px 0 0 0; }}
    .detail-list li {{
      font-size: 13px; padding: 6px 0;
      border-bottom: 1px solid var(--border);
      color: var(--text-secondary);
    }}
    .detail-list li:last-child {{ border-bottom: none; }}
    .detail-file {{ color: var(--accent); }}
    .detail-owasp {{
      font-size: 11px; padding: 1px 6px; border-radius: 8px;
      background: var(--risk-high-bg); color: var(--risk-high);
      margin-left: 6px;
    }}
    .toggle-btn {{
      background: none; border: none; color: var(--accent);
      cursor: pointer; font-size: 13px; padding: 0;
    }}
    .toggle-btn:hover {{ text-decoration: underline; }}

    .method-note {{
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 20px 24px;
      margin-bottom: 32px;
    }}
    .method-note h2 {{ font-size: 16px; margin-bottom: 8px; }}
    .method-note p {{ font-size: 14px; color: var(--text-secondary); margin-bottom: 8px; }}
    .method-note code {{
      background: var(--bg-panel); padding: 2px 6px; border-radius: 4px;
      font-size: 13px;
    }}

    .cta {{
      background: var(--bg-secondary);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 24px;
      text-align: center;
    }}
    .cta h2 {{ font-size: 18px; margin-bottom: 8px; }}
    .cta p {{ color: var(--text-secondary); font-size: 14px; margin-bottom: 16px; }}
    .cta-code {{
      background: var(--bg-primary); border: 1px solid var(--border);
      border-radius: var(--radius); padding: 12px 16px;
      font-family: 'SFMono-Regular', Consolas, monospace;
      font-size: 14px; display: inline-block; color: var(--text-primary);
      user-select: all;
    }}
    .footer {{
      margin-top: 40px; padding-top: 20px;
      border-top: 1px solid var(--border);
      font-size: 12px; color: var(--text-muted);
      text-align: center;
    }}
    .footer a {{ color: var(--accent); text-decoration: none; }}

    .filter-bar {{
      display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap;
      align-items: center;
    }}
    .filter-btn {{
      background: var(--bg-secondary); border: 1px solid var(--border);
      border-radius: 16px; padding: 4px 12px; font-size: 12px;
      color: var(--text-secondary); cursor: pointer;
    }}
    .filter-btn:hover, .filter-btn.active {{
      border-color: var(--accent); color: var(--accent);
    }}

    @media (max-width: 640px) {{
      .stat-bar {{ flex-direction: column; }}
      table {{ font-size: 13px; }}
      td, th {{ padding: 8px 6px; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <h1>AI Agent Security Report</h1>
    <p class="subtitle">
      <code>aegis scan</code> results for <strong>{total_repos}</strong> AI agent repositories.
      Scanned <span id="total-files">0</span> Python files.
      Last updated: April 2026.
    </p>

    <div class="stat-bar">
      <div class="stat-card">
        <div class="stat-num red" id="total-findings">0</div>
        <div class="stat-label">Ungoverned tool calls</div>
      </div>
      <div class="stat-card">
        <div class="stat-num red">{grade_f}/{total_repos}</div>
        <div class="stat-label">Repos scored F</div>
      </div>
      <div class="stat-card">
        <div class="stat-num yellow" id="total-repos">{total_repos}</div>
        <div class="stat-label">Repos scanned</div>
      </div>
      <div class="stat-card">
        <div class="stat-num red">0/{total_repos}</div>
        <div class="stat-label">Have selection governance</div>
      </div>
    </div>

    <div class="key-finding">
      <h2>Key Finding</h2>
      <p><strong>{grade_f} out of {total_repos}</strong> scanned repositories have <strong>zero governance</strong> on their AI tool calls.</p>
      <p><strong>0 out of {total_repos}</strong> have any form of <strong>selection governance</strong> (detecting what agents choose NOT to show).</p>
      <p>Combined: <strong>{total_findings:,}</strong> ungoverned tool calls across <strong>{total_files:,}</strong> Python files.</p>
    </div>

    <div class="filter-bar">
      <span style="font-size:12px;color:var(--text-muted)">Filter:</span>
      <button class="filter-btn active" data-grade="all">All ({total_repos})</button>
      <button class="filter-btn" data-grade="F">Grade F ({grade_f})</button>
      <button class="filter-btn" data-grade="D">Grade D ({grade_d})</button>
      <button class="filter-btn" data-grade="C">Grade C ({grade_c})</button>
      <button class="filter-btn" data-grade="B">Grade B ({grade_b})</button>
      <button class="filter-btn" data-grade="A">Grade A ({grade_a})</button>
    </div>

    <table>
      <thead>
        <tr>
          <th data-sort="name">Repository</th>
          <th data-sort="stars">Stars</th>
          <th data-sort="files">Files</th>
          <th data-sort="findings">Findings</th>
          <th data-sort="grade">Grade</th>
          <th>Categories</th>
          <th></th>
        </tr>
      </thead>
      <tbody id="results-body"></tbody>
    </table>

    <div class="method-note">
      <h2>Methodology</h2>
      <p>
        <code>aegis scan</code> performs static AST analysis on Python files. It detects tool calls, LLM API invocations,
        subprocess executions, and MCP tool definitions that lack a governance wrapper (policy check, guardrail, or approval gate).
      </p>
      <p>
        Each finding is mapped to the
        <a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications/" style="color:var(--accent)">OWASP Top 10 for Agentic Applications</a>.
        A governance wrapper does not mean the code is vulnerable &mdash; it means there is no automated policy enforcement at that call site.
      </p>
      <p>
        <strong>Selection governance check:</strong> We also verified whether each framework implements any form of
        selection-by-negation detection, option filtering audit, or commit-reveal protocol. None do.
      </p>
      <p>
        Scanner source:
        <a href="https://github.com/Acacian/aegis/blob/main/src/aegis/cli/scan.py" style="color:var(--accent)">aegis/cli/scan.py</a>.
        Results are reproducible &mdash; clone the repo and run <code>aegis scan .</code>.
      </p>
    </div>

    <div class="cta">
      <h2>Scan your own repo</h2>
      <p>Find ungoverned AI tool calls in your codebase.</p>
      <div class="cta-code">pip install agent-aegis && aegis scan .</div>
    </div>

    <div class="footer">
      Built with <a href="https://github.com/Acacian/aegis">Aegis</a> &mdash;
      <a href="https://acacian.github.io/aegis/playground/">Playground</a> &middot;
      <a href="https://pypi.org/project/agent-aegis/">PyPI</a> &middot;
      <a href="https://github.com/marketplace/actions/aegis-ai-agent-security-gate">GitHub Action</a>
    </div>
  </div>

  <script>
    const DATA = {data_json};

    DATA.sort((a, b) => b.findings - a.findings);

    const totalFindings = DATA.reduce((s, r) => s + r.findings, 0);
    const totalFiles = DATA.reduce((s, r) => s + r.files, 0);
    document.getElementById('total-findings').textContent = totalFindings.toLocaleString();
    document.getElementById('total-files').textContent = totalFiles.toLocaleString();

    const tbody = document.getElementById('results-body');
    const gradeClass = g => ({{ A:'grade-a', B:'grade-b', C:'grade-c', D:'grade-d', F:'grade-f' }})[g] || 'grade-f';

    function renderTable(filter) {{
      tbody.innerHTML = '';
      const filtered = filter === 'all' ? DATA : DATA.filter(r => r.grade === filter);
      filtered.forEach((repo, i) => {{
        const tr = document.createElement('tr');
        tr.style.cursor = 'pointer';
        tr.dataset.grade = repo.grade;
        const findingClass = repo.findings <= 3 ? 'finding-count low' : 'finding-count';
        tr.innerHTML = `
          <td class="repo-name"><a href="${{repo.url}}" target="_blank" rel="noopener">${{repo.name}}</a></td>
          <td class="stars">${{repo.stars}}</td>
          <td>${{repo.files.toLocaleString()}}</td>
          <td class="${{findingClass}}">${{repo.findings}}</td>
          <td><span class="grade ${{gradeClass(repo.grade)}}">${{repo.grade}}</span></td>
          <td class="cat-tags">${{Object.entries(repo.categories || {{}})
            .sort((a,b) => b[1]-a[1])
            .map(([c,n]) => `<span class="cat-tag">${{c}}: ${{n}}</span>`)
            .join('')}}</td>
          <td><button class="toggle-btn" data-idx="${{i}}">details</button></td>
        `;
        tbody.appendChild(tr);

        const detailTr = document.createElement('tr');
        detailTr.className = 'detail-row';
        detailTr.id = `detail-${{i}}`;
        detailTr.innerHTML = `
          <td colspan="7">
            <ul class="detail-list">
              ${{(repo.examples || []).map(ex => `
                <li>
                  <span class="detail-file">${{ex.file}}:${{ex.line}}</span>
                  &mdash; ${{ex.detail}}
                  ${{ex.owasp ? `<span class="detail-owasp">${{ex.owasp}}</span>` : ''}}
                </li>
              `).join('')}}
              ${{repo.findings > 3 ? `<li style="color:var(--text-muted)">... and ${{repo.findings - 3}} more findings. Run <code>aegis scan</code> to see all.</li>` : ''}}
            </ul>
          </td>
        `;
        tbody.appendChild(detailTr);

        tr.addEventListener('click', () => detailTr.classList.toggle('open'));
      }});

      document.querySelectorAll('.toggle-btn').forEach(btn => {{
        btn.addEventListener('click', (e) => {{
          e.stopPropagation();
          document.getElementById(`detail-${{btn.dataset.idx}}`)?.classList.toggle('open');
        }});
      }});
    }}

    renderTable('all');

    // Filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {{
      btn.addEventListener('click', () => {{
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        renderTable(btn.dataset.grade);
      }});
    }});

    // Sort headers
    let sortDir = {{}};
    document.querySelectorAll('th[data-sort]').forEach(th => {{
      th.addEventListener('click', () => {{
        const key = th.dataset.sort;
        sortDir[key] = !(sortDir[key] || false);
        const dir = sortDir[key] ? 1 : -1;
        DATA.sort((a, b) => {{
          let av = a[key], bv = b[key];
          if (key === 'stars') {{
            av = parseFloat(av) * (av.includes('K') ? 1000 : 1);
            bv = parseFloat(bv) * (bv.includes('K') ? 1000 : 1);
          }}
          if (typeof av === 'string') return av.localeCompare(bv) * dir;
          return (av - bv) * dir;
        }});
        const active = document.querySelector('.filter-btn.active');
        renderTable(active?.dataset.grade || 'all');
      }});
    }});
  </script>
</body>
</html>"""


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python scripts/generate-report.py <scan-results.json>", file=sys.stderr)
        sys.exit(1)

    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    html = generate(data)

    output_path = Path(__file__).resolve().parents[1] / "playground" / "scan-report.html"
    output_path.write_text(html, encoding="utf-8")
    print(f"Report generated: {output_path}")
    print(f"  {len(data)} repos, {sum(r['findings'] for r in data):,} findings")


if __name__ == "__main__":
    main()
