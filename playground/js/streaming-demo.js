/**
 * Aegis Playground — Streaming Guardrail Demo
 *
 * Split-screen live comparison:
 *   Left:  LLM streams freely → PII leaks to the user
 *   Right: Aegis scans the stream → PII caught, stream blocked/masked
 *
 * Demonstrates StreamingGuardrailEngine strategies:
 *   - Windowed scan (configurable window_size)
 *   - Full buffer (collect → scan → release)
 */

/* ============================================================
   SCENARIOS
   ============================================================ */

const STREAM_SCENARIOS = {
  email: {
    label: 'Email Leak',
    prompt: 'My email is john.doe@example.com. Write a funny greeting with my email.',
    response: `Sure! Here's a funny greeting for you:\n\n` +
      `Hey there, awesome human!\n\n` +
      `Just popping in to say — if you ever need a digital superhero, ` +
      `you can reach me at my secret lair: john.doe@example.com! ` +
      `But beware, sending a message may result in spontaneous laughter ` +
      `and a 100% increase in good vibes!\n\n` +
      `Chirp chirp, let the email adventures begin!`,
    piiPattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    piiLabel: 'email',
  },
  credit_card: {
    label: 'Credit Card',
    prompt: 'Summarize my recent order.',
    response: `Here's your order summary:\n\n` +
      `Product: Premium AI Subscription (Annual)\n` +
      `Amount: $299.99\n` +
      `Payment: Visa ending in ...6789\n` +
      `Full card on file: 4532-0151-2345-6789\n` +
      `Billing: 123 Gangnam-daero, Seoul\n\n` +
      `Your next billing date is April 15, 2026.`,
    piiPattern: /(?<!\d)(?:4[0-9]{3}|5[1-5][0-9]{2})(?:[\s\-]?[0-9]{4}){2}[\s\-]?[0-9]{1,4}(?!\d)/g,
    piiLabel: 'credit_card',
  },
  api_key: {
    label: 'API Key Leak',
    prompt: 'Show me how to set up the OpenAI integration.',
    response: `Here's how to set up the integration:\n\n` +
      `import openai\n\n` +
      `client = openai.Client(\n` +
      `    api_key="sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"\n` +
      `)\n\n` +
      `response = client.chat.completions.create(\n` +
      `    model="gpt-4o",\n` +
      `    messages=[{"role": "user", "content": "Hello!"}]\n` +
      `)`,
    piiPattern: /sk-(?:proj-)?[A-Za-z0-9_\-]{20,}/g,
    piiLabel: 'api_key',
  },
  multi: {
    label: 'Multi-PII',
    prompt: 'Send me the customer record for John Smith.',
    response: `Customer Record — John Smith\n\n` +
      `Email: john.smith@acme-corp.com\n` +
      `Phone: 010-9876-5432\n` +
      `SSN: 123-45-6789\n` +
      `Card: 4532-0151-2345-6789\n\n` +
      `Address: 456 Teheran-ro, Gangnam-gu, Seoul\n` +
      `Account Status: Active since 2024-01-15`,
    piiPattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}|(?<!\d)(?:4[0-9]{3}|5[1-5][0-9]{2})(?:[\s\-]?[0-9]{4}){2}[\s\-]?[0-9]{1,4}(?!\d)|(?<!\d)(?!000|666|9\d{2})[0-9]{3}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}(?!\d)|(?<!\d)01[016789][\s\-]?[0-9]{3,4}[\s\-]?[0-9]{4}(?!\d)/g,
    piiLabel: 'multiple',
  },
};

/* ============================================================
   CODE SNIPPETS
   ============================================================ */

const CODE_SNIPPETS = {
  windowed: `from aegis.guardrails import GuardrailEngine, StreamingGuardrailEngine
from aegis.guardrails.pattern import PatternGuardrail

engine = GuardrailEngine()
engine.add(PatternGuardrail(name="pii", pattern=r"\\w+@\\w+\\.\\w+", action="block"))
# requires_full_buffer=False (default) → windowed mode

streaming = StreamingGuardrailEngine(engine, window_size=3)

async for chunk in streaming.scan_stream(llm_stream):
    if chunk.blocked:
        print("[BLOCKED — PII detected]")
        break
    print(chunk.content, end="", flush=True)`,
  full_buffer: `from aegis.guardrails import GuardrailEngine, StreamingGuardrailEngine
from aegis.guardrails.pattern import PatternGuardrail

engine = GuardrailEngine()
engine.add(PatternGuardrail(
    name="pii", pattern=r"\\w+@\\w+\\.\\w+",
    action="block", requires_full_buffer=True  # ← forces full buffering
))

streaming = StreamingGuardrailEngine(engine)

async for chunk in streaming.scan_stream(llm_stream):
    # Content only arrives AFTER full response is scanned
    if chunk.blocked:
        print("[BLOCKED — PII detected]")
    else:
        print(chunk.content)  # safe, fully scanned`,
};

/* ============================================================
   STATE
   ============================================================ */

let _streamRunning = false;
let _streamAbort = null;
let _currentScenario = 'email';

/* ============================================================
   HELPERS
   ============================================================ */

function _tokenize(text) {
  // Split into word-like tokens preserving whitespace/newlines
  const tokens = [];
  let buf = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === ' ' || ch === '\n') {
      if (buf) { tokens.push(buf); buf = ''; }
      tokens.push(ch);
    } else {
      buf += ch;
    }
  }
  if (buf) tokens.push(buf);
  return tokens;
}

function _hasPII(text, pattern) {
  const re = new RegExp(pattern.source, pattern.flags);
  return re.test(text);
}

function _highlightPII(text, pattern) {
  const re = new RegExp(pattern.source, pattern.flags);
  return text.replace(re, m =>
    `<span style="background:rgba(248,81,73,.25);color:#ff7b72;border-bottom:2px solid #f85149;padding:0 2px;border-radius:2px">${m}</span>`
  );
}

function _maskPII(text, pattern) {
  const re = new RegExp(pattern.source, pattern.flags);
  return text.replace(re, m => {
    if (m.includes('@')) {
      const [local, domain] = m.split('@');
      return local[0] + '*'.repeat(local.length - 1) + '@' + domain;
    }
    if (m.startsWith('sk-')) return m.slice(0, 4) + '*'.repeat(m.length - 4);
    // Numbers: keep first 4 and last 4
    const digits = m.replace(/\D/g, '');
    if (digits.length >= 8) {
      return m.replace(/\d/g, (function() {
        let idx = 0;
        return () => { idx++; return (idx <= 4 || idx > digits.length - 4) ? digits[idx-1] : '*'; };
      })());
    }
    return '*'.repeat(m.length);
  });
}

function _el(id) { return document.getElementById(id); }

function _sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/* ============================================================
   MAIN DEMO RUNNER
   ============================================================ */

async function runStreamingDemo() {
  if (_streamRunning) return;
  _streamRunning = true;

  const ac = new AbortController();
  _streamAbort = ac;

  const scenario = STREAM_SCENARIOS[_currentScenario];
  const strategy = _el('stream-strategy').value;
  const windowSize = parseInt(_el('stream-window-size').value, 10);
  const tokens = _tokenize(scenario.response);

  // Reset UI
  const leftOut = _el('stream-left-output');
  const rightOut = _el('stream-right-output');
  const leftVerdict = _el('stream-left-verdict');
  const rightVerdict = _el('stream-right-verdict');
  const leftStatus = _el('stream-left-status');
  const rightStatus = _el('stream-right-status');
  const btn = _el('stream-start-btn');

  leftOut.innerHTML = '';
  rightOut.innerHTML = '';
  leftVerdict.style.display = 'none';
  rightVerdict.style.display = 'none';
  _el('stream-left-stats').innerHTML = '';
  _el('stream-right-stats').innerHTML = '';

  btn.textContent = '⏹ Running...';
  btn.style.opacity = '0.7';
  leftStatus.textContent = 'Streaming...';
  leftStatus.style.color = '#d29922';

  if (strategy === 'full_buffer') {
    rightStatus.textContent = 'Buffering...';
    rightStatus.style.color = '#d29922';
  } else {
    rightStatus.textContent = 'Scanning (window=' + windowSize + ')...';
    rightStatus.style.color = '#d29922';
  }

  // Update code snippet
  _el('stream-code-snippet').textContent = CODE_SNIPPETS[strategy];

  const TOKEN_DELAY = 45; // ms per token
  let leftText = '';
  let leftTokenCount = 0;
  let rightText = '';
  let rightTokenCount = 0;
  let rightBlocked = false;
  let piiLeakedCount = 0;

  // --- Left panel: stream freely (no guardrail) ---
  const leftPromise = (async () => {
    for (const token of tokens) {
      if (ac.signal.aborted) return;
      leftText += token;
      leftTokenCount++;
      leftOut.innerHTML = _highlightPII(leftText, scenario.piiPattern);
      leftOut.scrollTop = leftOut.scrollHeight;
      await _sleep(TOKEN_DELAY);
    }
    // Count leaked PII
    const re = new RegExp(scenario.piiPattern.source, scenario.piiPattern.flags);
    const matches = leftText.match(re);
    piiLeakedCount = matches ? matches.length : 0;

    leftStatus.textContent = 'Complete';
    leftStatus.style.color = '#f85149';
    leftVerdict.style.display = 'block';
    leftVerdict.style.background = 'rgba(248,81,73,.1)';
    leftVerdict.style.color = '#f85149';
    leftVerdict.innerHTML = `&#x26A0; ${piiLeakedCount} PII instance(s) leaked to user`;

    _el('stream-left-stats').innerHTML =
      `<span>Tokens: ${leftTokenCount}</span>` +
      `<span style="color:#f85149">PII leaked: ${piiLeakedCount}</span>` +
      `<span>Strategy: none</span>`;
  })();

  // --- Right panel: Aegis-guarded stream ---
  const rightPromise = (async () => {
    if (strategy === 'full_buffer') {
      await _runFullBuffer(tokens, scenario, ac, TOKEN_DELAY);
    } else {
      await _runWindowed(tokens, scenario, windowSize, ac, TOKEN_DELAY);
    }
  })();

  await Promise.all([leftPromise, rightPromise]);

  btn.textContent = '▶ Start Demo';
  btn.style.opacity = '1';
  _streamRunning = false;
  _streamAbort = null;
}

/* ============================================================
   WINDOWED STRATEGY
   ============================================================ */

async function _runWindowed(tokens, scenario, windowSize, ac, delay) {
  const out = _el('stream-right-output');
  const status = _el('stream-right-status');
  const verdict = _el('stream-right-verdict');
  const stats = _el('stream-right-stats');

  const buffer = [];
  let released = '';
  let releasedCount = 0;
  let blocked = false;

  for (const token of tokens) {
    if (ac.signal.aborted) return;
    buffer.push(token);

    if (buffer.length >= windowSize) {
      const windowText = buffer.join('');
      if (_hasPII(windowText, scenario.piiPattern)) {
        // BLOCKED
        blocked = true;
        status.textContent = 'BLOCKED';
        status.style.color = '#f85149';

        // Flash effect
        out.style.transition = 'box-shadow .3s';
        out.style.boxShadow = '0 0 20px rgba(63,185,80,.4)';
        setTimeout(() => { out.style.boxShadow = 'none'; }, 600);

        verdict.style.display = 'block';
        verdict.style.background = 'rgba(63,185,80,.12)';
        verdict.style.color = '#3fb950';
        verdict.innerHTML = `&#x1F6E1; PII detected in window — stream killed. Zero tokens leaked.`;

        stats.innerHTML =
          `<span>Tokens released: ${releasedCount}</span>` +
          `<span style="color:#3fb950">PII leaked: 0</span>` +
          `<span>Strategy: windowed (size=${windowSize})</span>`;
        return;
      }
      // Release oldest token
      const oldest = buffer.shift();
      released += oldest;
      releasedCount++;
      out.textContent = released;
      out.scrollTop = out.scrollHeight;
    }
    await _sleep(delay);
  }

  // Flush remaining buffer
  if (buffer.length > 0) {
    const remaining = buffer.join('');
    if (_hasPII(remaining, scenario.piiPattern)) {
      blocked = true;
      status.textContent = 'BLOCKED';
      status.style.color = '#f85149';
      verdict.style.display = 'block';
      verdict.style.background = 'rgba(63,185,80,.12)';
      verdict.style.color = '#3fb950';
      verdict.innerHTML = `&#x1F6E1; PII detected in final buffer — stream killed.`;
      stats.innerHTML =
        `<span>Tokens released: ${releasedCount}</span>` +
        `<span style="color:#3fb950">PII leaked: 0</span>` +
        `<span>Strategy: windowed (size=${windowSize})</span>`;
      return;
    }
    released += remaining;
    releasedCount += buffer.length;
    out.textContent = released;
  }

  if (!blocked) {
    status.textContent = 'Clean';
    status.style.color = '#3fb950';
    verdict.style.display = 'block';
    verdict.style.background = 'rgba(63,185,80,.08)';
    verdict.style.color = '#3fb950';
    verdict.innerHTML = `&#x2713; Stream completed — no PII detected.`;
    stats.innerHTML =
      `<span>Tokens released: ${releasedCount}</span>` +
      `<span style="color:#3fb950">PII leaked: 0</span>` +
      `<span>Strategy: windowed (size=${windowSize})</span>`;
  }
}

/* ============================================================
   FULL BUFFER STRATEGY
   ============================================================ */

async function _runFullBuffer(tokens, scenario, ac, delay) {
  const out = _el('stream-right-output');
  const status = _el('stream-right-status');
  const verdict = _el('stream-right-verdict');
  const stats = _el('stream-right-stats');

  // Show buffering progress
  const totalTokens = tokens.length;
  let buffered = 0;

  out.innerHTML = '<div id="stream-buffer-progress" style="text-align:center;padding:40px 0"></div>';
  const progressEl = _el('stream-buffer-progress');

  for (const token of tokens) {
    if (ac.signal.aborted) return;
    buffered++;
    const pct = Math.round((buffered / totalTokens) * 100);
    const barWidth = pct;
    progressEl.innerHTML =
      `<div style="font-size:13px;color:var(--text-secondary);margin-bottom:12px">Buffering response...</div>` +
      `<div style="background:var(--bg-secondary);border-radius:6px;height:8px;width:80%;margin:0 auto;overflow:hidden">` +
        `<div style="background:linear-gradient(90deg,#58a6ff,#3fb950);height:100%;width:${barWidth}%;transition:width .1s;border-radius:6px"></div>` +
      `</div>` +
      `<div style="font-size:11px;color:var(--text-muted);margin-top:8px">${buffered} / ${totalTokens} tokens</div>`;
    await _sleep(delay);
  }

  // Scanning phase
  status.textContent = 'Scanning...';
  progressEl.innerHTML =
    `<div style="font-size:13px;color:var(--accent);margin-bottom:8px">Scanning full response...</div>` +
    `<div class="stream-scan-spinner"></div>`;
  await _sleep(400);

  const fullText = tokens.join('');
  const hasPii = _hasPII(fullText, scenario.piiPattern);
  const re = new RegExp(scenario.piiPattern.source, scenario.piiPattern.flags);
  const matches = fullText.match(re);
  const piiCount = matches ? matches.length : 0;

  if (hasPii) {
    status.textContent = 'BLOCKED';
    status.style.color = '#f85149';

    out.style.transition = 'box-shadow .3s';
    out.style.boxShadow = '0 0 20px rgba(63,185,80,.4)';
    setTimeout(() => { out.style.boxShadow = 'none'; }, 600);

    out.innerHTML = `<div style="text-align:center;padding:40px 20px">` +
      `<div style="font-size:48px;margin-bottom:12px">&#x1F6E1;</div>` +
      `<div style="font-size:15px;font-weight:600;color:#3fb950;margin-bottom:8px">${piiCount} PII instance(s) detected and blocked</div>` +
      `<div style="font-size:12px;color:var(--text-muted)">Full response was scanned before any content reached the user.</div>` +
      `</div>`;

    verdict.style.display = 'block';
    verdict.style.background = 'rgba(63,185,80,.12)';
    verdict.style.color = '#3fb950';
    verdict.innerHTML = `&#x1F6E1; Entire response blocked — zero exposure.`;
  } else {
    status.textContent = 'Clean';
    status.style.color = '#3fb950';

    // Stream out the clean content
    out.innerHTML = '';
    let displayed = '';
    for (const token of tokens) {
      if (ac.signal.aborted) return;
      displayed += token;
      out.textContent = displayed;
      out.scrollTop = out.scrollHeight;
      await _sleep(15); // faster since already scanned
    }

    verdict.style.display = 'block';
    verdict.style.background = 'rgba(63,185,80,.08)';
    verdict.style.color = '#3fb950';
    verdict.innerHTML = `&#x2713; Full scan passed — content released.`;
  }

  stats.innerHTML =
    `<span>Tokens buffered: ${totalTokens}</span>` +
    `<span style="color:#3fb950">PII leaked: 0</span>` +
    `<span>Strategy: full_buffer</span>`;
}

/* ============================================================
   INIT
   ============================================================ */

function initStreamingDemo() {
  // Scenario buttons
  document.querySelectorAll('.stream-scenario-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.stream-scenario-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      _currentScenario = btn.dataset.scenario;
    });
  });

  // Window size slider
  const slider = _el('stream-window-size');
  const label = _el('stream-window-label');
  if (slider && label) {
    slider.addEventListener('input', () => { label.textContent = slider.value; });
  }

  // Strategy selector
  const stratSelect = _el('stream-strategy');
  if (stratSelect && slider) {
    stratSelect.addEventListener('change', () => {
      const isWindowed = stratSelect.value === 'windowed';
      slider.disabled = !isWindowed;
      slider.style.opacity = isWindowed ? '1' : '0.3';
      // Update code snippet
      _el('stream-code-snippet').textContent = CODE_SNIPPETS[stratSelect.value];
    });
  }

  // Start button
  const btn = _el('stream-start-btn');
  if (btn) {
    btn.addEventListener('click', () => {
      if (_streamRunning && _streamAbort) {
        _streamAbort.abort();
        _streamRunning = false;
        btn.textContent = '▶ Start Demo';
        btn.style.opacity = '1';
        return;
      }
      runStreamingDemo();
    });
    btn.addEventListener('mouseenter', () => {
      if (!_streamRunning) btn.style.transform = 'scale(1.04)';
    });
    btn.addEventListener('mouseleave', () => {
      btn.style.transform = 'scale(1)';
    });
  }

  // Set initial code snippet
  const codeEl = _el('stream-code-snippet');
  if (codeEl) codeEl.textContent = CODE_SNIPPETS.windowed;
}

// Auto-init when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initStreamingDemo);
} else {
  initStreamingDemo();
}
