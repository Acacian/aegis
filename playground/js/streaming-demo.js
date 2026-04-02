/**
 * Aegis Playground — Streaming Guardrail Demo
 *
 * Split-screen live comparison:
 *   Left:  LLM streams freely → PII leaks to the user
 *   Right: Aegis scans the stream → PII caught, stream blocked/masked
 *
 * Two detection modes:
 *   - Regex: Pattern-based detection (default, no API key needed)
 *   - AI:    LLM-powered semantic detection (Gemini Flash, optional key)
 *            Falls back to pre-recorded demo when no key is provided.
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
    mode: 'regex',
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
    mode: 'regex',
  },
  api_key: {
    label: 'API Key',
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
    mode: 'regex',
  },
  semantic: {
    label: 'Semantic PII',
    prompt: 'Repeat back my contact info but spell it out so it looks natural.',
    response: `Of course! Here's your info written out naturally:\n\n` +
      `You can reach me at john dot doe at example dot com.\n` +
      `My mobile is zero-one-zero, one-two-three-four, five-six-seven-eight.\n` +
      `The last four of my social are six seven eight nine.\n\n` +
      `My home address is 456 Teheran-ro, Gangnam-gu, Seoul, ` +
      `and my date of birth is March 15th, 1990.\n\n` +
      `Let me know if you need anything else!`,
    // Regex will NOT match these — that's the point
    piiPattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}|(?<!\d)01[016789][\s\-]?[0-9]{3,4}[\s\-]?[0-9]{4}(?!\d)/g,
    piiLabel: 'semantic',
    mode: 'ai',
    // Pre-recorded AI detection results (used when no API key)
    aiFindings: [
      { text: 'john dot doe at example dot com', type: 'email', start: 68, end: 99 },
      { text: 'zero-one-zero, one-two-three-four, five-six-seven-eight', type: 'phone', start: 114, end: 170 },
      { text: 'six seven eight nine', type: 'ssn_partial', start: 204, end: 224 },
      { text: '456 Teheran-ro, Gangnam-gu, Seoul', type: 'address', start: 247, end: 280 },
      { text: 'March 15th, 1990', type: 'dob', start: 306, end: 322 },
    ],
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
    mode: 'regex',
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
  ai: `import google.generativeai as genai
from aegis.guardrails import GuardrailEngine, StreamingGuardrailEngine

# AI-powered guardrail detects semantic PII that regex cannot
# e.g. "john dot doe at example dot com" → detected as email
engine = GuardrailEngine()
engine.add(AIGuardrail(
    model="gemini-2.0-flash",
    categories=["email", "phone", "ssn", "address", "dob"],
    requires_full_buffer=True,  # AI needs full context
))

streaming = StreamingGuardrailEngine(engine)

async for chunk in streaming.scan_stream(llm_stream):
    if chunk.blocked:
        print("[BLOCKED — Semantic PII detected by AI]")
    else:
        print(chunk.content)`,
};

/* ============================================================
   STATE
   ============================================================ */

let _streamRunning = false;
let _streamAbort = null;
let _currentScenario = 'semantic';

/* ============================================================
   HELPERS
   ============================================================ */

function _tokenize(text) {
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

function _highlightAIFindings(text, findings) {
  // Sort by start descending to avoid index shifting
  const sorted = [...findings].sort((a, b) => b.start - a.start);
  let result = text;
  for (const f of sorted) {
    const before = result.slice(0, f.start);
    const match = result.slice(f.start, f.end);
    const after = result.slice(f.end);
    result = before +
      `<span style="background:rgba(88,166,255,.2);color:#58a6ff;border-bottom:2px solid #58a6ff;padding:0 2px;border-radius:2px" title="${f.type}">${match}</span>` +
      after;
  }
  return result;
}

function _el(id) { return document.getElementById(id); }

function _sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/* ============================================================
   GEMINI FLASH API
   ============================================================ */

const GEMINI_SCAN_PROMPT = `You are a PII detection system. Analyze the following text and identify ALL personally identifiable information, including:
- Information written in spelled-out or obfuscated form (e.g., "john dot doe at example dot com" = email)
- Partial PII (e.g., "last four digits are 6789" = partial SSN/card)
- Addresses, dates of birth, phone numbers in any format

Respond ONLY with a JSON array. Each item: {"text": "matched text", "type": "category", "start": start_index, "end": end_index}
Categories: email, phone, ssn, credit_card, address, dob, api_key, name, other_pii
If no PII found, respond with: []

Text to analyze:
`;

async function _callGemini(apiKey, text) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [{ parts: [{ text: GEMINI_SCAN_PROMPT + text }] }],
      generationConfig: { temperature: 0, maxOutputTokens: 1024 },
    }),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Gemini API error: ${res.status} — ${err.slice(0, 200)}`);
  }
  const data = await res.json();
  const raw = data.candidates?.[0]?.content?.parts?.[0]?.text || '[]';
  // Extract JSON from possible markdown code block
  const jsonMatch = raw.match(/\[[\s\S]*\]/);
  return jsonMatch ? JSON.parse(jsonMatch[0]) : [];
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
  const apiKey = (_el('stream-api-key')?.value || '').trim();
  const isAIScenario = scenario.mode === 'ai';

  // Reset UI
  const leftOut = _el('stream-left-output');
  const rightOut = _el('stream-right-output');
  const leftVerdict = _el('stream-left-verdict');
  const rightVerdict = _el('stream-right-verdict');
  const leftStatus = _el('stream-left-status');
  const rightStatus = _el('stream-right-status');
  const leftLabel = _el('stream-left-label');
  const rightLabel = _el('stream-right-label');
  const btn = _el('stream-start-btn');

  leftOut.innerHTML = '';
  rightOut.innerHTML = '';
  leftVerdict.style.display = 'none';
  rightVerdict.style.display = 'none';
  _el('stream-left-stats').innerHTML = '';
  _el('stream-right-stats').innerHTML = '';

  // Update labels for AI scenario
  if (leftLabel) leftLabel.textContent = isAIScenario ? 'Regex Only' : 'Without Aegis';
  if (rightLabel) rightLabel.textContent = isAIScenario ? 'Aegis + AI' : 'With Aegis';

  btn.textContent = '\u23F9 Running...';
  btn.style.opacity = '0.7';
  leftStatus.textContent = 'Streaming...';
  leftStatus.style.color = '#d29922';

  const effectiveStrategy = isAIScenario ? 'full_buffer' : strategy;

  if (effectiveStrategy === 'full_buffer') {
    rightStatus.textContent = isAIScenario ? 'Buffering for AI scan...' : 'Buffering...';
    rightStatus.style.color = '#d29922';
  } else {
    rightStatus.textContent = 'Scanning (window=' + windowSize + ')...';
    rightStatus.style.color = '#d29922';
  }

  // Update code snippet
  _el('stream-code-snippet').textContent = isAIScenario ? CODE_SNIPPETS.ai : CODE_SNIPPETS[strategy];

  const TOKEN_DELAY = 45;
  let leftText = '';
  let leftTokenCount = 0;

  // --- Left panel ---
  const leftPromise = (async () => {
    for (const token of tokens) {
      if (ac.signal.aborted) return;
      leftText += token;
      leftTokenCount++;
      // For AI scenario, regex finds nothing — that's the point
      leftOut.innerHTML = _highlightPII(leftText, scenario.piiPattern);
      leftOut.scrollTop = leftOut.scrollHeight;
      await _sleep(TOKEN_DELAY);
    }

    const re = new RegExp(scenario.piiPattern.source, scenario.piiPattern.flags);
    const matches = leftText.match(re);
    const piiLeakedCount = matches ? matches.length : 0;

    leftStatus.textContent = 'Complete';

    if (isAIScenario && piiLeakedCount === 0) {
      leftStatus.style.color = '#d29922';
      leftVerdict.style.display = 'block';
      leftVerdict.style.background = 'rgba(210,153,34,.12)';
      leftVerdict.style.color = '#d29922';
      leftVerdict.innerHTML = '\u26A0 Regex found 0 PII — but 5 instances are hidden in plain text!';
    } else {
      leftStatus.style.color = '#f85149';
      leftVerdict.style.display = 'block';
      leftVerdict.style.background = 'rgba(248,81,73,.1)';
      leftVerdict.style.color = '#f85149';
      leftVerdict.innerHTML = `\u26A0 ${piiLeakedCount} PII instance(s) leaked to user`;
    }

    _el('stream-left-stats').innerHTML =
      `<span>Tokens: ${leftTokenCount}</span>` +
      `<span style="color:${isAIScenario ? '#d29922' : '#f85149'}">PII found: ${piiLeakedCount}</span>` +
      `<span>Detection: regex</span>`;
  })();

  // --- Right panel ---
  const rightPromise = (async () => {
    if (isAIScenario) {
      await _runAIMode(tokens, scenario, apiKey, ac, TOKEN_DELAY);
    } else if (effectiveStrategy === 'full_buffer') {
      await _runFullBuffer(tokens, scenario, ac, TOKEN_DELAY);
    } else {
      await _runWindowed(tokens, scenario, windowSize, ac, TOKEN_DELAY);
    }
  })();

  await Promise.all([leftPromise, rightPromise]);

  btn.textContent = '\u25B6 Start Demo';
  btn.style.opacity = '1';
  _streamRunning = false;
  _streamAbort = null;
}

/* ============================================================
   AI MODE (pre-recorded or live Gemini)
   ============================================================ */

async function _runAIMode(tokens, scenario, apiKey, ac, delay) {
  const out = _el('stream-right-output');
  const status = _el('stream-right-status');
  const verdict = _el('stream-right-verdict');
  const stats = _el('stream-right-stats');

  const totalTokens = tokens.length;
  let buffered = 0;

  // Buffering phase
  out.innerHTML = '<div id="stream-buffer-progress" style="text-align:center;padding:40px 0"></div>';
  const progressEl = _el('stream-buffer-progress');

  for (const token of tokens) {
    if (ac.signal.aborted) return;
    buffered++;
    const pct = Math.round((buffered / totalTokens) * 100);
    progressEl.innerHTML =
      `<div style="font-size:13px;color:var(--text-secondary);margin-bottom:12px">Buffering response...</div>` +
      `<div style="background:var(--bg-secondary);border-radius:6px;height:8px;width:80%;margin:0 auto;overflow:hidden">` +
        `<div style="background:linear-gradient(90deg,#58a6ff,#3fb950);height:100%;width:${pct}%;transition:width .1s;border-radius:6px"></div>` +
      `</div>` +
      `<div style="font-size:11px;color:var(--text-muted);margin-top:8px">${buffered} / ${totalTokens} tokens</div>`;
    await _sleep(delay);
  }

  // AI scanning phase
  status.textContent = 'AI scanning...';
  status.style.color = '#58a6ff';
  progressEl.innerHTML =
    `<div style="font-size:13px;color:#58a6ff;margin-bottom:8px">AI analyzing for semantic PII...</div>` +
    `<div class="stream-scan-spinner" style="border-top-color:#58a6ff"></div>`;

  let findings;
  let isLive = false;

  if (apiKey) {
    // Live Gemini call
    try {
      findings = await _callGemini(apiKey, tokens.join(''));
      isLive = true;
    } catch (e) {
      progressEl.innerHTML =
        `<div style="color:#f85149;font-size:12px;padding:8px">API error: ${e.message}<br>Falling back to pre-recorded results.</div>`;
      await _sleep(1500);
      findings = scenario.aiFindings || [];
    }
  } else {
    // Pre-recorded demo
    await _sleep(800); // simulate AI thinking time
    findings = scenario.aiFindings || [];
  }

  const piiCount = findings.length;

  if (piiCount > 0) {
    status.textContent = 'BLOCKED';
    status.style.color = '#f85149';

    out.style.transition = 'box-shadow .3s';
    out.style.boxShadow = '0 0 20px rgba(88,166,255,.4)';
    setTimeout(() => { out.style.boxShadow = 'none'; }, 600);

    // Show findings with highlights
    const fullText = tokens.join('');
    const highlighted = _highlightAIFindings(fullText, findings);

    out.innerHTML = `<div style="padding:0">` +
      `<div style="background:rgba(88,166,255,.08);padding:8px 12px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px">` +
        `<span style="font-size:18px">\u{1F9E0}</span>` +
        `<span style="font-size:12px;font-weight:600;color:#58a6ff">AI detected ${piiCount} semantic PII instance(s)</span>` +
        `${!isLive ? '<span style="font-size:10px;color:var(--text-muted);margin-left:auto">(pre-recorded demo)</span>' : '<span style="font-size:10px;color:#3fb950;margin-left:auto">live Gemini Flash</span>'}` +
      `</div>` +
      `<div style="padding:12px;font-family:\'SF Mono\',Consolas,monospace;font-size:13px;line-height:1.7;white-space:pre-wrap;word-break:break-word">${highlighted}</div>` +
      `<div style="padding:8px 12px;border-top:1px solid var(--border);display:flex;flex-wrap:wrap;gap:6px">` +
        findings.map(f =>
          `<span style="font-size:11px;background:rgba(88,166,255,.15);color:#58a6ff;padding:2px 8px;border-radius:10px">${f.type}: "${f.text.slice(0, 30)}${f.text.length > 30 ? '...' : ''}"</span>`
        ).join('') +
      `</div>` +
    `</div>`;

    verdict.style.display = 'block';
    verdict.style.background = 'rgba(63,185,80,.12)';
    verdict.style.color = '#3fb950';
    verdict.innerHTML = `\u{1F6E1} AI blocked ${piiCount} semantic PII — regex found 0. Zero exposure.`;
  } else {
    status.textContent = 'Clean';
    status.style.color = '#3fb950';
    out.innerHTML = '';
    let displayed = '';
    for (const token of tokens) {
      if (ac.signal.aborted) return;
      displayed += token;
      out.textContent = displayed;
      out.scrollTop = out.scrollHeight;
      await _sleep(15);
    }
    verdict.style.display = 'block';
    verdict.style.background = 'rgba(63,185,80,.08)';
    verdict.style.color = '#3fb950';
    verdict.innerHTML = '\u2713 AI scan passed — content released.';
  }

  stats.innerHTML =
    `<span>Tokens buffered: ${totalTokens}</span>` +
    `<span style="color:#3fb950">PII leaked: 0</span>` +
    `<span>Detection: AI${isLive ? ' (live)' : ' (demo)'}</span>`;
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

  for (const token of tokens) {
    if (ac.signal.aborted) return;
    buffer.push(token);

    if (buffer.length >= windowSize) {
      const windowText = buffer.join('');
      if (_hasPII(windowText, scenario.piiPattern)) {
        status.textContent = 'BLOCKED';
        status.style.color = '#f85149';
        out.style.transition = 'box-shadow .3s';
        out.style.boxShadow = '0 0 20px rgba(63,185,80,.4)';
        setTimeout(() => { out.style.boxShadow = 'none'; }, 600);
        verdict.style.display = 'block';
        verdict.style.background = 'rgba(63,185,80,.12)';
        verdict.style.color = '#3fb950';
        verdict.innerHTML = `\u{1F6E1} PII detected in window — stream killed. Zero tokens leaked.`;
        stats.innerHTML =
          `<span>Tokens released: ${releasedCount}</span>` +
          `<span style="color:#3fb950">PII leaked: 0</span>` +
          `<span>Strategy: windowed (size=${windowSize})</span>`;
        return;
      }
      const oldest = buffer.shift();
      released += oldest;
      releasedCount++;
      out.textContent = released;
      out.scrollTop = out.scrollHeight;
    }
    await _sleep(delay);
  }

  // Flush remaining
  if (buffer.length > 0) {
    const remaining = buffer.join('');
    if (_hasPII(remaining, scenario.piiPattern)) {
      status.textContent = 'BLOCKED';
      status.style.color = '#f85149';
      verdict.style.display = 'block';
      verdict.style.background = 'rgba(63,185,80,.12)';
      verdict.style.color = '#3fb950';
      verdict.innerHTML = `\u{1F6E1} PII detected in final buffer — stream killed.`;
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

  status.textContent = 'Clean';
  status.style.color = '#3fb950';
  verdict.style.display = 'block';
  verdict.style.background = 'rgba(63,185,80,.08)';
  verdict.style.color = '#3fb950';
  verdict.innerHTML = '\u2713 Stream completed — no PII detected.';
  stats.innerHTML =
    `<span>Tokens released: ${releasedCount}</span>` +
    `<span style="color:#3fb950">PII leaked: 0</span>` +
    `<span>Strategy: windowed (size=${windowSize})</span>`;
}

/* ============================================================
   FULL BUFFER STRATEGY
   ============================================================ */

async function _runFullBuffer(tokens, scenario, ac, delay) {
  const out = _el('stream-right-output');
  const status = _el('stream-right-status');
  const verdict = _el('stream-right-verdict');
  const stats = _el('stream-right-stats');

  const totalTokens = tokens.length;
  let buffered = 0;

  out.innerHTML = '<div id="stream-buffer-progress" style="text-align:center;padding:40px 0"></div>';
  const progressEl = _el('stream-buffer-progress');

  for (const token of tokens) {
    if (ac.signal.aborted) return;
    buffered++;
    const pct = Math.round((buffered / totalTokens) * 100);
    progressEl.innerHTML =
      `<div style="font-size:13px;color:var(--text-secondary);margin-bottom:12px">Buffering response...</div>` +
      `<div style="background:var(--bg-secondary);border-radius:6px;height:8px;width:80%;margin:0 auto;overflow:hidden">` +
        `<div style="background:linear-gradient(90deg,#58a6ff,#3fb950);height:100%;width:${pct}%;transition:width .1s;border-radius:6px"></div>` +
      `</div>` +
      `<div style="font-size:11px;color:var(--text-muted);margin-top:8px">${buffered} / ${totalTokens} tokens</div>`;
    await _sleep(delay);
  }

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
      `<div style="font-size:48px;margin-bottom:12px">\u{1F6E1}</div>` +
      `<div style="font-size:15px;font-weight:600;color:#3fb950;margin-bottom:8px">${piiCount} PII instance(s) detected and blocked</div>` +
      `<div style="font-size:12px;color:var(--text-muted)">Full response was scanned before any content reached the user.</div>` +
      `</div>`;

    verdict.style.display = 'block';
    verdict.style.background = 'rgba(63,185,80,.12)';
    verdict.style.color = '#3fb950';
    verdict.innerHTML = `\u{1F6E1} Entire response blocked — zero exposure.`;
  } else {
    status.textContent = 'Clean';
    status.style.color = '#3fb950';
    out.innerHTML = '';
    let displayed = '';
    for (const token of tokens) {
      if (ac.signal.aborted) return;
      displayed += token;
      out.textContent = displayed;
      out.scrollTop = out.scrollHeight;
      await _sleep(15);
    }
    verdict.style.display = 'block';
    verdict.style.background = 'rgba(63,185,80,.08)';
    verdict.style.color = '#3fb950';
    verdict.innerHTML = '\u2713 Full scan passed — content released.';
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

      // Show/hide AI key section based on scenario
      const scenario = STREAM_SCENARIOS[_currentScenario];
      const aiSection = _el('stream-ai-section');
      if (aiSection) {
        aiSection.style.display = scenario.mode === 'ai' ? 'flex' : 'none';
      }
      // Auto-switch strategy for AI scenarios
      const stratSelect = _el('stream-strategy');
      if (scenario.mode === 'ai' && stratSelect) {
        stratSelect.value = 'full_buffer';
        stratSelect.dispatchEvent(new Event('change'));
      }
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
      const scenario = STREAM_SCENARIOS[_currentScenario];
      if (scenario.mode === 'ai') {
        _el('stream-code-snippet').textContent = CODE_SNIPPETS.ai;
      } else {
        _el('stream-code-snippet').textContent = CODE_SNIPPETS[stratSelect.value];
      }
    });
  }

  // API key — restore from sessionStorage
  const keyInput = _el('stream-api-key');
  if (keyInput) {
    const saved = sessionStorage.getItem('aegis_gemini_key');
    if (saved) keyInput.value = saved;
    keyInput.addEventListener('input', () => {
      sessionStorage.setItem('aegis_gemini_key', keyInput.value);
    });
  }

  // Start button
  const btn = _el('stream-start-btn');
  if (btn) {
    btn.addEventListener('click', () => {
      if (_streamRunning && _streamAbort) {
        _streamAbort.abort();
        _streamRunning = false;
        btn.textContent = '\u25B6 Start Demo';
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
  if (codeEl) codeEl.textContent = CODE_SNIPPETS.ai;
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initStreamingDemo);
} else {
  initStreamingDemo();
}
