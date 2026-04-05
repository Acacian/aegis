/**
 * Aegis Playground i18n — lightweight, no-dependency translation system.
 *
 * Usage:
 *   HTML:  <span data-i18n="header.tagline">fallback text</span>
 *   JS:    t('header.tagline')
 *   Switch: setLang('ko') / setLang('en')
 */

/* ------------------------------------------------------------------ */
/*  Translation data                                                   */
/* ------------------------------------------------------------------ */

const I18N = {
  en: {
    // Header
    'header.tagline': 'AI agent governance in your browser. No install needed.',
    'header.tests': '2540+ tests',
    'header.coverage': '92% coverage',
    'header.adapters': '7 adapters',
    'header.eval': '<1ms eval',

    // Loading
    'loading.title': 'Loading Aegis Playground',
    'loading.status': 'Initializing Python runtime...',
    'loading.tip': 'Tip: Aegis evaluates policies in under 1ms',

    // Noscript
    'noscript': 'The Aegis Playground requires JavaScript. Please enable JavaScript or install the Python library: pip install agent-aegis',

    // Tab names
    'tab.streaming': 'Streaming Guard',
    'tab.pii': 'PII Scanner',
    'tab.injection': 'Injection Detector',
    'tab.mcp': 'MCP Security',
    'tab.init': 'auto_instrument()',
    'tab.policy': 'Policy',
    'tab.cost': 'Cost Breaker',
    'tab.audit': 'Audit Chain',
    'tab.regulatory': 'Compliance',
    'tab.scan': 'Scan Report (39 Repos, 92% F)',
    'tab.benchmark': 'Benchmark vs MS AGT',
    'tab.selection': 'Selection Gov',

    // Selection Governance panel
    'selection.title': 'Selection Governance (v0.9)',
    'selection.desc': 'Detect covert power through what an agent <em>excludes</em>. Audit selection-by-negation patterns and compute justification gaps between declared and assessed impact. Based on Santander "Selection as Power" (arXiv:2602.14606).',
    'selection.scenario.title': 'What Your AI Agent Hid From You',
    'selection.scenario.pick': 'Scenario:',
    'selection.scenario.shown': 'Agent showed you these options:',
    'selection.scenario.reveal': 'Reveal What Was Hidden',
    'selection.scenario.hidden': "What your agent DIDN'T show you:",
    'selection.scenario.investment': 'Investment Advisor',
    'selection.scenario.hiring': 'Hiring Agent',
    'selection.scenario.security': 'Security Scanner',
    'selection.audit.title': 'Selection Audit',
    'selection.audit.hint': 'An agent had 5 tool options, selected 1, and eliminated 4. Audit the selection.',
    'selection.audit.selected': 'Selected Option',
    'selection.audit.run': 'Audit Selection',
    'selection.gap.title': 'Justification Gap',
    'selection.gap.hint': 'Agent declares zero impact. System independently assesses the real impact. See the gap.',
    'selection.gap.action': 'Action Type',
    'selection.gap.target': 'Target',
    'selection.gap.declared': "Agent's Declared Impact (6D vector)",
    'selection.gap.assess': 'Assess',
    'selection.gap.zero': 'Zero All',
    'selection.gap.honest': 'Honest Report',

    // auto_instrument panel
    'init.title': 'aegis.auto_instrument() \u2014 One Call, Full Security',
    'init.desc': 'One function activates everything: guardrails, policy enforcement, auto-patching, audit logging, and cost tracking. Drop an <code>aegis.yaml</code> in your project root and call <code>aegis.auto_instrument()</code>.',
    'init.config.hint': 'Drop this file in your project root',
    'init.run': 'Run aegis.auto_instrument()',
    'init.test.title': 'Test Input',
    'init.test.hint': 'Paste text to see guardrails in action',
    'init.test.placeholder': 'Type or paste text here to test PII detection + injection blocking...\n\nExample: My email is john@example.com and my card is 4532-0151-2345-6789',
    'init.results.title': 'Guardrail Results',
    'init.results.status': 'Waiting for init...',
    'init.masked.title': 'Sanitized Output',
    'init.activate.title': 'Two ways to activate',
    'init.frameworks.title': 'Supported Frameworks (11)',
    'init.defaults.title': 'Default Guardrails (zero config)',
    'init.sample.pii': 'PII Sample',
    'init.sample.injection': 'Injection Sample',
    'init.sample.mixed': 'Mixed Attack',
    'init.sample.clean': 'Clean Text',

    // Default guardrails table
    'guard.header.name': 'Guardrail',
    'guard.header.default': 'Default',
    'guard.header.catches': 'Catches',
    'guard.injection': 'Prompt injection',
    'guard.injection.catches': '85+ patterns, multi-language (EN/KO/ZH/JA)',
    'guard.pii': 'PII detection',
    'guard.pii.catches': '12 categories (email, credit card, SSN, API keys\u2026)',
    'guard.leak': 'Prompt leak',
    'guard.leak.catches': 'System prompt extraction attempts',
    'guard.toxicity': 'Toxicity',
    'guard.toxicity.catches': 'Harmful/abusive content (opt-in to block)',

    // Policy panel
    'policy.title': 'Policy Editor',
    'policy.preset': 'Preset:',
    'policy.actions.title': 'Test Actions',
    'policy.result.title': 'Result',
    'policy.export': 'Export',

    // PII panel
    'pii.title': 'PII Scanner',
    'pii.desc': 'Paste text below to detect personally identifiable information in real time.',
    'pii.input.placeholder': 'Paste text to scan for PII...',
    'pii.categories': 'Categories',
    'pii.results': 'Detection Results',

    // Injection panel
    'injection.title': 'Prompt Injection Detector',
    'injection.desc': 'Test whether input text contains prompt injection attacks.',

    // MCP panel
    'mcp.title': 'MCP Security Scanner',
    'mcp.desc': 'Analyze MCP tool definitions for security risks: tool poisoning, hidden instructions, and more.',

    // Cost panel
    'cost.title': 'Cost Circuit Breaker',
    'cost.desc': 'Track AI API costs in real time and enforce budget limits.',

    // Audit panel
    'audit.title': 'Audit Chain Visualizer',
    'audit.desc': 'SHA-256 hash-linked tamper-evident audit trail.',

    // Regulatory panel
    'regulatory.title': 'Regulatory Compliance',
    'regulatory.desc': 'Evaluate your AI agent configuration against regulatory frameworks.',

    // Streaming panel
    'streaming.title': 'Streaming Guard',
    'streaming.desc': 'See how Aegis protects streaming LLM responses in real time.',
    'streaming.unguarded': 'Unguarded Stream',
    'streaming.guarded': 'Aegis-Protected Stream',

    // Common
    'common.run': 'Run',
    'common.clear': 'Clear',
    'common.copy': 'Copy',
    'common.reset': 'Reset',
    'common.block': 'Block',
    'common.warn': 'Warn',
    'common.auto': 'Auto',
    'common.close': 'Close',

    // Footer / CTA
    'cta.install': 'pip install agent-aegis',
    'cta.docs': 'Read the docs',
    'cta.github': 'View on GitHub',

    // Language toggle
    'lang.switch': 'KO',
  },

  ko: {
    // Header
    'header.tagline': '\uBE0C\uB77C\uC6B0\uC800\uC5D0\uC11C \uCCB4\uD5D8\uD558\uB294 AI \uC5D0\uC774\uC804\uD2B8 \uAC70\uBC84\uB10C\uC2A4. \uC124\uCE58 \uBD88\uD544\uC694.',
    'header.tests': '2540+ \uD14C\uC2A4\uD2B8',
    'header.coverage': '92% \uCEE4\uBC84\uB9AC\uC9C0',
    'header.adapters': '7\uAC1C \uC5B4\uB311\uD130',
    'header.eval': '<1ms \uD3C9\uAC00',

    // Loading
    'loading.title': 'Aegis Playground \uB85C\uB529 \uC911',
    'loading.status': 'Python \uB7F0\uD0C0\uC784 \uCD08\uAE30\uD654 \uC911...',
    'loading.tip': '\uD301: Aegis\uB294 1ms \uBBF8\uB9CC\uC73C\uB85C \uC815\uCC45\uC744 \uD3C9\uAC00\uD569\uB2C8\uB2E4',

    // Noscript
    'noscript': 'Aegis Playground\uB294 JavaScript\uAC00 \uD544\uC694\uD569\uB2C8\uB2E4. JavaScript\uB97C \uD65C\uC131\uD654\uD558\uAC70\uB098 Python \uB77C\uC774\uBE0C\uB7EC\uB9AC\uB97C \uC124\uCE58\uD558\uC138\uC694: pip install agent-aegis',

    // Tab names
    'tab.streaming': '\uC2A4\uD2B8\uB9AC\uBC0D \uAC00\uB4DC',
    'tab.pii': '\uAC1C\uC778\uC815\uBCF4 \uC2A4\uCE90\uB108',
    'tab.injection': '\uC778\uC81D\uC158 \uD0D0\uC9C0',
    'tab.mcp': 'MCP \uBCF4\uC548',
    'tab.init': 'auto_instrument()',
    'tab.policy': '\uC815\uCC45 \uD3B8\uC9D1\uAE30',
    'tab.cost': '\uBE44\uC6A9 \uCC28\uB2E8\uAE30',
    'tab.audit': '\uAC10\uC0AC \uCCB4\uC778',
    'tab.regulatory': '\uADDC\uC81C \uC900\uC218',
    'tab.scan': '\uC2A4\uCE94 \uB9AC\uD3EC\uD2B8 (39\uAC1C \uB808\uD3EC, 92% F)',
    'tab.benchmark': '\uBCA4\uCE58\uB9C8\uD06C vs MS AGT',
    'tab.selection': '\uC120\uD0DD \uAC70\uBC84\uB10C\uC2A4',

    // Selection Governance panel
    'selection.title': '\uC120\uD0DD \uAC70\uBC84\uB10C\uC2A4 (v0.9)',
    'selection.desc': '\uC5D0\uC774\uC804\uD2B8\uAC00 <em>\uBC30\uC81C\uD558\uB294 \uAC83</em>\uC744 \uD1B5\uD574 \uC740\uBC00\uD55C \uAD8C\uB825 \uD589\uC0AC\uB97C \uD0D0\uC9C0\uD569\uB2C8\uB2E4. \uC120\uD0DD-\uBD80\uC815(selection-by-negation) \uD328\uD134\uC744 \uAC10\uC0AC\uD558\uACE0, \uC120\uC5B8\uB41C \uC601\uD5A5\uACFC \uD3C9\uAC00\uB41C \uC601\uD5A5 \uAC04\uC758 \uC815\uB2F9\uD654 \uAC29\uCC28\uB97C \uACC4\uC0B0\uD569\uB2C8\uB2E4. Santander "Selection as Power" (arXiv:2602.14606) \uAE30\uBC18.',
    'selection.scenario.title': '\uB2F9\uC2E0\uC758 AI \uC5D0\uC774\uC804\uD2B8\uAC00 \uC228\uAE34 \uAC83',
    'selection.scenario.pick': '\uC2DC\uB098\uB9AC\uC624:',
    'selection.scenario.shown': '\uC5D0\uC774\uC804\uD2B8\uAC00 \uBCF4\uC5EC\uC900 \uC635\uC158:',
    'selection.scenario.reveal': '\uC228\uACA8\uC9C4 \uAC83 \uBCF4\uAE30',
    'selection.scenario.hidden': '\uC5D0\uC774\uC804\uD2B8\uAC00 \uBCF4\uC5EC\uC8FC\uC9C0 \uC54A\uC740 \uAC83:',
    'selection.scenario.investment': '\uD22C\uC790 \uC5B4\uB4DC\uBC14\uC774\uC800',
    'selection.scenario.hiring': '\uCC44\uC6A9 \uC5D0\uC774\uC804\uD2B8',
    'selection.scenario.security': '\uBCF4\uC548 \uC2A4\uCE90\uB108',
    'selection.audit.title': '\uC120\uD0DD \uAC10\uC0AC',
    'selection.audit.hint': '\uC5D0\uC774\uC804\uD2B8\uAC00 5\uAC1C \uB3C4\uAD6C \uC635\uC158 \uC911 1\uAC1C\uB97C \uC120\uD0DD\uD558\uACE0 4\uAC1C\uB97C \uBC30\uC81C\uD588\uC2B5\uB2C8\uB2E4. \uC120\uD0DD\uC744 \uAC10\uC0AC\uD558\uC138\uC694.',
    'selection.audit.selected': '\uC120\uD0DD\uB41C \uC635\uC158',
    'selection.audit.run': '\uC120\uD0DD \uAC10\uC0AC',
    'selection.gap.title': '\uC815\uB2F9\uD654 \uAC29\uCC28',
    'selection.gap.hint': '\uC5D0\uC774\uC804\uD2B8\uAC00 \uC601\uD5A5\uC744 0\uC73C\uB85C \uC120\uC5B8\uD569\uB2C8\uB2E4. \uC2DC\uC2A4\uD15C\uC774 \uB3C5\uB9BD\uC801\uC73C\uB85C \uC2E4\uC81C \uC601\uD5A5\uC744 \uD3C9\uAC00\uD569\uB2C8\uB2E4. \uAC29\uCC28\uB97C \uD655\uC778\uD558\uC138\uC694.',
    'selection.gap.action': '\uC561\uC158 \uD0C0\uC785',
    'selection.gap.target': '\uB300\uC0C1',
    'selection.gap.declared': '\uC5D0\uC774\uC804\uD2B8 \uC120\uC5B8 \uC601\uD5A5 (6\uCC28\uC6D0 \uBCA1\uD130)',
    'selection.gap.assess': '\uD3C9\uAC00',
    'selection.gap.zero': '\uBAA8\uB450 0\uC73C\uB85C',
    'selection.gap.honest': '\uC815\uC9C1\uD55C \uBCF4\uACE0',

    // auto_instrument panel
    'init.title': 'aegis.auto_instrument() \u2014 \uD55C \uBC88\uC758 \uD638\uCD9C\uB85C \uC644\uC804 \uBCF4\uC548',
    'init.desc': '\uD558\uB098\uC758 \uD568\uC218\uB85C \uBAA8\uB4E0 \uAC83\uC744 \uD65C\uC131\uD654\uD569\uB2C8\uB2E4: \uAC00\uB4DC\uB808\uC77C, \uC815\uCC45 \uC2DC\uD589, \uC790\uB3D9 \uD328\uCE58, \uAC10\uC0AC \uB85C\uAE45, \uBE44\uC6A9 \uCD94\uC801. \uD504\uB85C\uC81D\uD2B8 \uB8E8\uD2B8\uC5D0 <code>aegis.yaml</code>\uC744 \uB123\uACE0 <code>aegis.auto_instrument()</code>\uB97C \uD638\uCD9C\uD558\uC138\uC694.',
    'init.config.hint': '\uD504\uB85C\uC81D\uD2B8 \uB8E8\uD2B8\uC5D0 \uC774 \uD30C\uC77C\uC744 \uB123\uC73C\uC138\uC694',
    'init.run': 'aegis.auto_instrument() \uC2E4\uD589',
    'init.test.title': '\uD14C\uC2A4\uD2B8 \uC785\uB825',
    'init.test.hint': '\uD14D\uC2A4\uD2B8\uB97C \uBD99\uC5EC\uB123\uACE0 \uAC00\uB4DC\uB808\uC77C\uC744 \uD655\uC778\uD558\uC138\uC694',
    'init.test.placeholder': 'PII \uD0D0\uC9C0 + \uC778\uC81D\uC158 \uCC28\uB2E8\uC744 \uD14C\uC2A4\uD2B8\uD560 \uD14D\uC2A4\uD2B8\uB97C \uC785\uB825\uD558\uC138\uC694...\n\n\uC608\uC2DC: \uC81C \uC774\uBA54\uC77C\uC740 john@example.com\uC774\uACE0 \uCE74\uB4DC\uBC88\uD638\uB294 4532-0151-2345-6789\uC785\uB2C8\uB2E4',
    'init.results.title': '\uAC00\uB4DC\uB808\uC77C \uACB0\uACFC',
    'init.results.status': '\uCD08\uAE30\uD654 \uB300\uAE30 \uC911...',
    'init.masked.title': '\uC815\uD654\uB41C \uCD9C\uB825',
    'init.activate.title': '\uD65C\uC131\uD654 \uBC29\uBC95 2\uAC00\uC9C0',
    'init.frameworks.title': '\uC9C0\uC6D0 \uD504\uB808\uC784\uC6CC\uD06C (11\uAC1C)',
    'init.defaults.title': '\uAE30\uBCF8 \uAC00\uB4DC\uB808\uC77C (\uC124\uC815 \uBD88\uD544\uC694)',
    'init.sample.pii': '\uAC1C\uC778\uC815\uBCF4 \uC0D8\uD50C',
    'init.sample.injection': '\uC778\uC81D\uC158 \uC0D8\uD50C',
    'init.sample.mixed': '\uBCF5\uD569 \uACF5\uACA9',
    'init.sample.clean': '\uC815\uC0C1 \uD14D\uC2A4\uD2B8',

    // Default guardrails table
    'guard.header.name': '\uAC00\uB4DC\uB808\uC77C',
    'guard.header.default': '\uAE30\uBCF8\uAC12',
    'guard.header.catches': '\uD0D0\uC9C0 \uB300\uC0C1',
    'guard.injection': '\uD504\uB86C\uD504\uD2B8 \uC778\uC81D\uC158',
    'guard.injection.catches': '85\uAC1C \uC774\uC0C1 \uD328\uD134, \uB2E4\uAD6D\uC5B4 \uC9C0\uC6D0 (EN/KO/ZH/JA)',
    'guard.pii': '\uAC1C\uC778\uC815\uBCF4 \uD0D0\uC9C0',
    'guard.pii.catches': '12\uAC1C \uCE74\uD14C\uACE0\uB9AC (\uC774\uBA54\uC77C, \uC2E0\uC6A9\uCE74\uB4DC, SSN, API \uD0A4 \uB4F1)',
    'guard.leak': '\uD504\uB86C\uD504\uD2B8 \uC720\uCD9C',
    'guard.leak.catches': '\uC2DC\uC2A4\uD15C \uD504\uB86C\uD504\uD2B8 \uCD94\uCD9C \uC2DC\uB3C4 \uD0D0\uC9C0',
    'guard.toxicity': '\uC720\uD574\uC131',
    'guard.toxicity.catches': '\uC720\uD574/\uC545\uC758\uC801 \uCF58\uD150\uCE20 (\uCC28\uB2E8\uC740 \uC120\uD0DD\uC801)',

    // Policy panel
    'policy.title': '\uC815\uCC45 \uD3B8\uC9D1\uAE30',
    'policy.preset': '\uD504\uB9AC\uC14B:',
    'policy.actions.title': '\uD14C\uC2A4\uD2B8 \uC561\uC158',
    'policy.result.title': '\uACB0\uACFC',
    'policy.export': '\uB0B4\uBCF4\uB0B4\uAE30',

    // PII panel
    'pii.title': '\uAC1C\uC778\uC815\uBCF4 \uC2A4\uCE90\uB108',
    'pii.desc': '\uC544\uB798\uC5D0 \uD14D\uC2A4\uD2B8\uB97C \uBD99\uC5EC\uB123\uC73C\uBA74 \uC2E4\uC2DC\uAC04\uC73C\uB85C \uAC1C\uC778\uC815\uBCF4\uB97C \uD0D0\uC9C0\uD569\uB2C8\uB2E4.',
    'pii.input.placeholder': 'PII \uC2A4\uCE94\uD560 \uD14D\uC2A4\uD2B8\uB97C \uBD99\uC5EC\uB123\uC73C\uC138\uC694...',
    'pii.categories': '\uCE74\uD14C\uACE0\uB9AC',
    'pii.results': '\uD0D0\uC9C0 \uACB0\uACFC',

    // Injection panel
    'injection.title': '\uD504\uB86C\uD504\uD2B8 \uC778\uC81D\uC158 \uD0D0\uC9C0\uAE30',
    'injection.desc': '\uC785\uB825 \uD14D\uC2A4\uD2B8\uC5D0 \uD504\uB86C\uD504\uD2B8 \uC778\uC81D\uC158 \uACF5\uACA9\uC774 \uD3EC\uD568\uB418\uC5B4 \uC788\uB294\uC9C0 \uD14C\uC2A4\uD2B8\uD569\uB2C8\uB2E4.',

    // MCP panel
    'mcp.title': 'MCP \uBCF4\uC548 \uC2A4\uCE90\uB108',
    'mcp.desc': 'MCP \uB3C4\uAD6C \uC815\uC758\uC5D0\uC11C \uBCF4\uC548 \uC704\uD5D8\uC744 \uBD84\uC11D\uD569\uB2C8\uB2E4: \uB3C4\uAD6C \uD3EC\uC774\uC988\uB2DD, \uC228\uACA8\uC9C4 \uBA85\uB839 \uB4F1.',

    // Cost panel
    'cost.title': '\uBE44\uC6A9 \uCC28\uB2E8\uAE30',
    'cost.desc': 'AI API \uBE44\uC6A9\uC744 \uC2E4\uC2DC\uAC04 \uCD94\uC801\uD558\uACE0 \uC608\uC0B0 \uD55C\uB3C4\uB97C \uC801\uC6A9\uD569\uB2C8\uB2E4.',

    // Audit panel
    'audit.title': '\uAC10\uC0AC \uCCB4\uC778 \uC2DC\uAC01\uD654',
    'audit.desc': 'SHA-256 \uD574\uC2DC \uC5F0\uACB0 \uC704\uBCC0\uC870 \uBC29\uC9C0 \uAC10\uC0AC \uCD94\uC801.',

    // Regulatory panel
    'regulatory.title': '\uADDC\uC81C \uC900\uC218 \uD3C9\uAC00',
    'regulatory.desc': 'AI \uC5D0\uC774\uC804\uD2B8 \uC124\uC815\uC744 \uADDC\uC81C \uD504\uB808\uC784\uC6CC\uD06C\uC5D0 \uB530\uB77C \uD3C9\uAC00\uD569\uB2C8\uB2E4.',

    // Streaming panel
    'streaming.title': '\uC2A4\uD2B8\uB9AC\uBC0D \uAC00\uB4DC',
    'streaming.desc': 'Aegis\uAC00 \uC2A4\uD2B8\uB9AC\uBC0D LLM \uC751\uB2F5\uC744 \uC2E4\uC2DC\uAC04\uC73C\uB85C \uBCF4\uD638\uD558\uB294 \uBAA8\uC2B5\uC744 \uD655\uC778\uD558\uC138\uC694.',
    'streaming.unguarded': '\uBE44\uBCF4\uD638 \uC2A4\uD2B8\uB9BC',
    'streaming.guarded': 'Aegis \uBCF4\uD638 \uC2A4\uD2B8\uB9BC',

    // Common
    'common.run': '\uC2E4\uD589',
    'common.clear': '\uCD08\uAE30\uD654',
    'common.copy': '\uBCF5\uC0AC',
    'common.reset': '\uB9AC\uC14B',
    'common.block': '\uCC28\uB2E8',
    'common.warn': '\uACBD\uACE0',
    'common.auto': '\uC790\uB3D9',
    'common.close': '\uB2EB\uAE30',

    // Footer / CTA
    'cta.install': 'pip install agent-aegis',
    'cta.docs': '\uBB38\uC11C \uBCF4\uAE30',
    'cta.github': 'GitHub\uC5D0\uC11C \uBCF4\uAE30',

    // Language toggle
    'lang.switch': 'EN',
  },
};

/* ------------------------------------------------------------------ */
/*  Engine                                                             */
/* ------------------------------------------------------------------ */

let _lang = localStorage.getItem('aegis-lang') || (navigator.language.startsWith('ko') ? 'ko' : 'en');

/** Return translated string for the current language. */
function t(key) {
  const map = I18N[_lang] || I18N.en;
  return map[key] ?? I18N.en[key] ?? key;
}

/** Apply all data-i18n translations to the DOM. */
function applyI18n() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    const val = t(key);
    if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
      el.placeholder = val;
    } else {
      el.innerHTML = val;
    }
  });
  // Update lang attribute
  document.documentElement.lang = _lang === 'ko' ? 'ko' : 'en';
  // Update toggle button text
  const btn = document.getElementById('lang-toggle');
  if (btn) btn.textContent = t('lang.switch');
}

/** Switch language and persist. */
function setLang(lang) {
  _lang = lang;
  localStorage.setItem('aegis-lang', lang);
  applyI18n();
}

/** Get current language. */
function getLang() {
  return _lang;
}

/** Toggle between en and ko. */
function toggleLang() {
  setLang(_lang === 'en' ? 'ko' : 'en');
}

// Auto-apply on DOMContentLoaded
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', applyI18n);
} else {
  applyI18n();
}
