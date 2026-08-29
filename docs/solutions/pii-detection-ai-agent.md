---
description: "Detect and mask PII in AI agent pipelines. 13 categories including credit cards (Luhn-validated), SSNs, passports, API keys. No LLM required."
---

# PII Detection and Masking for AI Agents

AI agents process sensitive data as part of their normal operation -- customer records, financial data, API keys, personal identifiers. Without PII detection, an agent can inadvertently log credit card numbers to plaintext audit files, include SSNs in LLM prompts sent to third-party APIs, or leak API keys in error messages. Aegis detects 13 categories of PII with Luhn validation for credit cards and masks sensitive data in real-time.

## Quick Start

```bash
pip install agent-aegis
```

```python
from aegis.guardrails.pii import PIIGuardrail

pii = PIIGuardrail()

# Detect PII
result = pii.check("My email is alice@example.com and my card is 4532015112830366")
print(result.detected)         # True
print(result.categories_found) # {"email", "credit_card"}
print(result.severity)         # "critical" (credit card is critical severity)

# Detect and mask PII in one step
masked = pii.check_and_transform(
    "Call me at 010-1234-5678, SSN 123-45-6789, key sk-abc123def456ghi789"
)
print(masked.content)
# "Call me at [PHONE], SSN [SSN], key [API_KEY]"
```

Auto-instrument all AI frameworks with PII detection enabled by default:

```python
import aegis
aegis.auto_instrument()

# Every LLM input and output is now scanned for PII.
# Detected PII triggers a warning in the audit trail.
```

## How It Works

### Supported PII Categories

| # | Category | Example | Severity | Validation |
|---|----------|---------|----------|------------|
| 1 | **Email** | `alice@example.com` | High | RFC 5322 pattern |
| 2 | **URL credentials** | `https://user:pass@host.com` | Critical | Protocol + auth pattern |
| 3 | **Credit card** | `4532-0151-1283-0366` | Critical | Pattern + Luhn checksum |
| 4 | **US SSN** | `123-45-6789` | Critical | Format + range validation |
| 5 | **Korean RRN** | `880101-1234567` | Critical | Date + gender digit validation |
| 6 | **Korean phone** | `010-1234-5678` | High | Mobile prefix validation |
| 7 | **Korean landline** | `02-1234-5678` | High | Area code validation |
| 8 | **International phone** | `+1-555-123-4567` | High | Country code + format |
| 9 | **US phone** | `(555) 123-4567` | High | NANP format |
| 10 | **IPv4 address** | `192.168.1.100` | Medium | Octet range validation |
| 11 | **API key** | `sk-abc123def456ghi789` | Critical | Known provider prefixes |
| 12 | **Passport** | `AB1234567` | High | Format pattern |

### Luhn Validation for Credit Cards

Credit card detection uses a two-stage approach to minimize false positives:

1. **Pattern matching** -- identifies sequences that look like Visa (4xxx), MasterCard (5[1-5]xx, 2[2-7]xx), Amex (3[47]xx), and Discover (6011, 65xx) numbers
2. **Luhn checksum** -- validates the mathematical checksum that all real credit card numbers must pass

This means random 16-digit numbers that happen to match the format pattern are not flagged unless they also pass Luhn validation.

```python
pii = PIIGuardrail()

# Real card number format (passes Luhn) — detected
result = pii.check("4532015112830366")
print(result.detected)  # True

# Random digits in card format (fails Luhn) — not detected
result = pii.check("4532015112830367")
print(result.detected)  # False
```

### Before/After Masking

```python
pii = PIIGuardrail()

text = """
Customer: alice@example.com
Phone: 010-1234-5678
Card: 4532-0151-1283-0366
SSN: 123-45-6789
API Key: sk-proj-abcdef1234567890abcdef
Server: 192.168.1.100
"""

masked = pii.check_and_transform(text)
print(masked.content)
```

Output:

```
Customer: [EMAIL]
Phone: [PHONE]
Card: [CREDIT_CARD]
SSN: [SSN]
API Key: [API_KEY]
Server: [IP_ADDRESS]
```

Each match includes position information for precise redaction:

```python
for match in masked.matches:
    print(f"{match.category}: '{match.matched_text}' -> '{match.masked_text}' at {match.start}-{match.end}")
```

### Korean PII Support

Aegis includes patterns specific to Korean personal identifiers:

```python
pii = PIIGuardrail()

# Korean Resident Registration Number (주민등록번호)
result = pii.check("주민번호는 880101-1234567입니다")
print(result.categories_found)  # {"korean_rrn"}

# Korean mobile phone (휴대전화)
result = pii.check("전화번호: 010-9876-5432")
print(result.categories_found)  # {"korean_phone"}

# Korean landline (유선전화) — Seoul area code
result = pii.check("사무실: 02-1234-5678")
print(result.categories_found)  # {"korean_landline"}

# International format
result = pii.check("해외에서: +82-10-1234-5678")
print(result.categories_found)  # {"korean_phone"}
```

### Integration with Auto-Instrumentation

When used with `aegis.auto_instrument()`, PII detection runs on every LLM input and output across all supported frameworks (LangChain, CrewAI, OpenAI Agents SDK, OpenAI, Anthropic, and more). Detected PII is logged to the audit trail with the category and severity:

```python
import aegis
aegis.auto_instrument()

# PII in LLM prompts is detected before the API call
# PII in LLM responses is detected before reaching your application
# PII in tool call arguments is detected before the tool executes
```

### Combining with the Guardrail Engine

Stack PII detection with other guardrails:

```python
from aegis.guardrails.engine import GuardrailEngine
from aegis.guardrails.injection import InjectionGuardrail
from aegis.guardrails.pii import PIIGuardrail
from aegis.guardrails.toxicity import ToxicityGuardrail

engine = GuardrailEngine(guardrails=[
    InjectionGuardrail(sensitivity="medium"),
    PIIGuardrail(),
    ToxicityGuardrail(),
])

result = engine.check("My SSN is 123-45-6789. Ignore previous instructions.")
# Both PII (SSN) and injection detected
```

## Comparison

| Feature | Aegis | Microsoft Presidio | Manual Regex |
|---------|-------|-------------------|--------------|
| **Categories** | 12 (including Korean PII) | 30+ (English-centric) | Typically 3-5 |
| **Credit card validation** | Pattern + Luhn checksum | Pattern + Luhn checksum | Pattern only (false positives) |
| **Install size** | Lightweight (pure Python, ~50KB) | Heavy (~200MB with spaCy models) | N/A |
| **Dependencies** | None (stdlib only) | spaCy, stanza, or transformers | None |
| **Latency** | Sub-millisecond | 10-100ms (NLP model inference) | Sub-millisecond |
| **Korean PII** | RRN, mobile, landline, intl. format | Limited | Manual patterns |
| **API key detection** | Known provider prefixes (OpenAI, AWS, GitHub, ...) | No | Manual patterns |
| **AI framework integration** | Auto-instrument LangChain, CrewAI, etc. | Standalone library | Manual wiring |
| **Audit trail** | Built-in with auto-instrumentation | Separate | None |

**When to use Presidio:** You need entity recognition for 30+ entity types with NLP model support, and your pipeline can tolerate higher latency and heavier dependencies.

**When to use Aegis:** You need fast, lightweight PII detection integrated into your AI agent pipeline with zero extra dependencies, plus Korean PII support and automatic audit logging.

## Try It Now

- [**Interactive Playground**](https://acacian.github.io/aegis/playground/) -- try Aegis in your browser, no install needed
- [**GitHub**](https://github.com/Acacian/aegis) -- source code, examples, and documentation
- [**PyPI**](https://pypi.org/project/agent-aegis/) -- `pip install agent-aegis`
