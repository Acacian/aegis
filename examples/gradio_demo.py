"""
Gradio-based Aegis demo — deployable to Hugging Face Spaces.

Usage:
    pip install agent-aegis gradio
    python examples/gradio_demo.py

To deploy to Hugging Face Spaces:
    1. Create a new Space at huggingface.co/new-space
    2. Select Gradio as the SDK
    3. Copy this file as app.py
    4. Add agent-aegis to requirements.txt
    5. Push — your governance playground is live!
"""

from __future__ import annotations

import json

try:
    import gradio as gr
except ImportError as err:
    raise ImportError("pip install gradio  # required for this demo") from err

from aegis import Action, Policy
from aegis.core.policy import Approval, RiskLevel

DEFAULT_POLICY = """\
version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: read_safe
    match: { type: "read*" }
    risk_level: low
    approval: auto

  - name: write_review
    match: { type: "write*" }
    risk_level: medium
    approval: approve

  - name: bulk_high
    match: { type: "bulk_*" }
    conditions:
      param_gt: { count: 100 }
    risk_level: high
    approval: approve

  - name: delete_block
    match: { type: "delete*" }
    risk_level: critical
    approval: block
"""


def evaluate(policy_yaml: str, action_type: str, target: str, params_json: str) -> str:
    """Evaluate an action against a policy and return results."""
    try:
        policy = Policy.from_dict(
            __import__("yaml").safe_load(policy_yaml)
        )
    except Exception as e:
        return f"Policy Error: {e}"

    params = {}
    if params_json.strip():
        try:
            params = json.loads(params_json)
        except json.JSONDecodeError as e:
            return f"Params Error: {e}"

    action = Action(action_type, target, params=params)
    decision = policy.evaluate(action)

    risk_emoji = {
        RiskLevel.LOW: "🟢",
        RiskLevel.MEDIUM: "🟡",
        RiskLevel.HIGH: "🟠",
        RiskLevel.CRITICAL: "🔴",
    }
    approval_emoji = {
        Approval.AUTO: "✅ Auto-Approved",
        Approval.APPROVE: "⏳ Needs Human Approval",
        Approval.BLOCK: "🚫 BLOCKED",
    }

    result = f"""## Evaluation Result

**Action:** `{action_type}` → `{target}`
**Params:** `{json.dumps(params)}`

---

**Risk Level:** {risk_emoji.get(decision.risk_level, "❓")} **{decision.risk_level.value}**

**Decision:** {approval_emoji.get(decision.approval, "❓")}

**Matched Rule:** `{decision.matched_rule or "(default)"}`

**Allowed:** {"✅ Yes" if decision.approval != Approval.BLOCK else "❌ No"}
"""
    return result


def batch_evaluate(policy_yaml: str) -> str:
    """Evaluate common actions against the policy."""
    actions = [
        ("read", "crm", {}),
        ("write", "crm", {"field": "name"}),
        ("bulk_update", "crm", {"count": 150}),
        ("delete", "crm", {"id": "all"}),
    ]

    results = []
    for atype, target, params in actions:
        r = evaluate(policy_yaml, atype, target, json.dumps(params))
        results.append(r)

    return "\n---\n".join(results)


# Build Gradio UI
with gr.Blocks(
    title="Aegis - AI Agent Governance",
    theme=gr.themes.Soft(),
) as demo:
    gr.Markdown(
        """
    # Aegis — AI Agent Governance

    Write YAML policies, evaluate actions, see results instantly.

    `pip install agent-aegis` | [GitHub](https://github.com/Acacian/aegis) | [Docs](https://acacian.github.io/aegis/)
    """
    )

    with gr.Row():
        with gr.Column(scale=1):
            policy_input = gr.Textbox(
                label="Policy (YAML)",
                value=DEFAULT_POLICY,
                lines=20,
                max_lines=30,
            )

        with gr.Column(scale=1):
            with gr.Group():
                action_type = gr.Textbox(
                    label="Action Type", value="read", placeholder="e.g. read, write, delete"
                )
                target = gr.Textbox(
                    label="Target", value="crm", placeholder="e.g. crm, database"
                )
                params_input = gr.Textbox(
                    label="Params (JSON)", value="{}", placeholder='{"count": 50}'
                )
                eval_btn = gr.Button("Evaluate", variant="primary")
                batch_btn = gr.Button("Run All Common Actions")

            result_output = gr.Markdown(label="Result")

    eval_btn.click(
        evaluate,
        inputs=[policy_input, action_type, target, params_input],
        outputs=result_output,
    )
    batch_btn.click(
        batch_evaluate,
        inputs=[policy_input],
        outputs=result_output,
    )

if __name__ == "__main__":
    demo.launch()
