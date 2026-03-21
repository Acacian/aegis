# Deploy an Aegis Playground on HuggingFace Spaces

Want to let your team -- or the whole internet -- try Aegis policies in a
browser? The **Gradio playground** is a zero-backend, interactive UI where
users write YAML policies, fire actions, and see governance decisions in
real time.

Deploy it to [HuggingFace Spaces](https://huggingface.co/spaces) and you
get a shareable URL in under five minutes.

**What you will build:** A hosted web app where anyone can edit YAML policies,
evaluate single or batch actions, and instantly see risk levels, approval
decisions, and matched rules.

**Time:** 5 minutes.

---

## Prerequisites

For local development:

```bash
pip install agent-aegis gradio pyyaml
```

For HuggingFace Spaces deployment, you only need a free
[HuggingFace account](https://huggingface.co/join).

---

## What the Playground Does

The Gradio demo provides two core workflows in a single page:

1. **Single evaluation** -- Type an action type, target, and optional JSON
   params. Click **Evaluate** to see the policy decision: risk level,
   approval status, matched rule, and whether the action is allowed.

2. **Batch evaluation** -- Click **Run All Common Actions** to fire a
   predefined set of actions (`read`, `write`, `bulk_update`, `delete`)
   against the current policy. This shows how different rules interact
   without manually testing each one.

The policy editor on the left is live YAML. Change a rule, click Evaluate,
and the result updates instantly -- no server restart, no page reload.

---

## Run Locally

```bash
python examples/gradio_demo.py
```

Gradio starts a local server (typically `http://127.0.0.1:7860`) and opens
your browser. Edit the YAML policy on the left, enter an action on the right,
and click **Evaluate**.

---

## Deploy to HuggingFace Spaces

### Step 1: Create a Space

1. Go to [huggingface.co/new-space](https://huggingface.co/new-space).
2. Name your Space (e.g., `aegis-playground`).
3. Select **Gradio** as the SDK.
4. Choose visibility (public or private).
5. Click **Create Space**.

### Step 2: Add Files

Your Space needs exactly two files:

**`app.py`** -- Copy the contents of
[`examples/gradio_demo.py`](https://github.com/Acacian/aegis/blob/main/examples/gradio_demo.py):

```bash
# From the aegis repo root
cp examples/gradio_demo.py app.py
```

**`requirements.txt`** -- List the Python dependencies:

```text
agent-aegis
pyyaml
```

!!! note "Gradio is pre-installed"
    HuggingFace Spaces with the Gradio SDK already have `gradio` installed.
    You do not need to include it in `requirements.txt`.

### Step 3: Push

Using the HuggingFace CLI:

```bash
pip install huggingface_hub
huggingface-cli login

# Clone your Space
git clone https://huggingface.co/spaces/YOUR_USERNAME/aegis-playground
cd aegis-playground

# Add the files
cp /path/to/aegis/examples/gradio_demo.py app.py
echo -e "agent-aegis\npyyaml" > requirements.txt

git add app.py requirements.txt
git commit -m "Initial Aegis playground"
git push
```

Or upload directly through the HuggingFace web UI:

1. Open your Space's **Files** tab.
2. Click **Add file > Upload files**.
3. Upload `app.py` and `requirements.txt`.

HuggingFace builds and deploys automatically. Within a minute or two,
your playground is live at `https://huggingface.co/spaces/YOUR_USERNAME/aegis-playground`.

---

## Code Walkthrough

The demo lives in a single file:
[`examples/gradio_demo.py`](https://github.com/Acacian/aegis/blob/main/examples/gradio_demo.py).

### Default Policy

The `DEFAULT_POLICY` string is a YAML policy pre-loaded into the editor.
It defines four rules that cover the most common governance patterns:

| Rule | Match | Risk | Decision |
|------|-------|------|----------|
| `read_safe` | `read*` | low | auto-approve |
| `write_review` | `write*` | medium | needs approval |
| `bulk_high` | `bulk_*` with `count > 100` | high | needs approval |
| `delete_block` | `delete*` | critical | blocked |

Users can edit this YAML freely. Invalid YAML shows a clear error message
instead of crashing the UI.

### The `evaluate` Function

```python
def evaluate(policy_yaml, action_type, target, params_json):
```

This is the core handler wired to the **Evaluate** button. It:

1. Parses the YAML string into a `Policy` object.
2. Parses the optional JSON params.
3. Creates an `Action` and calls `policy.evaluate(action)`.
4. Formats the `PolicyDecision` as a Markdown result card showing
   risk level, approval decision, matched rule, and allowed status.

Error handling is built in -- malformed YAML or JSON returns a user-friendly
error string instead of a traceback.

### The `batch_evaluate` Function

```python
def batch_evaluate(policy_yaml):
```

Runs four predefined actions (`read`, `write`, `bulk_update` with
`count: 150`, and `delete`) against the current policy. This lets users
see how their rules behave across a realistic spread of action types
without manual entry.

### Gradio UI Layout

The interface uses `gr.Blocks` with a two-column layout:

- **Left column:** A multi-line `Textbox` for the YAML policy editor.
- **Right column:** Input fields for action type, target, and JSON params,
  plus two buttons (Evaluate and Run All Common Actions) and a Markdown
  output area for results.

The `gr.themes.Soft()` theme gives a clean, professional look suitable
for demos and internal tools.

---

## Customizing the Interface

### Change the Default Policy

Replace the `DEFAULT_POLICY` string with your own rules. For example,
a finance-focused policy:

```python
DEFAULT_POLICY = """\
version: "1"
defaults:
  risk_level: high
  approval: block

rules:
  - name: read_reports
    match: { type: "read_report" }
    risk_level: low
    approval: auto

  - name: approve_transactions
    match: { type: "transaction" }
    conditions:
      param_lte: { amount: 10000 }
    risk_level: medium
    approval: approve

  - name: block_large_transactions
    match: { type: "transaction" }
    conditions:
      param_gt: { amount: 10000 }
    risk_level: critical
    approval: block
"""
```

### Change the Batch Actions

Edit the `actions` list in `batch_evaluate` to match your domain:

```python
actions = [
    ("read_report", "finance", {}),
    ("transaction", "payments", {"amount": 500}),
    ("transaction", "payments", {"amount": 50000}),
    ("wire_transfer", "banking", {"destination": "external"}),
]
```

### Add a Title and Branding

Update the `gr.Markdown` header block:

```python
gr.Markdown(
    """
# Your Company -- Policy Playground

Test governance rules for our AI agent fleet.
Contact: platform-team@yourcompany.com
"""
)
```

### Add Example Presets

Gradio supports `gr.Examples` for one-click preset inputs:

```python
gr.Examples(
    examples=[
        ["read", "crm", "{}"],
        ["write", "database", '{"table": "users"}'],
        ["delete", "storage", '{"id": "all"}'],
        ["bulk_update", "crm", '{"count": 200}'],
    ],
    inputs=[action_type, target, params_input],
    label="Try these examples",
)
```

Place this inside the right column, before `result_output`.

### Change the Theme

Gradio ships several built-in themes:

```python
# Dark theme
theme = gr.themes.Base(primary_hue="blue")

# Monochrome
theme = gr.themes.Monochrome()

# Default soft
theme = gr.themes.Soft()
```

Pass the theme to `gr.Blocks(theme=theme)`.

### Add Authentication

For private deployments on HuggingFace Spaces, enable the built-in
auth gate:

```python
demo.launch(auth=("admin", "your-password"))
```

Or use HuggingFace's native Space access controls by setting the Space
to **private** and sharing access with specific users or organizations.

---

## Troubleshooting

**Space build fails with import error:**
Make sure `requirements.txt` includes `agent-aegis` and `pyyaml`.
Do not include `gradio` -- it is pre-installed by the Spaces SDK.

**YAML parse errors on valid-looking YAML:**
Check for tabs. YAML requires spaces for indentation. The Gradio textbox
may insert tabs depending on browser settings.

**Space is slow to load:**
Free-tier Spaces have cold starts. The first load after inactivity can
take 20-30 seconds while the container boots. Upgrade to a persistent
Space for always-on availability.

---

## Next Steps

- [Policy syntax reference](../guides/policies.md) -- all match patterns, conditions, and operators
- [REST API Server](../guides/rest-api.md) -- deploy Aegis as an HTTP service
- [Docker deployment](docker-rest-api.md) -- containerized REST API with production hardening
- [Production deployment](../guides/deployment.md) -- Kubernetes, monitoring, and checklists
