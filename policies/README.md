# Policy Templates

Ready-to-use governance policies for common AI agent use cases. Copy one and customize it.

| Template | Use Case | Risk Profile |
|----------|----------|-------------|
| [crm-agent.yaml](crm-agent.yaml) | Salesforce, HubSpot, CRM agents | Read=auto, Write=approve, Delete=block |
| [code-agent.yaml](code-agent.yaml) | Coding assistants (Cursor, Copilot) | Read=auto, Write=approve, Shell=high, Deploy=block |
| [financial-agent.yaml](financial-agent.yaml) | Payments, invoicing, accounting | View=auto, Small payments=approve, Transfers=critical |
| [browser-agent.yaml](browser-agent.yaml) | Browser automation (Playwright) | Navigate=auto, Click=approve, JS eval=block |
| [data-pipeline.yaml](data-pipeline.yaml) | ETL, database operations | SELECT=auto, INSERT=approve, DROP=block |
| [devops-agent.yaml](devops-agent.yaml) | CI/CD, infrastructure, deployments | Monitor=auto, Deploy=approve, Destroy=block |
| [healthcare-agent.yaml](healthcare-agent.yaml) | Healthcare, EHR, patient data (HIPAA) | Search=auto, PHI=approve, Delete=block |

## Usage

```python
from aegis import Policy, Runtime

policy = Policy.from_yaml("policies/crm-agent.yaml")
runtime = Runtime(executor=your_executor, policy=policy)
```

## Customizing

Each template is a starting point. Common customizations:

- Change `approval: block` to `approval: approve` if you want human review instead of hard blocks
- Add `conditions` for time-based or parameter-based rules
- Adjust `param_gt`/`param_lte` thresholds for your use case
- Add `match: { target: "specific_system" }` to scope rules to particular targets

See the [Policy Writing Guide](https://acacian.github.io/aegis/guides/policies/) for full syntax.
