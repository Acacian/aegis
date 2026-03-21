/**
 * Policy presets for the Aegis Playground.
 */
const POLICY_PRESETS = {
  default: `version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: navigate_auto
    match: { type: "navigate" }
    risk_level: low
    approval: auto

  - name: read_auto
    match: { type: "read" }
    risk_level: low
    approval: auto

  - name: write_approve
    match: { type: "write" }
    risk_level: medium
    approval: approve

  - name: click_approve
    match: { type: "click" }
    risk_level: medium
    approval: approve

  - name: bulk_ops_high
    match: { type: "bulk_*" }
    conditions:
      param_gt: { count: 100 }
    risk_level: high
    approval: approve

  - name: delete_block
    match: { type: "delete" }
    risk_level: critical
    approval: block
`,

  strict: `version: "1"
defaults:
  risk_level: high
  approval: approve

rules:
  - name: read_only_auto
    match: { type: "read" }
    risk_level: low
    approval: auto

  - name: navigate_approve
    match: { type: "navigate" }
    risk_level: medium
    approval: approve

  - name: any_write_block
    match: { type: "write" }
    risk_level: critical
    approval: block

  - name: any_click_block
    match: { type: "click" }
    risk_level: high
    approval: approve

  - name: bulk_block
    match: { type: "bulk_*" }
    risk_level: critical
    approval: block

  - name: delete_block
    match: { type: "delete" }
    risk_level: critical
    approval: block
`,

  permissive: `version: "1"
defaults:
  risk_level: low
  approval: auto

rules:
  - name: all_reads_auto
    match: { type: "read" }
    risk_level: low
    approval: auto

  - name: all_writes_auto
    match: { type: "write" }
    risk_level: low
    approval: auto

  - name: all_clicks_auto
    match: { type: "click" }
    risk_level: low
    approval: auto

  - name: bulk_approve
    match: { type: "bulk_*" }
    risk_level: medium
    approval: approve

  - name: delete_approve
    match: { type: "delete" }
    risk_level: high
    approval: approve
`,

  "time-based": `version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: read_always_auto
    match: { type: "read" }
    risk_level: low
    approval: auto

  - name: navigate_always_auto
    match: { type: "navigate" }
    risk_level: low
    approval: auto

  - name: write_business_hours
    match: { type: "write" }
    conditions:
      time_after: "09:00"
      time_before: "18:00"
      weekdays: [1, 2, 3, 4, 5]
    risk_level: medium
    approval: auto

  - name: bulk_small_auto
    match: { type: "bulk_*" }
    conditions:
      param_lte: { count: 50 }
    risk_level: medium
    approval: auto

  - name: bulk_large_approve
    match: { type: "bulk_*" }
    conditions:
      param_gt: { count: 50 }
    risk_level: high
    approval: approve

  - name: delete_block
    match: { type: "delete" }
    risk_level: critical
    approval: block
`,
};
