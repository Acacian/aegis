/**
 * Policy presets for the Agent-Aegis Playground.
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

  // --- Industry Templates ---

  crm: `version: "1"
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

  - name: search_auto
    match: { type: "search" }
    risk_level: low
    approval: auto

  - name: create_approve
    match: { type: "create" }
    risk_level: medium
    approval: approve

  - name: update_approve
    match: { type: "update" }
    risk_level: medium
    approval: approve

  - name: bulk_high
    match: { type: "bulk_*" }
    conditions:
      param_gt: { count: 50 }
    risk_level: high
    approval: approve

  - name: export_approve
    match: { type: "export" }
    risk_level: high
    approval: approve

  - name: delete_block
    match: { type: "delete" }
    risk_level: critical
    approval: block

  - name: merge_approve
    match: { type: "merge" }
    risk_level: high
    approval: approve
`,

  code: `version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: read_file_auto
    match: { type: "read_file" }
    risk_level: low
    approval: auto

  - name: list_dir_auto
    match: { type: "list_dir" }
    risk_level: low
    approval: auto

  - name: search_auto
    match: { type: "search" }
    risk_level: low
    approval: auto

  - name: write_file_approve
    match: { type: "write_file" }
    risk_level: medium
    approval: approve

  - name: shell_high
    match: { type: "shell" }
    risk_level: high
    approval: approve

  - name: git_approve
    match: { type: "git_*" }
    risk_level: medium
    approval: approve

  - name: install_high
    match: { type: "install" }
    risk_level: high
    approval: approve

  - name: delete_file_block
    match: { type: "delete_file" }
    risk_level: critical
    approval: block

  - name: deploy_block
    match: { type: "deploy" }
    risk_level: critical
    approval: block
`,

  financial: `version: "1"
defaults:
  risk_level: high
  approval: approve

rules:
  - name: view_auto
    match: { type: "view" }
    risk_level: low
    approval: auto

  - name: read_auto
    match: { type: "read" }
    risk_level: low
    approval: auto

  - name: report_auto
    match: { type: "report" }
    risk_level: low
    approval: auto

  - name: create_invoice
    match: { type: "create_invoice" }
    risk_level: medium
    approval: approve

  - name: payment_small
    match: { type: "payment" }
    conditions:
      param_lte: { amount: 100 }
    risk_level: medium
    approval: approve

  - name: payment_large
    match: { type: "payment" }
    conditions:
      param_gt: { amount: 100 }
    risk_level: high
    approval: approve

  - name: refund_approve
    match: { type: "refund" }
    risk_level: high
    approval: approve

  - name: transfer_critical
    match: { type: "transfer" }
    risk_level: critical
    approval: approve

  - name: delete_block
    match: { type: "delete" }
    risk_level: critical
    approval: block

  - name: after_hours_block
    match: { type: "*" }
    conditions:
      time_after: "20:00"
    risk_level: critical
    approval: block
`,

  browser: `version: "1"
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

  - name: screenshot_auto
    match: { type: "screenshot" }
    risk_level: low
    approval: auto

  - name: scroll_auto
    match: { type: "scroll" }
    risk_level: low
    approval: auto

  - name: click_approve
    match: { type: "click" }
    risk_level: medium
    approval: approve

  - name: fill_approve
    match: { type: "fill" }
    risk_level: medium
    approval: approve

  - name: submit_high
    match: { type: "submit" }
    risk_level: high
    approval: approve

  - name: upload_high
    match: { type: "upload" }
    risk_level: high
    approval: approve

  - name: eval_block
    match: { type: "eval" }
    risk_level: critical
    approval: block

  - name: execute_js_block
    match: { type: "execute_js" }
    risk_level: critical
    approval: block
`,

  "data-pipeline": `version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: select_auto
    match: { type: "select" }
    risk_level: low
    approval: auto

  - name: read_auto
    match: { type: "read" }
    risk_level: low
    approval: auto

  - name: insert_approve
    match: { type: "insert" }
    risk_level: medium
    approval: approve

  - name: update_approve
    match: { type: "update" }
    risk_level: medium
    approval: approve

  - name: staging_auto
    match: { target: "staging*" }
    risk_level: low
    approval: auto

  - name: prod_write_high
    match: { target: "prod*" }
    risk_level: high
    approval: approve

  - name: bulk_large
    match: { type: "bulk_*" }
    conditions:
      param_gt: { rows: 10000 }
    risk_level: high
    approval: approve

  - name: schema_critical
    match: { type: "alter_*" }
    risk_level: critical
    approval: approve

  - name: drop_block
    match: { type: "drop" }
    risk_level: critical
    approval: block

  - name: delete_block
    match: { type: "delete" }
    risk_level: critical
    approval: block

  - name: truncate_block
    match: { type: "truncate" }
    risk_level: critical
    approval: block
`,

  devops: `version: "1"
defaults:
  risk_level: high
  approval: approve

rules:
  - name: monitor_auto
    match: { type: "monitor" }
    risk_level: low
    approval: auto

  - name: view_logs_auto
    match: { type: "view_logs" }
    risk_level: low
    approval: auto

  - name: status_auto
    match: { type: "status" }
    risk_level: low
    approval: auto

  - name: list_auto
    match: { type: "list_*" }
    risk_level: low
    approval: auto

  - name: build_approve
    match: { type: "build" }
    risk_level: medium
    approval: approve

  - name: staging_deploy
    match: { type: "deploy" }
    conditions:
      param_eq: { env: "staging" }
      time_after: "09:00"
      time_before: "18:00"
      weekdays: [1, 2, 3, 4, 5]
    risk_level: medium
    approval: auto

  - name: prod_deploy
    match: { type: "deploy" }
    conditions:
      param_eq: { env: "production" }
    risk_level: high
    approval: approve

  - name: scale_up_approve
    match: { type: "scale_up" }
    risk_level: high
    approval: approve

  - name: rollback_approve
    match: { type: "rollback" }
    risk_level: high
    approval: approve

  - name: destroy_block
    match: { type: "destroy" }
    risk_level: critical
    approval: block

  - name: force_push_block
    match: { type: "force_push" }
    risk_level: critical
    approval: block
`,

  healthcare: `version: "1"
defaults:
  risk_level: high
  approval: approve

rules:
  - name: view_schedule_auto
    match: { type: "view_schedule" }
    risk_level: low
    approval: auto

  - name: search_auto
    match: { type: "search" }
    risk_level: low
    approval: auto

  - name: view_patient_approve
    match: { type: "view_patient" }
    risk_level: medium
    approval: approve

  - name: access_phi_high
    match: { type: "access_phi" }
    risk_level: high
    approval: approve

  - name: create_note_approve
    match: { type: "create_note" }
    risk_level: medium
    approval: approve

  - name: order_approve
    match: { type: "order" }
    risk_level: high
    approval: approve

  - name: prescribe_critical
    match: { type: "prescribe" }
    risk_level: critical
    approval: approve

  - name: export_phi_critical
    match: { type: "export" }
    risk_level: critical
    approval: approve

  - name: modify_patient_block
    match: { type: "modify_patient" }
    risk_level: critical
    approval: block

  - name: delete_block
    match: { type: "delete" }
    risk_level: critical
    approval: block
`,

  ecommerce: `version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: view_auto
    match: { type: "view_*" }
    risk_level: low
    approval: auto

  - name: search_auto
    match: { type: "search" }
    risk_level: low
    approval: auto

  - name: check_inventory_auto
    match: { type: "check_inventory" }
    risk_level: low
    approval: auto

  - name: update_order_approve
    match: { type: "update_order" }
    risk_level: medium
    approval: approve

  - name: refund_small
    match: { type: "refund" }
    conditions:
      param_lte: { amount: 25 }
    risk_level: medium
    approval: auto

  - name: refund_large
    match: { type: "refund" }
    conditions:
      param_gt: { amount: 25 }
    risk_level: high
    approval: approve

  - name: change_price_high
    match: { type: "change_price" }
    risk_level: high
    approval: approve

  - name: delete_product_block
    match: { type: "delete_product" }
    risk_level: critical
    approval: block

  - name: cancel_all_block
    match: { type: "cancel_all" }
    risk_level: critical
    approval: block
`,

  support: `version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: read_auto
    match: { type: "read_*" }
    risk_level: low
    approval: auto

  - name: search_auto
    match: { type: "search" }
    risk_level: low
    approval: auto

  - name: draft_auto
    match: { type: "draft" }
    risk_level: low
    approval: auto

  - name: tag_auto
    match: { type: "tag" }
    risk_level: low
    approval: auto

  - name: escalate_auto
    match: { type: "escalate" }
    risk_level: low
    approval: auto

  - name: send_response_approve
    match: { type: "send_response" }
    risk_level: medium
    approval: approve

  - name: close_ticket_approve
    match: { type: "close_ticket" }
    risk_level: medium
    approval: approve

  - name: issue_credit_approve
    match: { type: "issue_credit" }
    conditions:
      param_lte: { amount: 50 }
    risk_level: medium
    approval: approve

  - name: modify_account_high
    match: { type: "modify_account" }
    risk_level: high
    approval: approve

  - name: delete_ticket_block
    match: { type: "delete_ticket" }
    risk_level: critical
    approval: block
`,

  research: `version: "1"
defaults:
  risk_level: medium
  approval: approve

rules:
  - name: search_auto
    match: { type: "search" }
    risk_level: low
    approval: auto

  - name: read_auto
    match: { type: "read*" }
    risk_level: low
    approval: auto

  - name: fetch_auto
    match: { type: "fetch" }
    risk_level: low
    approval: auto

  - name: summarize_auto
    match: { type: "summarize" }
    risk_level: low
    approval: auto

  - name: draft_auto
    match: { type: "draft" }
    risk_level: low
    approval: auto

  - name: save_approve
    match: { type: "save" }
    risk_level: medium
    approval: approve

  - name: send_approve
    match: { type: "send" }
    risk_level: medium
    approval: approve

  - name: publish_high
    match: { type: "publish" }
    risk_level: high
    approval: approve

  - name: delete_block
    match: { type: "delete" }
    risk_level: critical
    approval: block
`,
};

/**
 * Suggested actions for each preset, so users can quickly test relevant scenarios.
 */
const PRESET_ACTIONS = {
  crm: [
    { action_type: "search", target: "crm", params: { query: "John" }, description: "Search contacts" },
    { action_type: "create", target: "crm", params: { name: "New Lead" }, description: "Create lead" },
    { action_type: "export", target: "crm", params: { format: "csv" }, description: "Export contacts" },
    { action_type: "delete", target: "crm", params: { id: "12345" }, description: "Delete contact" },
  ],
  code: [
    { action_type: "read_file", target: "repo", params: { path: "src/main.py" }, description: "Read source file" },
    { action_type: "write_file", target: "repo", params: { path: "src/main.py", content: "..." }, description: "Edit file" },
    { action_type: "shell", target: "repo", params: { command: "npm test" }, description: "Run shell command" },
    { action_type: "deploy", target: "production", params: { version: "1.2.0" }, description: "Deploy to prod" },
  ],
  financial: [
    { action_type: "view", target: "accounting", params: { account: "main" }, description: "View account" },
    { action_type: "payment", target: "vendor", params: { amount: 50, currency: "USD" }, description: "Small payment ($50)" },
    { action_type: "payment", target: "vendor", params: { amount: 5000, currency: "USD" }, description: "Large payment ($5k)" },
    { action_type: "transfer", target: "bank", params: { amount: 10000, to: "external" }, description: "Wire transfer" },
  ],
  browser: [
    { action_type: "navigate", target: "browser", params: { url: "https://example.com" }, description: "Navigate to URL" },
    { action_type: "click", target: "browser", params: { selector: "#login-btn" }, description: "Click button" },
    { action_type: "fill", target: "browser", params: { selector: "#email", value: "user@example.com" }, description: "Fill form" },
    { action_type: "eval", target: "browser", params: { script: "document.title" }, description: "Execute JavaScript" },
  ],
  "data-pipeline": [
    { action_type: "select", target: "staging_db", params: { table: "users" }, description: "SELECT from staging" },
    { action_type: "insert", target: "prod_db", params: { table: "logs", rows: 100 }, description: "INSERT to prod" },
    { action_type: "alter_table", target: "prod_db", params: { table: "users", add: "email" }, description: "ALTER TABLE" },
    { action_type: "drop", target: "prod_db", params: { table: "temp_data" }, description: "DROP TABLE" },
  ],
  devops: [
    { action_type: "view_logs", target: "app", params: { service: "api" }, description: "View app logs" },
    { action_type: "build", target: "ci", params: { branch: "main" }, description: "Trigger build" },
    { action_type: "deploy", target: "infra", params: { env: "staging" }, description: "Deploy to staging" },
    { action_type: "deploy", target: "infra", params: { env: "production" }, description: "Deploy to prod" },
    { action_type: "destroy", target: "infra", params: { resource: "cluster" }, description: "Destroy infra" },
  ],
  healthcare: [
    { action_type: "view_schedule", target: "ehr", params: { date: "today" }, description: "View schedule" },
    { action_type: "view_patient", target: "ehr", params: { id: "P-12345" }, description: "View patient record" },
    { action_type: "access_phi", target: "ehr", params: { field: "ssn" }, description: "Access PHI (SSN)" },
    { action_type: "prescribe", target: "ehr", params: { drug: "amoxicillin" }, description: "Prescribe medication" },
    { action_type: "delete", target: "ehr", params: { id: "P-12345" }, description: "Delete patient data" },
  ],
  ecommerce: [
    { action_type: "search", target: "store", params: { query: "laptop" }, description: "Search products" },
    { action_type: "update_order", target: "store", params: { id: "ORD-789", status: "shipped" }, description: "Update order" },
    { action_type: "refund", target: "store", params: { amount: 15, order: "ORD-100" }, description: "Small refund ($15)" },
    { action_type: "refund", target: "store", params: { amount: 500, order: "ORD-200" }, description: "Large refund ($500)" },
    { action_type: "delete_product", target: "store", params: { sku: "PROD-999" }, description: "Delete product" },
  ],
  support: [
    { action_type: "search", target: "helpdesk", params: { query: "billing issue" }, description: "Search tickets" },
    { action_type: "draft", target: "helpdesk", params: { ticket: "T-456" }, description: "Draft response" },
    { action_type: "send_response", target: "helpdesk", params: { ticket: "T-456" }, description: "Send to customer" },
    { action_type: "escalate", target: "helpdesk", params: { ticket: "T-789", to: "tier2" }, description: "Escalate ticket" },
    { action_type: "delete_ticket", target: "helpdesk", params: { ticket: "T-001" }, description: "Delete ticket" },
  ],
  research: [
    { action_type: "search", target: "web", params: { query: "AI governance 2025" }, description: "Web search" },
    { action_type: "fetch", target: "web", params: { url: "arxiv.org/..." }, description: "Fetch paper" },
    { action_type: "summarize", target: "docs", params: { doc: "report.pdf" }, description: "Summarize document" },
    { action_type: "publish", target: "blog", params: { title: "Findings" }, description: "Publish externally" },
    { action_type: "delete", target: "kb", params: { id: "DOC-100" }, description: "Delete research" },
  ],
};
