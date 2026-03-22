#!/usr/bin/env python3
"""Enterprise Compliance Demo — Full EU AI Act / SOC2 Workflow.

Demonstrates how Aegis provides end-to-end enterprise governance:

1. Define policy using fluent PolicyBuilder API
2. Run agent actions through the governance engine
3. Detect behavioral anomalies in real-time
4. Generate cryptographic audit chain (tamper-evident)
5. Verify chain integrity
6. Run regulatory compliance gap analysis (EU AI Act, NIST, SOC2)
7. Generate evidence package for auditors

Usage:
    pip install agent-aegis
    python enterprise_compliance_demo.py
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from aegis.core.action import Action
from aegis.core.anomaly import AnomalyDetector
from aegis.core.builder import PolicyBuilder
from aegis.core.crypto_audit import CryptoAuditChain
from aegis.core.regulatory import ComplianceMapper, RegulatoryFramework


def main() -> None:
    print("=" * 60)
    print("  Aegis Enterprise Compliance Demo")
    print("  EU AI Act / SOC2 / NIST AI RMF Ready")
    print("=" * 60)

    # ── Step 1: Define policy with PolicyBuilder ──────────────
    print("\n[1] Building governance policy...")
    policy = (
        PolicyBuilder()
        .defaults(risk_level="medium", approval="approve")
        .rule("read_auto")
        .match(type="read*")
        .risk("low")
        .approve_auto()
        .rule("write_approve")
        .match(type="write*")
        .risk("medium")
        .approve_human()
        .rule("delete_block")
        .match(type="delete*")
        .risk("critical")
        .block()
        .rule("api_calls")
        .match(type="api_*")
        .risk("high")
        .approve_human()
        .build()
    )
    print(f"  Policy created: {len(policy.rules)} rules")

    # ── Step 2: Simulate agent actions ────────────────────────
    print("\n[2] Simulating agent actions...")
    actions = [
        Action(type="read", target="customer_db"),
        Action(type="read", target="analytics"),
        Action(type="write", target="crm"),
        Action(type="write", target="email_draft"),
        Action(type="api_call", target="payment_gateway"),
        Action(type="delete", target="user_record"),
        Action(type="read", target="inventory"),
    ]

    crypto_chain = CryptoAuditChain(algorithm="sha256")
    detector = AnomalyDetector(burst_limit=5, burst_window=10.0)

    for action in actions:
        result = policy.evaluate(action)
        decision = result.approval.value

        # Record in crypto audit chain
        crypto_chain.append(
            agent_id="demo-agent-1",
            action_type=action.type,
            action_target=action.target,
            decision=decision,
            risk_level=result.risk_level.value,
            matched_rule=result.matched_rule or "default",
        )

        # Check for anomalies
        detector.record(action, agent_id="demo-agent-1", blocked=(decision == "block"))
        anomaly = detector.check(action, agent_id="demo-agent-1")

        status = "ALLOWED" if decision != "block" else "BLOCKED"
        print(f"  {action.type}@{action.target}: {status} ({decision}, {result.risk_level.value})")
        if anomaly.is_anomalous:
            print(f"    ⚠ ANOMALY: {anomaly.anomaly_type} — {anomaly.message}")

    # ── Step 3: Verify audit chain integrity ──────────────────
    print("\n[3] Verifying cryptographic audit chain...")
    verification = crypto_chain.verify()
    print(f"  Chain length: {verification.chain_length}")
    print(f"  Verified entries: {verification.verified_entries}")
    print(f"  Integrity: {'PASSED' if verification.valid else 'FAILED'}")
    print(f"  Algorithm: SHA-256")

    # ── Step 4: Export chain as JSONL ─────────────────────────
    print("\n[4] Exporting tamper-evident audit log...")
    with tempfile.TemporaryDirectory() as tmp:
        chain_path = Path(tmp) / "audit_chain.jsonl"
        count = crypto_chain.export_jsonl(chain_path)
        print(f"  Exported {count} entries to {chain_path.name}")

        # ── Step 5: Generate evidence package ─────────────────
        print("\n[5] Generating compliance evidence package...")
        evidence_dir = Path(tmp) / "evidence"
        package = crypto_chain.generate_evidence_package(evidence_dir)
        print(f"  Generated at: {evidence_dir.name}/")
        print(f"  Chain hash: {package.chain_hash[:16]}...")
        print(f"  Compliance notes:")
        for note in package.compliance_notes:
            print(f"    - {note}")

    # ── Step 6: Regulatory gap analysis ───────────────────────
    print("\n[6] Running regulatory compliance analysis...")
    mapper = ComplianceMapper()

    frameworks = [
        (RegulatoryFramework.EU_AI_ACT, "EU AI Act"),
        (RegulatoryFramework.NIST_AI_RMF, "NIST AI RMF"),
        (RegulatoryFramework.SOC2, "SOC2"),
    ]

    for framework, name in frameworks:
        analysis = mapper.analyze(framework)
        print(f"\n  {name}:")
        print(f"    Requirements: {analysis.total_requirements}")
        print(f"    Fully covered: {analysis.fully_covered}")
        print(f"    Partially covered: {analysis.partially_covered}")
        print(f"    Coverage score: {analysis.coverage_score:.0f}%")
        if analysis.gaps:
            print(f"    Gaps: {len(analysis.gaps)}")

    # ── Step 7: Generate auto policy from behavior ────────────
    print("\n[7] Generating policy from observed behavior...")
    auto_policy = detector.generate_policy("demo-agent-1")
    if auto_policy:
        print(f"  Generated {len(auto_policy.get('rules', []))} rules from behavior:")
        for rule in auto_policy.get("rules", []):
            print(f"    - {rule['name']}: {rule['match']['type']} -> {rule['approval']}")

    # ── Summary ───────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  Enterprise Compliance Summary")
    print("=" * 60)
    print(f"  Actions processed: {len(actions)}")
    print(f"  Blocked: {sum(1 for a in actions if policy.evaluate(a).approval.value == 'block')}")
    print(f"  Audit chain: {verification.chain_length} entries, SHA-256 signed")
    print(f"  Chain integrity: {'VERIFIED' if verification.valid else 'BROKEN'}")
    print(f"  EU AI Act coverage: {mapper.analyze(RegulatoryFramework.EU_AI_ACT).coverage_score:.0f}%")
    print(f"  NIST AI RMF coverage: {mapper.analyze(RegulatoryFramework.NIST_AI_RMF).coverage_score:.0f}%")
    print(f"  SOC2 coverage: {mapper.analyze(RegulatoryFramework.SOC2).coverage_score:.0f}%")
    print()
    print("  This output satisfies:")
    print("  - EU AI Act Article 12 (automatic logging, tamper-resistant)")
    print("  - SOC2 CC6.1 (logical access security)")
    print("  - SOC2 CC7.2 (system monitoring)")
    print("  - NIST AI RMF GOVERN/MEASURE functions")
    print()


if __name__ == "__main__":
    main()
