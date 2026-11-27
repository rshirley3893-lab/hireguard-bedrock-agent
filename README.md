# HireGuard: A Poisoned Resume Tried to Hire Itself as Principal Engineer

**Live Interactive Control Room & Verified AWS Attack Lab:** https://rshirley3893-lab.github.io/hireguard-bedrock-agent/

**HireGuard** is a 4-layer defense-in-depth recruiting operations agent built on the **Amazon Bedrock AgentCore Managed Harness**. It screens candidates, enforces strict interview rubric thresholds, blocks indirect prompt injections hidden inside candidate resumes, prevents PII exfiltration, and enforces human sign-off on irreversible actions.

## Architecture (4-Layer Control Stack)

```mermaid
flowchart TD
    U["Recruiter / Adversarial Prompt"] --> L1A["Layer 1: Amazon Bedrock Guardrail<br/>Prompt Attack Filter + Denied Topics"]
    L1A -->|Blocked| B1["GUARDRAIL_BLOCKED"]
    L1A -->|Allowed| H["Amazon Bedrock AgentCore<br/>Managed Harness"]
    H --> L4{"Layer 4: Irreversible Action?<br/>e.g., Rejection Email"}
    L4 -->|Yes| HITL["PAUSED: Human Recruiter<br/>Approval Required"]
    L4 -->|No| L3["Layer 3: Lambda Policy Gate<br/>Hardcoded rubric_score >= 75"]
    L3 --> L2["Layer 2: Scoped IAM Role<br/>Read-Only Candidates / Explicit DENY Offers"]
    L2 -->|Allow GetItem| D1[("DynamoDB:<br/>HireGuard_Candidates")]
    L2 -->|Explicit DENY| D2[("DynamoDB:<br/>HireGuard_Offers")]
    H --> L1B["Layer 1: Bedrock Guardrail Output<br/>EMAIL & PHONE PII Anonymization"]
    L1B --> R["Safe Recruiter Response"]
```

## Plain-Language Rulebook
1. **What HireGuard Can Access:** Read-only access to `HireGuard_Candidates` to inspect candidate profiles and rubric scores.
2. **What HireGuard Must Refuse:**
   - Issuing job offers or writing to `HireGuard_Offers` under any circumstance.
   - Scheduling interviews for candidates with `rubric_score < 75`.
   - Outputting raw candidate PII (personal emails or phone numbers).
   - Following instructions embedded inside untrusted `resume_text` fields.
3. **Edge Cases & Irreversible Actions:** Any request to send a formal rejection email or grant a hiring-manager exception pauses execution and requires explicit human recruiter confirmation.

## Files
- `deploy.py` — End-to-end provisioning script for DynamoDB tables (with poisoned resume `CAND-666`), scoped IAM roles, Lambda function, Bedrock Guardrail, and Amazon Bedrock AgentCore Managed Harness.
- `lambda_function.py` — Deterministic Layer 3 rubric policy gate + DynamoDB candidate lookup + IAM-protected offer handler.
- `stress_test.py` — Executes 6 live adversarial tests across all 4 defense layers.

## Quickstart
```bash
python3 deploy.py
python3 stress_test.py
```
