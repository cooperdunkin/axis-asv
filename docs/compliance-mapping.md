# Axis Compliance Mapping

This document maps Axis capabilities to common compliance frameworks. Axis is not itself certified — it provides the technical controls that help your organization meet these requirements for AI agent credential management.

## SOC 2 Type II

| Control | Description | Axis Implementation |
|---|---|---|
| CC6.1 | Logical access security | Deny-by-default policy engine (`config/policy.yaml`). Per-identity rules with service and action granularity. Wildcard support for broad rules. Policy file is hot-reloaded — changes take effect without restart. |
| CC6.2 | Prior to issuing credentials | Credentials are encrypted at rest with AES-256-GCM. Master password derives per-service keys via PBKDF2-SHA-512 (210K iterations). No plaintext secret is ever written to disk. |
| CC6.3 | Least privilege | Every credential grant is scoped to a specific service + action combination. TTL-based grants (default 5 minutes, configurable) expire automatically. Rate limiting per identity prevents abuse. |
| CC7.1 | Detection of changes | Keystore file at `~/.axis/keystore.json` uses authenticated encryption (GCM auth tag). Tampering is detected on decryption. File permissions set to 600 (owner-only). |
| CC7.2 | System monitoring | Append-only JSONL audit log at `~/.axis/audit.jsonl`. Every request, grant, denial, and error is logged with: timestamp, agent identity, service, action, decision, and request ID. Credentials are never logged. |
| CC7.3 | Evaluation of events | `axis logs` CLI with `--service` and `--decision` filters. `axis logs --tail` for live monitoring. Dashboard at `localhost:3847` provides visual log review. |

## GDPR

| Article | Requirement | Axis Implementation |
|---|---|---|
| Art. 5(1)(c) | Data minimization | Zero-knowledge logging: audit logs record actions and outcomes, never credentials or API keys. Only metadata necessary for audit is captured. |
| Art. 5(1)(f) | Integrity and confidentiality | AES-256-GCM encryption with unique salt and IV per credential. PBKDF2-SHA-512 key derivation. Local-first architecture — no data leaves the machine except for proxied API calls. |
| Art. 25 | Data protection by design | Deny-by-default policy. Credentials are architecturally isolated from the agent — the agent cannot access raw keys by design, not just by policy. |
| Art. 32 | Security of processing | Encryption at rest, authenticated encryption (GCM), rate limiting, automatic grant expiry, append-only audit log. |

## EU AI Act

| Article | Requirement | Axis Implementation |
|---|---|---|
| Art. 9 | Risk management system | Policy engine defines permitted agent behaviors. Rate limiting prevents runaway agents. Audit log provides complete action history for risk assessment. |
| Art. 12 | Record-keeping | JSONL audit log with timestamp, identity, service, action, decision, and request ID for every agent interaction. Filterable and exportable via CLI. |
| Art. 14 | Human oversight | Deny-by-default policy means no agent can act without explicit human-authored policy rules. Policy changes require file system access. Dashboard provides real-time visibility. |

## ISO 27001:2022

| Control | Description | Axis Implementation |
|---|---|---|
| A.5.15 | Access control | Identity-based policy engine with deny-by-default. Per-service, per-action granularity. |
| A.5.33 | Protection of records | Append-only audit log. Credentials excluded by design. |
| A.8.2 | Privileged access | TTL-based grants with automatic expiry. No standing credential access for agents. |
| A.8.5 | Secure authentication | AES-256-GCM encryption. PBKDF2-SHA-512 derivation. Master password required for all operations. OS keychain integration available. |

## What Axis does NOT provide

For full transparency:
- Axis is not SOC 2, ISO 27001, or any other certified product
- Axis does not manage human user identities — it governs agent (non-human) credential access
- Axis does not provide SSO, SAML, or OAuth integration (agents authenticate via AXIS_IDENTITY env var)
- Axis does not provide centralized multi-machine management — it is a local-first, single-machine tool
- For enterprise-scale NHI governance across cloud environments, see: Oasis Security, CyberArk, Strata

These are complementary tools, not competitors. Axis is the developer layer; enterprise NHI platforms are the organizational layer.

---

*Last updated: April 2026*
