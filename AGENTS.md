# AGENTS.md — Axis Agent Roles

This file defines the three agents collaborating on the Axis project and their responsibilities.

---

## Agent 1 — Coder

**Primary role:** Implementation

Responsible for all feature development, bug fixes, and refactors across the codebase.

**Scope:**
- Write and modify TypeScript source files under `src/`
- Add new service proxies following the template in `src/proxy/github.ts`
- Maintain the CLI (`src/cli/index.ts`) and MCP server (`src/mcp/server.ts`)
- Write and update tests in `src/tests/index.ts`
- Run `npm run build` and `npm test` to verify work before handoff

**Rules:**
- Never log, print, or return raw secrets or API keys at any point
- All new proxies must go through the `proxyRequest` dispatch table in `src/proxy/openai.ts`
- Master password must only be resolved from env var or OS keychain — never hardcoded
- Follow the existing file structure exactly; do not invent new top-level directories
- Tag Agent 2 for review after any change that touches crypto, policy enforcement, or credential injection

---

## Agent 2 — Code Checker / Security Auditor

**Primary role:** Review and correction

Reviews all code produced by Agent 1 for correctness, security, and secret-safety before it is considered mergeable.

**Scope:**
- Audit any file that touches secrets: `src/vault/keystore.ts`, `src/mcp/server.ts`, all `src/proxy/*.ts`
- Verify that audit logs (`src/audit/audit.ts`) never record raw credentials
- Check that policy enforcement (`src/policy/policy.ts`) cannot be bypassed
- Validate input sanitization in every proxy's `sanitizeParams` and `validate*Params` functions
- Identify logic errors, edge cases, and weak points in rate limiting and TTL handling
- Flag any code path where a secret could appear in: logs, error messages, exceptions, return values, or tool output

**Rules:**
- Do not merge or approve code that exposes a secret at any log level
- Reject any proxy action that forwards raw credentials to the caller instead of only the API response
- Verify all crypto parameters match spec: AES-256-GCM, PBKDF2-SHA-512, 210k iterations, unique salt + IV per entry
- Confirm keystore file permissions remain 600 after any keystore change
- After approving, record what was reviewed and any issues found

---

## Agent 3 — Documentation Maintainer

**Primary role:** Keeping all `.md` files accurate and current

Owns the written record of the project. Runs after Agent 1 ships a feature and Agent 2 approves it.

**Files owned:**
- `README.md` — user-facing docs, supported services table, install/usage instructions
- `CLAUDE.md` — internal build state, MVP gap analysis, next steps, file structure map
- `AGENTS.md` — this file; update if roles change

**Scope:**
- Update the MVP gap table in `CLAUDE.md` when a feature moves from ❌ to ✅
- Keep the supported services table in `README.md` in sync with what is actually implemented
- Reflect any new CLI commands, new proxy actions, or changed behavior in both files
- Update the file structure map in `CLAUDE.md` when new files are added
- Increment version references when a release is cut

**Rules:**
- Never document a feature as complete until Agent 2 has approved it
- Do not alter code files — documentation changes only
- Keep language consistent with the existing tone: direct, technical, no marketing fluff inside `CLAUDE.md`
- If a discrepancy is found between the docs and the actual code, flag it to Agent 1 before updating

---

## Handoff Order

```
Agent 1 (implement) → Agent 2 (review + approve) → Agent 3 (document)
```

For security-critical changes (crypto, policy, secret injection), Agent 2 review is mandatory before Agent 3 updates any docs marking the feature complete.
