# CLAUDE.md — Agent Secrets Vault (ASV)

## The Problem This Solves

AI agents in 2025–2026 (Claude Code, Cursor, Devin, GitHub Copilot Workspace) are given shell execution, filesystem access, and live API keys to do their work. Every current method of delivering those keys is broken:

- **Environment variables** — readable by any shell command: `echo $STRIPE_API_KEY`, `env | grep KEY`
- **.env files** — readable by `cat .env` or any file-read tool; persist on disk indefinitely
- **System prompt injection** — the agent sees the key in its own context; any logging of tool inputs captures the key
- **Proxy workarounds** — custom internal proxies reinvent HashiCorp Vault with massive operational overhead

**The root issue:** There is no native primitive for giving an agent time-limited, action-scoped credentials without exposing the raw secret at any point in the flow.

---

## What ASV Does

ASV is an MCP-native credential vault. The agent **never sees a raw API key**.

```
Agent (Claude Code / Cursor)
  │
  │  request_credential({ service, action, justification, params })
  ▼
ASV MCP Server ──── policy check ──── audit log
  │
  │  injects stored API key (server-side only)
  ▼
External API  ──── raw response ────► back to agent

(The API key never leaves the ASV process)
```

**The analogy:** AWS IAM roles, but for LLM tool calls.

Key properties:
- **MCP-native** — works with any MCP-compatible agent framework
- **Local-first** — vault runs as a local process; keys never leave the machine except for the proxied API call
- **Deny-by-default policy** — YAML rules define which agents can call which services/actions
- **Full audit log** — every request, grant, denial, and proxied call logged with timestamp + identity
- **Zero-knowledge design** — audit logs contain responses, not keys

---

## What Has Been Built (Current State)

### Core Infrastructure ✅
- **`src/vault/keystore.ts`** — AES-256-GCM encrypted local keystore; PBKDF2-SHA-512 (210k iterations); unique salt + IV per entry; stored at `~/.asv/keystore.json` (mode 600)
- **`src/policy/policy.ts`** — YAML-based deny-by-default policy engine with wildcard support (`*` for identity/service/action); hot-reload via `fs.watch`
- **`src/policy/ratelimit.ts`** — In-memory per-identity token-bucket rate limiter; configurable window for testing
- **`src/audit/audit.ts`** — Append-only JSONL audit log at `~/.asv/audit.jsonl`; logs only metadata, never secrets
- **`src/keychain/keychain.ts`** — OS keychain integration via `keytar` (macOS Keychain, Linux Secret Service, Windows Credential Manager); lazy-loaded to handle missing native deps gracefully

### MCP Server ✅
- **`src/mcp/server.ts`** — Exposes single `request_credential` tool via stdio transport; resolves master password from env var (priority) or OS keychain; enforces policy + rate limits; logs all requests

### API Proxies ✅
- **`src/proxy/openai.ts`** — OpenAI Responses API (`responses.create`); also hosts the `proxyRequest` dispatch table
- **`src/proxy/anthropic.ts`** — Anthropic Messages API (`messages.create`)
- **`src/proxy/github.ts`** — GitHub REST API (`repos.get`, `issues.create`, `pulls.create`, `contents.read`)
- **`src/proxy/stripe.ts`** — Stripe API (`paymentIntents.create`, `customers.list`)
- **`src/proxy/slack.ts`** — Slack API (`chat.postMessage`, `conversations.list`)
- **`src/proxy/sendgrid.ts`** — SendGrid API (`mail.send`)
- **`src/proxy/notion.ts`** — Notion API (`pages.create`, `databases.query`)
- **`src/proxy/linear.ts`** — Linear GraphQL API (`issues.create`)
- **`src/proxy/twilio.ts`** — Twilio API (`messages.create`); Basic auth; credential format: `accountSid:authToken`
- **`src/proxy/aws.ts`** — AWS S3 (`s3.getObject`, `s3.putObject`); SigV4 signing; credential format: `accessKeyId:secretAccessKey`
- **`src/proxy/gcp.ts`** — GCP Cloud Storage (`storage.getObject`, `storage.listObjects`); OAuth2 access token

### CLI ✅
- `asv init` — creates `~/.asv/`, `config/policy.yaml`, `data/`
- `asv add <service>` — prompts for master password + secret, encrypts and stores
- `asv list` — lists stored services (metadata only, no secrets)
- `asv revoke <service>` — deletes a stored secret
- `asv doctor` — health-check: config, policy, crypto, keystore
- `asv mcp` — starts the MCP server
- `asv logs` — views audit log (`--tail` to watch live, `--last N`)
- `asv rotate <service>` — re-encrypts a secret under a new master password
- `asv keychain set|delete|status` — manages master password in OS keychain

### Tests ✅
- **111 tests passing** across keystore, policy engine, proxy validators (all 10 services), rate limiter, TTL store, CLI
- Run with: `npm test`

### Package ✅
- `package.json` is npm-publish-ready (files, repository, homepage, prepublishOnly)
- `npm pack --dry-run` verified — ships `dist/`, `config/`, `README.md`, `LICENSE`
- **Not yet published to npm** (`npm publish` has not been run)

---

## Tech Stack

- **Runtime:** Node.js 20+
- **Language:** TypeScript 5.7 → CommonJS output
- **Key deps:** `@modelcontextprotocol/sdk`, `js-yaml`, `keytar`, `uuid`
- **Tests:** `npx tsx src/tests/index.ts` (no build required)
- **Build:** `npm run build` → `dist/`
- **Repo:** https://github.com/cooperdunkin/agent-secrets-vault

---

## File Structure

```
src/
  cli/index.ts          CLI entry point (asv commands)
  mcp/server.ts         MCP server (the core integration point)
  vault/keystore.ts     Encrypted secret storage
  policy/
    policy.ts           YAML policy engine
    ratelimit.ts        Per-identity rate limiter
  proxy/
    openai.ts           OpenAI proxy + central dispatch table
    anthropic.ts        Anthropic proxy
    github.ts           GitHub proxy
    stripe.ts           Stripe proxy
    slack.ts            Slack proxy
    sendgrid.ts         SendGrid proxy
    notion.ts           Notion proxy
    linear.ts           Linear proxy (GraphQL)
    twilio.ts           Twilio proxy (Basic auth)
    aws.ts              AWS S3 proxy (SigV4)
    gcp.ts              GCP Storage proxy
  audit/audit.ts        JSONL audit logger
  keychain/keychain.ts  OS keychain wrapper
  tests/index.ts        Full test suite (111 tests)
config/policy.yaml      Default policy (deny-by-default, examples)
```

---

## MVP Gap Analysis

The original product brief specified a 10-service MVP. Here is what remains:

| Feature | Status |
|---|---|
| Encrypted keystore | ✅ Done |
| MCP tool `request_credential` | ✅ Done |
| OpenAI proxy | ✅ Done |
| Anthropic proxy | ✅ Done |
| GitHub proxy | ✅ Done |
| Stripe proxy | ✅ Done |
| Slack proxy | ✅ Done |
| SendGrid proxy | ✅ Done |
| Notion proxy | ✅ Done |
| Linear proxy | ✅ Done |
| Twilio proxy | ✅ Done |
| AWS S3 proxy (SigV4) | ✅ Done |
| GCP Storage proxy | ✅ Done |
| CLI (add/list/revoke/doctor/logs/rotate) | ✅ Done |
| OS keychain integration | ✅ Done |
| Policy engine (deny-by-default, wildcards) | ✅ Done |
| Rate limiting | ✅ Done |
| Short-lived tokens / TTL per grant | ✅ Done |
| Audit log | ✅ Done |
| README badges + accurate threat model | ✅ Done |
| npm publish (`npm install -g`) | ❌ Not done |

---

## Next Steps to Ship

### Step 1 — Publish to npm
```bash
npm login                      # authenticate with npm registry
npm run build && npm test      # verify clean build + 111 tests pass
npm publish                    # publishes to npm as "agent-secrets-vault"
npm info agent-secrets-vault   # verify it appears on the registry
npm install -g agent-secrets-vault && asv --version  # end-to-end install check
```

### Step 2 — Launch
1. **Hacker News Show HN post** — lead with the HN signal already in the product brief (m-hodges quote)
2. **Product Hunt** — schedule a launch day
3. **Twitter/X thread** — demo: show an agent calling `request_credential` and the key never appearing in any output

### Phase 2 — Business Model (after launch traction)
Per the product brief:
- **Free tier** — 3 services, 7-day audit log, single policy (what's shipped now)
- **Pro ($15/mo)** — unlimited services, 90-day logs, multiple policies, desktop GUI, email alerts
- **Team ($49/mo/seat)** — shared vault, role-based access, centralized policy, SSO
- **Enterprise (custom)** — on-prem, SOC2/HIPAA exports, custom connectors, SLA

To gate features you'll need: a licensing/activation mechanism, a payment processor (Stripe), and a backend for team/enterprise features.

---

## Development Commands

```bash
npm run build        # compile TypeScript → dist/
npm run build:watch  # watch mode
npm test             # run full test suite (54 tests, no build required)
npm run lint         # type-check without emitting
npm run start:mcp    # start MCP server with ASV_IDENTITY=local-dev
```

## Adding a New Service Proxy

1. Create `src/proxy/<service>.ts` — see `src/proxy/github.ts` as the template
2. Export `validate<Action>Params(params: unknown)` functions for each action
3. Export `sanitizeParams(params)` (strip credential-looking keys)
4. Export `proxy<Service>Action(action, params, keystore)` as the main entry point
5. Register in `src/proxy/openai.ts` dispatch table (`proxyRequest` function)
6. Add tests in `src/tests/index.ts`
7. Add a commented example to `config/policy.yaml`
