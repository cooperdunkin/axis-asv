# Axis

[![npm version](https://img.shields.io/npm/v/axis-asv.svg)](https://www.npmjs.com/package/axis-asv)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Website](https://img.shields.io/badge/website-axisproxy.com-brightgreen)](https://axisproxy.com/)

**Your AI agent can read your `.env` file. Axis stops that.**

Axis is the credential broker for AI agents — an MCP-native vault where agents call external APIs through Axis, and never receive the raw key. Think AWS IAM roles, but for LLM tool calls.

```
Agent (Claude Code / Cursor / Devin)
  │
  │  execute_action({ service: "openai", action: "responses.create", ... })
  ▼
Axis MCP Server  ──── policy check ──── audit log
  │
  │  injects stored API key server-side
  ▼
OpenAI API  ──── response ────► back to agent

The API key is never returned to the agent.
```

---

## Why Axis

Every current method of giving an AI agent API credentials is broken:

| Method | Problem |
|--------|---------|
| Environment variables | `echo $OPENAI_API_KEY` works in any shell tool |
| `.env` files | `cat .env` readable by any file-access tool |
| System prompt injection | Key is in agent context; any log captures it |
| Manual proxies | HashiCorp Vault overhead for a side project |

Axis is the missing primitive: **time-limited, action-scoped credential access without the agent ever seeing the key.**

---

## Supported Services

| Service | Actions |
|---------|---------|
| **OpenAI** | `responses.create` |
| **Anthropic** | `messages.create` |
| **GitHub** | `repos.get`, `issues.create`, `pulls.create`, `contents.read` |
| **Stripe** | `paymentIntents.create`, `customers.list` |
| **Slack** | `chat.postMessage`, `conversations.list` |
| **SendGrid** | `mail.send` |
| **Notion** | `pages.create`, `databases.query` |
| **Linear** | `issues.create` |
| **Twilio** | `messages.create` |
| **AWS S3** | `s3.getObject`, `s3.putObject` |
| **GCP Cloud Storage** | `storage.getObject`, `storage.listObjects` |

---

## 5-Minute Setup

### Prerequisites

- Node.js 20+

### 1. Install

```bash
npm install -g axis-asv
```

### 2. Create an account

```bash
axis signup
```

This creates your Axis Cloud account. Your credentials are encrypted on your machine before being sent — the cloud stores only ciphertext, never plaintext keys.

### 3. Store your first credential

```bash
axis add openai
```

You'll be prompted for:
1. Your **master password** — used to encrypt the key locally before it leaves your machine
2. Your **OpenAI API key** (`sk-...`)

### 4. Configure your MCP host

#### Claude Code

Add to `~/.claude.json` (global) or `.mcp.json` (project-level):

```json
{
  "mcpServers": {
    "axis": {
      "command": "axis",
      "args": ["mcp"],
      "env": {
        "AXIS_IDENTITY": "local-dev",
        "AXIS_MASTER_PASSWORD": "your-master-password"
      }
    }
  }
}
```

#### Cursor

Add to `~/.cursor/mcp.json` or your project's `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "axis": {
      "command": "axis",
      "args": ["mcp"],
      "env": {
        "AXIS_IDENTITY": "local-dev",
        "AXIS_MASTER_PASSWORD": "your-master-password"
      }
    }
  }
}
```

> **Tip:** Use `axis keychain set` to store the master password in your OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager) — then remove `AXIS_MASTER_PASSWORD` from the config entirely. See [Keychain Setup](#keychain-setup).

### 5. Verify

```bash
axis doctor
```

---

## How Your Agent Uses Axis

Axis exposes one MCP tool: `execute_action`. Your agent calls it like this:

```json
{
  "service": "openai",
  "action": "responses.create",
  "justification": "Summarising the uploaded document for the user",
  "params": {
    "model": "gpt-4o",
    "input": "Summarise the following in 3 sentences: ..."
  }
}
```

Axis checks the policy, proxies the call, and returns the API response. The agent never sees the key.

### Response (allowed)

```json
{
  "ok": true,
  "result": { "output": [{ "content": "..." }] },
  "request_id": "550e8400-..."
}
```

### Response (denied)

```json
{
  "denied": true,
  "reason": "Policy denied: identity=\"local-dev\" service=\"stripe\" action=\"paymentIntents.create\"",
  "request_id": "550e8400-..."
}
```

---

## Security Model

### Zero-knowledge cloud

Axis Cloud stores only ciphertext. Your master password never leaves your machine. Even if the database were breached, your keys are safe.

```
Your machine:     plaintext secret + master password → AES-256-GCM → ciphertext
Axis Cloud:       stores ciphertext, salt, IV only — never the plaintext or password
MCP Server:       fetches ciphertext → decrypts locally → proxies call → returns response
```

### Deny-by-default policy

Every request is denied unless an explicit rule allows it. Edit `config/policy.yaml`:

```yaml
policies:
  - identity: local-dev
    allow:
      - service: openai
        actions:
          - responses.create

  # Wildcard example
  - identity: ci-runner
    allow:
      - service: github
        actions:
          - "*"
```

The `identity` comes from `AXIS_IDENTITY` in your MCP config. Policy files hot-reload on save.

### Audit log

Every request — allowed or denied — is logged locally and to your Axis Cloud account:

```json
{
  "timestamp": "2025-01-15T10:30:00.000Z",
  "request_id": "550e8400-...",
  "identity": "local-dev",
  "service": "openai",
  "action": "responses.create",
  "decision": "allow",
  "justification": "Summarising document for user",
  "latency_ms": 342
}
```

Secrets are never logged. View logs with `axis logs` or in your Axis Cloud dashboard.

### Encryption

| Property | Value |
|----------|-------|
| Algorithm | AES-256-GCM |
| Key derivation | PBKDF2-SHA-512, 210,000 iterations |
| Salt | 32 bytes, unique per entry |
| IV | 12 bytes, unique per entry |
| Auth tag | 128 bits |

---

## CLI Reference

### Account

```bash
axis signup              # Create Axis Cloud account
axis login               # Sign in
axis logout              # Sign out
axis whoami              # Show current account and plan
```

### Credentials

```bash
axis add <service>       # Store an encrypted credential
axis list                # List stored services (no secrets shown)
axis revoke <service>    # Delete a stored credential
axis rotate <service>    # Re-encrypt a credential under a new master password
```

### Operations

```bash
axis mcp                 # Start the MCP server
axis logs                # View audit log (--tail to watch, --last N for count)
axis doctor              # Health check: config, policy, crypto, keystore
axis init                # Create config dirs and default policy.yaml
```

### Keychain

```bash
axis keychain set        # Store master password in OS keychain
axis keychain delete     # Remove from keychain
axis keychain status     # Check if master password is in keychain
```

---

## Keychain Setup

Storing `AXIS_MASTER_PASSWORD` in your MCP config file is convenient but keeps it in plaintext on disk. To eliminate this:

```bash
axis keychain set
```

Then update your MCP config to remove `AXIS_MASTER_PASSWORD`:

```json
{
  "mcpServers": {
    "axis": {
      "command": "axis",
      "args": ["mcp"],
      "env": {
        "AXIS_IDENTITY": "local-dev"
      }
    }
  }
}
```

Axis reads the master password from the OS keychain automatically at startup.

**Linux:** Install libsecret first:
```bash
# Ubuntu/Debian
sudo apt install libsecret-1-dev
# Fedora
sudo dnf install libsecret-devel
```

---

## Plans

| | Free | Pro | Team |
|--|------|-----|------|
| Credentials | 3 | Unlimited | Unlimited |
| Services | 11 | 11 | 11 |
| Audit log | Local only | 90 days cloud | 90 days cloud |
| Team members | 1 | 1 | Unlimited |
| Price | Free | $15/mo | $49/seat/mo |

Upgrade at [axisproxy.com](https://axisproxy.com).

---

## Threat Model

### What Axis protects against

| Threat | How |
|--------|-----|
| Agent receives raw credential | Never in tool responses — proxy injects key server-side |
| Credential leaked in logs | Audit log records metadata only, never secrets |
| Credential stored in plaintext | AES-256-GCM at rest, unique salt+IV per entry |
| Unauthorized service access | Deny-by-default policy, identity-scoped rules |
| Wrong action on a service | Policy rules scoped to `service + action` pairs |
| Cloud database breach | Cloud stores only ciphertext — master password never sent |

### What Axis does not protect against

| Threat | Notes |
|--------|-------|
| Compromised local machine | An attacker with OS-level access + your master password can decrypt. Use full-disk encryption (FileVault, BitLocker, LUKS). |
| Malicious MCP host | The MCP host receives the API response. Axis assumes the host is trusted. |
| Memory scraping | Decrypted secrets pass through process memory briefly during proxying. |
| Policy misconfiguration | Broad wildcards (`"*"`) grant wide access. Review policy rules. |

---

## Development

```bash
npm run build         # compile TypeScript → dist/
npm run build:watch   # watch mode
npm test              # run test suite (111 tests, no build needed)
npm run lint          # type-check without emitting
```

### Adding a new service proxy

1. Create `src/proxy/<service>.ts` — see `src/proxy/github.ts` as the template
2. Export `validate<Action>Params()`, `sanitizeParams()`, and `proxy<Service>Action()`
3. Register in the dispatch table in `src/proxy/openai.ts`
4. Add tests in `src/tests/index.ts`

---

## License

MIT — [axisproxy.com](https://axisproxy.com)
