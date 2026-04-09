# Axis

[![npm version](https://img.shields.io/npm/v/axis-asv.svg)](https://www.npmjs.com/package/axis-asv)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Website](https://img.shields.io/badge/website-axisproxy.com-brightgreen)](https://axisproxy.com/)

**Your AI agent can read your `.env` file. Axis stops that.**

Axis is the identity and credential layer for AI agents — an MCP-native broker where agents get scoped, time-limited permission to act, without ever seeing a raw API key. Think AWS IAM roles, but for LLM tool calls.

```
Agent (Claude Code / Cursor / Devin)
  |
  |  execute_action({ service: "openai", action: "responses.create", ... })
  v
Axis MCP Server  ---- policy check ---- audit log
  |
  |  injects stored API key server-side
  v
OpenAI API  ---- response ----> back to agent

The API key is never returned to the agent.
```

---

## Why Axis

AI agents are non-human identities. Every method of delivering credentials to them is broken:

| Method | Problem |
|--------|---------|
| Environment variables | `echo $OPENAI_API_KEY` works in any shell tool |
| `.env` files | `cat .env` readable by any file-access tool |
| System prompt injection | Key is in agent context; any log captures it |
| Manual proxies | HashiCorp Vault overhead for a side project |

Axis is the missing primitive: **time-limited, action-scoped credential access without the agent ever seeing the key.**

### How Axis fits the NHI landscape

Enterprise NHI platforms (Oasis, CyberArk, Strata) govern identity at organizational scale — SSO, cross-cloud policy, compliance dashboards. Axis operates at the developer layer: local-first, single-machine, zero-config credential brokering for individual developers and small teams. They're complementary, not competing. Axis is the tool you install today; enterprise NHI is what your security team evaluates next quarter.

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

## Quick Start

### 1. Install

```bash
npm install -g axis-asv
```

### 2. Run the setup wizard

```bash
axis setup
```

The wizard walks you through:
1. Creating config directories
2. Setting your master password (stored in OS keychain)
3. Encrypting your first API key
4. Generating your MCP config

Total time: ~60 seconds.

### 3. Add MCP config to your editor

Copy the config the wizard outputs into your MCP host config file:

- **Claude Code:** `~/.claude.json` or `.mcp.json` (project-level)
- **Cursor:** `~/.cursor/mcp.json`

### 4. Verify

```bash
axis doctor
```

---

<details>
<summary><strong>Manual Setup</strong> (step-by-step)</summary>

#### Prerequisites

- Node.js 20+

#### 1. Initialize

```bash
axis init
```

#### 2. Store your first credential

```bash
axis add openai
```

You'll be prompted for:
1. Your **master password** — used to encrypt the key locally
2. Your **OpenAI API key** (`sk-...`)

#### 3. Store master password in OS keychain

```bash
axis keychain set
```

This stores your master password in the OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager) so Axis can start without a plaintext password in config.

#### 4. Configure your MCP host

**Claude Code** — Add to `~/.claude.json` (global) or `.mcp.json` (project-level):

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

Axis reads the master password from your OS keychain automatically. If you prefer to use an environment variable instead, add `"AXIS_MASTER_PASSWORD": "your-password"` to the `env` block above.

**Cursor** — Add to `~/.cursor/mcp.json` or your project's `.cursor/mcp.json`:

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

#### 5. Verify

```bash
axis doctor
```

</details>

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

### Local-first encryption

All secrets are encrypted on your machine with AES-256-GCM. Your master password never leaves your machine.

```
Your machine:     plaintext secret + master password -> AES-256-GCM -> ciphertext
Keystore:         stores ciphertext, salt, IV only — never the plaintext or password
MCP Server:       decrypts locally -> proxies call -> returns response
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

### Rate limiting

Limit how many requests an identity can make per minute. If the limit is exceeded, further requests are denied until the window resets.

```yaml
policies:
  - identity: ci-runner
    rateLimit:
      requestsPerMinute: 30
    allow:
      - service: openai
        actions:
          - responses.create
```

### TTL (time-to-live grants)

Restrict how frequently a credential can be used. After a successful call, further requests for the same service/action are denied until the TTL expires. Useful for expensive or destructive operations.

```yaml
policies:
  - identity: ci-runner
    allow:
      - service: stripe
        actions:
          - paymentIntents.create
        ttl: 300  # credential access expires after 5 minutes
```

### Audit log

Every request — allowed or denied — is logged locally:

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

Secrets are never logged. View logs with `axis logs`.

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

**Linux:** Install libsecret first:
```bash
# Ubuntu/Debian
sudo apt install libsecret-1-dev
# Fedora
sudo dnf install libsecret-devel
```

---

## Dashboard

Axis includes a local web dashboard for monitoring and inspecting your vault.

```bash
axis dashboard
```

Opens `http://localhost:3847` in your browser. The dashboard shows:

- **Health status** — same checks as `axis doctor`
- **Audit log** — searchable, filterable, auto-refreshing
- **Stored services** — credential inventory (no secrets shown)
- **Policy rules** — current deny/allow configuration

The dashboard runs locally and binds to `127.0.0.1` only — it is never exposed to the network.

---

## CI/CD Integration

Axis works in CI environments. Use `--stdin` to pipe secrets non-interactively:

```bash
echo "$OPENAI_API_KEY" | axis add openai --stdin
```

Set `AXIS_MASTER_PASSWORD` as a CI secret. See [docs/ci-guide.md](docs/ci-guide.md) for full GitHub Actions examples.

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
npm run build         # compile TypeScript -> dist/
npm run build:watch   # watch mode
npm test              # run test suite (no build needed)
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
