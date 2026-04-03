# Using Axis in CI/CD Pipelines

Axis works in CI environments where agents run automated tasks (code review, deployment, notifications). This guide covers GitHub Actions, but the pattern applies to any CI system.

## How It Works in CI

1. Store your master password as a CI secret (e.g. `AXIS_MASTER_PASSWORD`)
2. Pre-encrypt your API credentials in a keystore file committed to the repo (or mounted as a secret volume)
3. The Axis MCP server starts in CI, reads the keystore, and proxies API calls

## GitHub Actions Example

```yaml
name: AI Agent Task
on: [push]

jobs:
  agent-task:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install Axis
        run: npm install -g axis-asv

      - name: Initialize Axis
        run: axis init

      - name: Add credentials
        env:
          AXIS_MASTER_PASSWORD: ${{ secrets.AXIS_MASTER_PASSWORD }}
        run: |
          echo "${{ secrets.OPENAI_API_KEY }}" | axis add openai --stdin
          echo "${{ secrets.GITHUB_TOKEN }}" | axis add github --stdin

      - name: Start Axis MCP server
        env:
          AXIS_MASTER_PASSWORD: ${{ secrets.AXIS_MASTER_PASSWORD }}
          AXIS_IDENTITY: ci-runner
        run: axis mcp &

      - name: Run your agent
        run: your-agent-command-here
```

## Environment Variables for CI

| Variable | Required | Description |
|----------|----------|-------------|
| `AXIS_MASTER_PASSWORD` | Yes | Master password for keystore encryption |
| `AXIS_IDENTITY` | Recommended | Identity for policy checks (default: "unknown") |
| `AXIS_POLICY_PATH` | Optional | Path to policy.yaml (default: config/policy.yaml) |

## CI Policy Example

Create a `config/policy.yaml` tuned for CI:

```yaml
policies:
  - identity: ci-runner
    rateLimit:
      requestsPerMinute: 30
    allow:
      - service: github
        actions:
          - issues.create
          - pulls.create
          - contents.read
      - service: slack
        actions:
          - chat.postMessage
```

## Security Notes for CI

- **Never** echo or log the master password
- Use GitHub Actions secrets (or your CI's equivalent) for all credentials
- Use a dedicated CI identity (`ci-runner`) with a restrictive policy
- Review audit logs after CI runs: `axis logs --service github --last 50`
