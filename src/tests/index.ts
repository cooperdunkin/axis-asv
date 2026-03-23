/**
 * tests/index.ts
 *
 * Basic test suite using Node's built-in assert module.
 * Tests: policy engine (isAllowed) and keystore encrypt/decrypt.
 *
 * Run with: npm test  (uses tsx for direct TS execution)
 * Or after build: npm run test:built
 */

import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { Keystore } from "../vault/keystore.js";
import { PolicyEngine } from "../policy/policy.js";
import { auditLogPath } from "../audit/audit.js";
import {
  validateAnthropicParams,
  sanitizeParams as sanitizeAnthropicParams,
} from "../proxy/anthropic.js";
import {
  validateReposGetParams,
  validateIssueCreateParams,
  validatePullsCreateParams,
  validateContentsReadParams,
  sanitizeParams as sanitizeGitHubParams,
} from "../proxy/github.js";
import { RateLimiter } from "../policy/ratelimit.js";
import { TtlStore } from "../policy/ttlstore.js";
import {
  validatePaymentIntentsCreateParams,
  validateCustomersListParams,
  sanitizeParams as sanitizeStripeParams,
} from "../proxy/stripe.js";
import {
  validateChatPostMessageParams,
  validateConversationsListParams,
  sanitizeParams as sanitizeSlackParams,
} from "../proxy/slack.js";
import {
  validateMailSendParams,
  sanitizeParams as sanitizeSendGridParams,
} from "../proxy/sendgrid.js";
import {
  validatePagesCreateParams,
  validateDatabasesQueryParams,
  sanitizeParams as sanitizeNotionParams,
} from "../proxy/notion.js";
import {
  validateIssuesCreateParams,
  sanitizeParams as sanitizeLinearParams,
} from "../proxy/linear.js";
import {
  validateMessagesCreateParams,
  sanitizeParams as sanitizeTwilioParams,
} from "../proxy/twilio.js";
import {
  validateS3GetObjectParams,
  validateS3PutObjectParams,
  sanitizeParams as sanitizeAWSParams,
} from "../proxy/aws.js";
import {
  validateStorageGetObjectParams,
  validateStorageListObjectsParams,
  sanitizeParams as sanitizeGCPParams,
} from "../proxy/gcp.js";

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

async function test(name: string, fn: () => void | Promise<void>): Promise<void> {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.log(`  ✗ ${name}`);
    console.log(`    ${(err as Error).message}`);
    failed++;
  }
}

// ---------------------------------------------------------------------------
// Keystore tests
// ---------------------------------------------------------------------------

async function runKeystoreTests(): Promise<void> {
  console.log("\n[Keystore]");

  // Each stateful test gets its own isolated HOME directory so tests
  // don't share a keystore file (which would mix entries from different passwords).
  function withTmpHome<T>(fn: (tmpDir: string) => T): T {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "axis-test-"));
    const origHome = process.env["HOME"];
    process.env["HOME"] = tmpDir;
    try {
      return fn(tmpDir);
    } finally {
      process.env["HOME"] = origHome;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  await test("selfTest passes with valid password", () => {
    assert.strictEqual(Keystore.selfTest("test-password-123"), true);
  });

  await test("selfTest passes with unicode password", () => {
    assert.strictEqual(Keystore.selfTest("pässwörд-🔑"), true);
  });

  await test("Keystore rejects empty master password", () => {
    assert.throws(() => new Keystore(""), /must not be empty/i);
  });

  await test("setSecret / getSecret round-trip", () => {
    withTmpHome(() => {
      const ks = new Keystore("super-secret-master-pw");
      ks.setSecret("testservice", "my-api-key-abc123");
      const retrieved = ks.getSecret("testservice");
      assert.strictEqual(retrieved, "my-api-key-abc123");
    });
  });

  await test("getSecret throws for unknown service", () => {
    withTmpHome(() => {
      const ks = new Keystore("any-password");
      assert.throws(() => ks.getSecret("nonexistent"), /no secret stored/i);
    });
  });

  await test("Wrong password fails decryption", () => {
    withTmpHome(() => {
      const ks1 = new Keystore("correct-password");
      ks1.setSecret("myservice", "secret-value");
      const ks2 = new Keystore("wrong-password");
      assert.throws(() => ks2.getSecret("myservice"), /decryption failed/i);
    });
  });

  await test("deleteSecret removes entry", () => {
    withTmpHome(() => {
      const ks = new Keystore("delete-test-pw");
      ks.setSecret("todelete", "value");
      const deleted = ks.deleteSecret("todelete");
      assert.strictEqual(deleted, true);
      assert.throws(() => ks.getSecret("todelete"), /no secret stored/i);
    });
  });

  await test("deleteSecret returns false for missing service", () => {
    withTmpHome(() => {
      const ks = new Keystore("any-pw");
      const result = ks.deleteSecret("does-not-exist");
      assert.strictEqual(result, false);
    });
  });

  await test("listServices returns service names and metadata", () => {
    withTmpHome(() => {
      const ks = new Keystore("list-test-pw");
      ks.setSecret("serviceA", "keyA");
      ks.setSecret("serviceB", "keyB");
      const list = ks.listServices();
      const names = list.map((e) => e.service).sort();
      assert.ok(names.includes("serviceA"), "should include serviceA");
      assert.ok(names.includes("serviceB"), "should include serviceB");
      for (const entry of list) {
        assert.ok(entry.createdAt, "should have createdAt");
        assert.ok(entry.updatedAt, "should have updatedAt");
      }
    });
  });

  await test("verifyPassword returns true with correct password", () => {
    withTmpHome(() => {
      const ks = new Keystore("verify-pw");
      ks.setSecret("checksvc", "checkval");
      assert.strictEqual(ks.verifyPassword(), true);
    });
  });

  await test("verifyPassword returns false with wrong password", () => {
    withTmpHome(() => {
      const ks1 = new Keystore("real-pw");
      ks1.setSecret("checksvc2", "checkval2");
      const ks2 = new Keystore("wrong-pw");
      assert.strictEqual(ks2.verifyPassword(), false);
    });
  });

  await test("Keystore file has mode 600", () => {
    withTmpHome((tmpDir) => {
      const ks = new Keystore("mode-test-pw");
      ks.setSecret("modesvc", "modeval");
      const kPath = path.join(tmpDir, ".axis", "keystore.json");
      const stat = fs.statSync(kPath);
      const mode = (stat.mode & 0o777).toString(8);
      assert.strictEqual(mode, "600", `Expected mode 600, got ${mode}`);
    });
  });
}

// ---------------------------------------------------------------------------
// Policy engine tests
// ---------------------------------------------------------------------------

async function runPolicyTests(): Promise<void> {
  console.log("\n[PolicyEngine]");

  // Write a temp policy file
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "axis-policy-test-"));
  const policyFile = path.join(tmpDir, "policy.yaml");

  const policyContent = `
policies:
  - identity: local-dev
    allow:
      - service: openai
        actions:
          - responses.create
          - embeddings.create
  - identity: ci-runner
    allow:
      - service: openai
        actions:
          - "*"
  - identity: wildcard-identity
    allow:
      - service: "*"
        actions:
          - read
  - identity: "*"
    allow:
      - service: public-service
        actions:
          - public.action
`;
  fs.writeFileSync(policyFile, policyContent);

  const pe = new PolicyEngine(policyFile);

  await test("Allows exact identity + service + action match", () => {
    assert.strictEqual(pe.isAllowed("local-dev", "openai", "responses.create").allowed, true);
  });

  await test("Allows second action in list", () => {
    assert.strictEqual(pe.isAllowed("local-dev", "openai", "embeddings.create").allowed, true);
  });

  await test("Denies action not in list for identity", () => {
    assert.strictEqual(pe.isAllowed("local-dev", "openai", "fine-tune.create").allowed, false);
  });

  await test("Denies unknown identity", () => {
    assert.strictEqual(
      pe.isAllowed("unknown-identity", "openai", "responses.create").allowed,
      false
    );
  });

  await test("Denies wrong service for valid identity", () => {
    assert.strictEqual(pe.isAllowed("local-dev", "anthropic", "messages.create").allowed, false);
  });

  await test("Wildcard action (*) allows any action for ci-runner", () => {
    assert.strictEqual(pe.isAllowed("ci-runner", "openai", "anything.at.all").allowed, true);
  });

  await test("Wildcard service (*) allows any service for wildcard-identity", () => {
    assert.strictEqual(pe.isAllowed("wildcard-identity", "someservice", "read").allowed, true);
  });

  await test("Wildcard action only covers allowed service", () => {
    assert.strictEqual(pe.isAllowed("ci-runner", "someother-service", "blah").allowed, false);
  });

  await test("Wildcard identity (*) applies to any identity", () => {
    assert.strictEqual(
      pe.isAllowed("totally-new-identity", "public-service", "public.action").allowed,
      true
    );
  });

  await test("Wildcard identity does not expand allowed actions", () => {
    assert.strictEqual(
      pe.isAllowed("totally-new-identity", "public-service", "private.action").allowed,
      false
    );
  });

  await test("Deny-by-default: empty identity returns false", () => {
    assert.strictEqual(pe.isAllowed("", "openai", "responses.create").allowed, false);
  });

  await test("Policy file missing throws on load", () => {
    assert.throws(
      () => new PolicyEngine("/nonexistent/path/policy.yaml"),
      /policy file not found/i
    );
  });

  await test("Malformed policy YAML throws on load", () => {
    const badFile = path.join(tmpDir, "bad.yaml");
    fs.writeFileSync(badFile, "not_policies:\n  - broken");
    assert.throws(
      () => new PolicyEngine(badFile),
      /malformed|expected top-level/i
    );
  });

  await test("getPolicies returns loaded policies", () => {
    const policies = pe.getPolicies();
    assert.ok(Array.isArray(policies));
    assert.ok(policies.length > 0);
  });

  await test("getPath returns policy file path", () => {
    assert.strictEqual(pe.getPath(), policyFile);
  });

  // TTL field in policy
  const ttlPolicyFile = path.join(tmpDir, "ttl-policy.yaml");
  fs.writeFileSync(
    ttlPolicyFile,
    `
policies:
  - identity: ttl-user
    allow:
      - service: stripe
        actions:
          - paymentIntents.create
        ttl: 300
      - service: openai
        actions:
          - responses.create
`
  );
  const ttlPe = new PolicyEngine(ttlPolicyFile);

  await test("Policy: isAllowed returns ttl when rule has ttl", () => {
    const result = ttlPe.isAllowed("ttl-user", "stripe", "paymentIntents.create");
    assert.strictEqual(result.allowed, true);
    assert.strictEqual(result.ttl, 300);
  });

  await test("Policy: isAllowed returns no ttl when rule has no ttl", () => {
    const result = ttlPe.isAllowed("ttl-user", "openai", "responses.create");
    assert.strictEqual(result.allowed, true);
    assert.strictEqual(result.ttl, undefined);
  });

  // Clean up
  fs.rmSync(tmpDir, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// Anthropic proxy tests (unit only — no live API calls)
// ---------------------------------------------------------------------------

async function runAnthropicProxyTests(): Promise<void> {
  console.log("\n[Anthropic Proxy]");

  await test("Anthropic: rejects missing model", () => {
    assert.throws(
      () =>
        validateAnthropicParams({
          messages: [{ role: "user", content: "hi" }],
          max_tokens: 100,
        }),
      /model/i
    );
  });

  await test("Anthropic: rejects missing messages", () => {
    assert.throws(
      () => validateAnthropicParams({ model: "claude-3-5-sonnet-20241022", max_tokens: 100 }),
      /messages/i
    );
  });

  await test("Anthropic: rejects empty messages array", () => {
    assert.throws(
      () =>
        validateAnthropicParams({
          model: "claude-3-5-sonnet-20241022",
          messages: [],
          max_tokens: 100,
        }),
      /messages/i
    );
  });

  await test("Anthropic: rejects missing max_tokens", () => {
    assert.throws(
      () =>
        validateAnthropicParams({
          model: "claude-3-5-sonnet-20241022",
          messages: [{ role: "user", content: "hi" }],
        }),
      /max_tokens/i
    );
  });

  await test("Anthropic: rejects non-positive max_tokens", () => {
    assert.throws(
      () =>
        validateAnthropicParams({
          model: "claude-3-5-sonnet-20241022",
          messages: [{ role: "user", content: "hi" }],
          max_tokens: 0,
        }),
      /max_tokens/i
    );
  });

  await test("Anthropic: rejects non-integer max_tokens", () => {
    assert.throws(
      () =>
        validateAnthropicParams({
          model: "claude-3-5-sonnet-20241022",
          messages: [{ role: "user", content: "hi" }],
          max_tokens: 1.5,
        }),
      /max_tokens/i
    );
  });

  await test("Anthropic: sanitizeParams strips credential keys", () => {
    const result = sanitizeAnthropicParams({
      model: "claude-3-5-sonnet-20241022",
      api_key: "sk-secret",
      auth_token: "tok",
      x_secret: "hidden",
      system: "You are helpful",
    });
    assert.ok(!("api_key" in result), "api_key should be stripped");
    assert.ok(!("auth_token" in result), "auth_token should be stripped");
    assert.ok(!("x_secret" in result), "x_secret should be stripped");
    assert.ok("model" in result, "model should be kept");
    assert.ok("system" in result, "system should be kept");
  });

  await test("Anthropic: valid params pass validation", () => {
    const result = validateAnthropicParams({
      model: "claude-3-5-sonnet-20241022",
      messages: [{ role: "user", content: "Hello" }],
      max_tokens: 1024,
    });
    assert.strictEqual(result.model, "claude-3-5-sonnet-20241022");
    assert.strictEqual(result.max_tokens, 1024);
  });
}

// ---------------------------------------------------------------------------
// GitHub proxy tests (unit only — no live API calls)
// ---------------------------------------------------------------------------

async function runGitHubProxyTests(): Promise<void> {
  console.log("\n[GitHub Proxy]");

  // repos.get
  await test("GitHub repos.get: rejects missing owner", () => {
    assert.throws(() => validateReposGetParams({ repo: "myrepo" }), /owner/i);
  });

  await test("GitHub repos.get: rejects missing repo", () => {
    assert.throws(() => validateReposGetParams({ owner: "myuser" }), /repo/i);
  });

  await test("GitHub repos.get: valid params pass", () => {
    const r = validateReposGetParams({ owner: "octocat", repo: "hello-world" });
    assert.strictEqual(r.owner, "octocat");
    assert.strictEqual(r.repo, "hello-world");
  });

  // issues.create
  await test("GitHub issues.create: rejects missing title", () => {
    assert.throws(
      () => validateIssueCreateParams({ owner: "octocat", repo: "hello-world" }),
      /title/i
    );
  });

  await test("GitHub issues.create: valid params pass", () => {
    const r = validateIssueCreateParams({
      owner: "octocat",
      repo: "hello-world",
      title: "Bug report",
    });
    assert.strictEqual(r.title, "Bug report");
  });

  // pulls.create
  await test("GitHub pulls.create: rejects missing head", () => {
    assert.throws(
      () =>
        validatePullsCreateParams({
          owner: "octocat",
          repo: "hello-world",
          title: "My PR",
          base: "main",
        }),
      /head/i
    );
  });

  await test("GitHub pulls.create: rejects missing base", () => {
    assert.throws(
      () =>
        validatePullsCreateParams({
          owner: "octocat",
          repo: "hello-world",
          title: "My PR",
          head: "feature",
        }),
      /base/i
    );
  });

  await test("GitHub pulls.create: valid params pass", () => {
    const r = validatePullsCreateParams({
      owner: "octocat",
      repo: "hello-world",
      title: "My PR",
      head: "feature-branch",
      base: "main",
    });
    assert.strictEqual(r.head, "feature-branch");
    assert.strictEqual(r.base, "main");
  });

  // contents.read
  await test("GitHub contents.read: rejects missing path", () => {
    assert.throws(
      () => validateContentsReadParams({ owner: "octocat", repo: "hello-world" }),
      /path/i
    );
  });

  await test("GitHub contents.read: valid params pass", () => {
    const r = validateContentsReadParams({
      owner: "octocat",
      repo: "hello-world",
      path: "src/index.ts",
    });
    assert.strictEqual(r.path, "src/index.ts");
  });

  // Sanitization
  await test("GitHub: sanitizeParams strips credential keys", () => {
    const result = sanitizeGitHubParams({
      owner: "octocat",
      repo: "hello-world",
      token: "ghp_secret",
      authorization: "Bearer xyz",
      api_key: "hidden",
      title: "Normal field",
    });
    assert.ok(!("token" in result), "token should be stripped");
    assert.ok(!("authorization" in result), "authorization should be stripped");
    assert.ok(!("api_key" in result), "api_key should be stripped");
    assert.ok("owner" in result, "owner should be kept");
    assert.ok("title" in result, "title should be kept");
  });
}

// ---------------------------------------------------------------------------
// RateLimiter tests
// ---------------------------------------------------------------------------

async function runRateLimiterTests(): Promise<void> {
  console.log("\n[RateLimiter]");

  await test("RateLimiter: allows requests up to limit", () => {
    const rl = new RateLimiter();
    assert.strictEqual(rl.check("user-a", 3), true);
    assert.strictEqual(rl.check("user-a", 3), true);
    assert.strictEqual(rl.check("user-a", 3), true);
  });

  await test("RateLimiter: denies after limit exceeded in same window", () => {
    const rl = new RateLimiter();
    rl.check("user-b", 2);
    rl.check("user-b", 2);
    assert.strictEqual(rl.check("user-b", 2), false);
  });

  await test("RateLimiter: tracks identities independently", () => {
    const rl = new RateLimiter();
    rl.check("user-c", 1);
    assert.strictEqual(rl.check("user-c", 1), false, "user-c should be limited");
    assert.strictEqual(rl.check("user-d", 1), true, "user-d should be allowed");
  });

  await test("RateLimiter: resets after window expires", async () => {
    const rl = new RateLimiter(50); // 50 ms window for fast test
    assert.strictEqual(rl.check("user-e", 1), true);
    assert.strictEqual(rl.check("user-e", 1), false); // rate limited
    await new Promise((resolve) => setTimeout(resolve, 100)); // wait for window expiry
    assert.strictEqual(rl.check("user-e", 1), true); // window reset, allowed again
  });
}

// ---------------------------------------------------------------------------
// CLI: logs + rotate tests
// ---------------------------------------------------------------------------

async function runCliTests(): Promise<void> {
  console.log("\n[CLI: logs + rotate]");

  function withTmpHome<T>(fn: (tmpDir: string) => T): T {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "axis-cli-test-"));
    const origHome = process.env["HOME"];
    process.env["HOME"] = tmpDir;
    try {
      return fn(tmpDir);
    } finally {
      process.env["HOME"] = origHome;
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  await test("logs: audit log absent in fresh environment", () => {
    withTmpHome(() => {
      assert.strictEqual(fs.existsSync(auditLogPath()), false);
    });
  });

  await test("logs: reads and parses JSONL audit entries", () => {
    withTmpHome(() => {
      const logPath = auditLogPath();
      fs.mkdirSync(path.dirname(logPath), { recursive: true });
      const entry = {
        timestamp: "2025-01-15T10:30:00.000Z",
        request_id: "550e8400-e29b-41d4-a716-446655440000",
        identity: "local-dev",
        service: "openai",
        action: "responses.create",
        decision: "allow",
        latency_ms: 342,
      };
      fs.writeFileSync(logPath, JSON.stringify(entry) + "\n");

      const content = fs.readFileSync(logPath, "utf8");
      const lines = content.split("\n").filter((l) => l.trim().length > 0);
      assert.strictEqual(lines.length, 1);
      const parsed = JSON.parse(lines[0]);
      assert.strictEqual(parsed.identity, "local-dev");
      assert.strictEqual(parsed.service, "openai");
      assert.strictEqual(parsed.decision, "allow");
      assert.strictEqual(parsed.latency_ms, 342);
      assert.strictEqual(parsed.request_id.slice(0, 8), "550e8400");
    });
  });

  await test("rotate: verifyPassword returns false for wrong current password", () => {
    withTmpHome(() => {
      const ks = new Keystore("correct-rotate-pw");
      ks.setSecret("rotateme", "secret-value");
      const wrongKs = new Keystore("wrong-rotate-pw");
      assert.strictEqual(wrongKs.verifyPassword(), false);
    });
  });

  await test("rotate: re-encrypts secret under new password, old password fails", () => {
    withTmpHome(() => {
      // Store with old password
      const oldKs = new Keystore("old-rotate-pw");
      oldKs.setSecret("rotateme", "rotate-secret-value");

      // Retrieve and re-encrypt (mirrors cmdRotate logic)
      const secret = oldKs.getSecret("rotateme");
      const newKs = new Keystore("new-rotate-pw");
      newKs.setSecret("rotateme", secret);

      // New password can decrypt
      assert.strictEqual(newKs.getSecret("rotateme"), "rotate-secret-value");
      // Old password can no longer decrypt the rotated entry
      assert.throws(() => oldKs.getSecret("rotateme"), /decryption failed/i);
    });
  });
}

// ---------------------------------------------------------------------------
// Stripe proxy tests
// ---------------------------------------------------------------------------

async function runStripeProxyTests(): Promise<void> {
  console.log("\n[Stripe Proxy]");

  await test("Stripe paymentIntents.create: rejects missing amount", () => {
    assert.throws(
      () => validatePaymentIntentsCreateParams({ currency: "usd" }),
      /amount/i
    );
  });

  await test("Stripe paymentIntents.create: rejects missing currency", () => {
    assert.throws(
      () => validatePaymentIntentsCreateParams({ amount: 1000 }),
      /currency/i
    );
  });

  await test("Stripe paymentIntents.create: valid params pass", () => {
    const r = validatePaymentIntentsCreateParams({ amount: 2000, currency: "usd" });
    assert.strictEqual(r.amount, 2000);
    assert.strictEqual(r.currency, "usd");
  });

  await test("Stripe customers.list: valid params pass", () => {
    const r = validateCustomersListParams({ limit: 10, email: "test@example.com" });
    assert.strictEqual(r.limit, 10);
  });

  await test("Stripe customers.list: rejects out-of-range limit", () => {
    assert.throws(
      () => validateCustomersListParams({ limit: 200 }),
      /limit/i
    );
  });

  await test("Stripe: sanitizeParams strips api_key", () => {
    const result = sanitizeStripeParams({
      amount: 1000,
      currency: "usd",
      api_key: "sk_live_secret",
    });
    assert.ok(!("api_key" in result), "api_key should be stripped");
    assert.ok("amount" in result, "amount should be kept");
    assert.ok("currency" in result, "currency should be kept");
  });
}

// ---------------------------------------------------------------------------
// Slack proxy tests
// ---------------------------------------------------------------------------

async function runSlackProxyTests(): Promise<void> {
  console.log("\n[Slack Proxy]");

  await test("Slack chat.postMessage: rejects missing channel", () => {
    assert.throws(
      () => validateChatPostMessageParams({ text: "hello" }),
      /channel/i
    );
  });

  await test("Slack chat.postMessage: rejects missing text", () => {
    assert.throws(
      () => validateChatPostMessageParams({ channel: "#general" }),
      /text/i
    );
  });

  await test("Slack chat.postMessage: valid params pass", () => {
    const r = validateChatPostMessageParams({ channel: "#general", text: "hello" });
    assert.strictEqual(r.channel, "#general");
    assert.strictEqual(r.text, "hello");
  });

  await test("Slack conversations.list: valid params pass", () => {
    const r = validateConversationsListParams({ limit: 100, types: "public_channel" });
    assert.strictEqual(r.limit, 100);
  });

  await test("Slack: sanitizeParams strips token", () => {
    const result = sanitizeSlackParams({
      channel: "#general",
      text: "hi",
      token: "xoxb-secret",
    });
    assert.ok(!("token" in result), "token should be stripped");
    assert.ok("channel" in result, "channel should be kept");
    assert.ok("text" in result, "text should be kept");
  });
}

// ---------------------------------------------------------------------------
// SendGrid proxy tests
// ---------------------------------------------------------------------------

async function runSendGridProxyTests(): Promise<void> {
  console.log("\n[SendGrid Proxy]");

  await test("SendGrid mail.send: rejects missing to", () => {
    assert.throws(
      () =>
        validateMailSendParams({
          from: "sender@example.com",
          subject: "Test",
          text: "Hello",
        }),
      /to/i
    );
  });

  await test("SendGrid mail.send: rejects missing from", () => {
    assert.throws(
      () =>
        validateMailSendParams({
          to: "recipient@example.com",
          subject: "Test",
          text: "Hello",
        }),
      /from/i
    );
  });

  await test("SendGrid mail.send: rejects missing subject", () => {
    assert.throws(
      () =>
        validateMailSendParams({
          to: "recipient@example.com",
          from: "sender@example.com",
          text: "Hello",
        }),
      /subject/i
    );
  });

  await test("SendGrid mail.send: rejects missing body", () => {
    assert.throws(
      () =>
        validateMailSendParams({
          to: "recipient@example.com",
          from: "sender@example.com",
          subject: "Test",
        }),
      /text|html|body/i
    );
  });

  await test("SendGrid mail.send: valid params pass with text", () => {
    const r = validateMailSendParams({
      to: "recipient@example.com",
      from: "sender@example.com",
      subject: "Hello",
      text: "World",
    });
    assert.strictEqual(r.subject, "Hello");
  });

  await test("SendGrid mail.send: valid params pass with array to", () => {
    const r = validateMailSendParams({
      to: ["a@example.com", "b@example.com"],
      from: "sender@example.com",
      subject: "Hello",
      html: "<p>World</p>",
    });
    assert.ok(Array.isArray(r.to));
  });

  await test("SendGrid: sanitizeParams strips api_key", () => {
    const result = sanitizeSendGridParams({
      to: "a@example.com",
      from: "b@example.com",
      api_key: "SG.secret",
    });
    assert.ok(!("api_key" in result), "api_key should be stripped");
    assert.ok("to" in result, "to should be kept");
  });
}

// ---------------------------------------------------------------------------
// Notion proxy tests
// ---------------------------------------------------------------------------

async function runNotionProxyTests(): Promise<void> {
  console.log("\n[Notion Proxy]");

  await test("Notion pages.create: rejects missing parent", () => {
    assert.throws(
      () =>
        validatePagesCreateParams({
          properties: { Name: { title: [{ text: { content: "Test" } }] } },
        }),
      /parent/i
    );
  });

  await test("Notion pages.create: rejects parent without database_id or page_id", () => {
    assert.throws(
      () =>
        validatePagesCreateParams({
          parent: {},
          properties: { Name: {} },
        }),
      /database_id|page_id/i
    );
  });

  await test("Notion pages.create: rejects missing properties", () => {
    assert.throws(
      () =>
        validatePagesCreateParams({
          parent: { database_id: "abc123" },
        }),
      /properties/i
    );
  });

  await test("Notion pages.create: valid params pass", () => {
    const r = validatePagesCreateParams({
      parent: { database_id: "abc123" },
      properties: { Name: { title: [{ text: { content: "Test" } }] } },
    });
    assert.ok(r.parent.database_id === "abc123");
  });

  await test("Notion databases.query: rejects missing database_id", () => {
    assert.throws(
      () => validateDatabasesQueryParams({}),
      /database_id/i
    );
  });

  await test("Notion databases.query: valid params pass", () => {
    const r = validateDatabasesQueryParams({ database_id: "db123" });
    assert.strictEqual(r.database_id, "db123");
  });

  await test("Notion: sanitizeParams strips token", () => {
    const result = sanitizeNotionParams({
      database_id: "db123",
      token: "secret_abc",
    });
    assert.ok(!("token" in result), "token should be stripped");
    assert.ok("database_id" in result, "database_id should be kept");
  });
}

// ---------------------------------------------------------------------------
// Linear proxy tests
// ---------------------------------------------------------------------------

async function runLinearProxyTests(): Promise<void> {
  console.log("\n[Linear Proxy]");

  await test("Linear issues.create: rejects missing teamId", () => {
    assert.throws(
      () => validateIssuesCreateParams({ title: "Bug" }),
      /teamId/i
    );
  });

  await test("Linear issues.create: rejects missing title", () => {
    assert.throws(
      () => validateIssuesCreateParams({ teamId: "TEAM-1" }),
      /title/i
    );
  });

  await test("Linear issues.create: rejects invalid priority", () => {
    assert.throws(
      () => validateIssuesCreateParams({ teamId: "TEAM-1", title: "Bug", priority: 5 }),
      /priority/i
    );
  });

  await test("Linear issues.create: valid params pass", () => {
    const r = validateIssuesCreateParams({ teamId: "TEAM-1", title: "Bug fix", priority: 2 });
    assert.strictEqual(r.teamId, "TEAM-1");
    assert.strictEqual(r.title, "Bug fix");
    assert.strictEqual(r.priority, 2);
  });

  await test("Linear: sanitizeParams strips api_key", () => {
    const result = sanitizeLinearParams({
      teamId: "TEAM-1",
      title: "Bug",
      api_key: "lin_api_secret",
    });
    assert.ok(!("api_key" in result), "api_key should be stripped");
    assert.ok("teamId" in result, "teamId should be kept");
  });
}

// ---------------------------------------------------------------------------
// Twilio proxy tests
// ---------------------------------------------------------------------------

async function runTwilioProxyTests(): Promise<void> {
  console.log("\n[Twilio Proxy]");

  await test("Twilio messages.create: rejects missing to", () => {
    assert.throws(
      () =>
        validateMessagesCreateParams({
          accountSid: "ACxxx",
          from: "+15005550006",
          body: "Hello",
        }),
      /to/i
    );
  });

  await test("Twilio messages.create: rejects missing from", () => {
    assert.throws(
      () =>
        validateMessagesCreateParams({
          accountSid: "ACxxx",
          to: "+15005550001",
          body: "Hello",
        }),
      /from/i
    );
  });

  await test("Twilio messages.create: rejects missing body", () => {
    assert.throws(
      () =>
        validateMessagesCreateParams({
          accountSid: "ACxxx",
          to: "+15005550001",
          from: "+15005550006",
        }),
      /body/i
    );
  });

  await test("Twilio messages.create: rejects missing accountSid", () => {
    assert.throws(
      () =>
        validateMessagesCreateParams({
          to: "+15005550001",
          from: "+15005550006",
          body: "Hello",
        }),
      /accountSid/i
    );
  });

  await test("Twilio messages.create: valid params pass", () => {
    const r = validateMessagesCreateParams({
      accountSid: "ACxxx",
      to: "+15005550001",
      from: "+15005550006",
      body: "Hello World",
    });
    assert.strictEqual(r.body, "Hello World");
  });

  await test("Twilio: sanitizeParams strips password", () => {
    const result = sanitizeTwilioParams({
      accountSid: "ACxxx",
      to: "+15005550001",
      from: "+15005550006",
      password: "auth_token_secret",
    });
    assert.ok(!("password" in result), "password should be stripped");
    assert.ok("accountSid" in result, "accountSid should be kept");
  });
}

// ---------------------------------------------------------------------------
// AWS proxy tests
// ---------------------------------------------------------------------------

async function runAWSProxyTests(): Promise<void> {
  console.log("\n[AWS Proxy]");

  await test("AWS s3.getObject: rejects missing bucket", () => {
    assert.throws(
      () => validateS3GetObjectParams({ key: "myfile.txt", region: "us-east-1" }),
      /bucket/i
    );
  });

  await test("AWS s3.getObject: rejects missing key", () => {
    assert.throws(
      () => validateS3GetObjectParams({ bucket: "my-bucket", region: "us-east-1" }),
      /key/i
    );
  });

  await test("AWS s3.getObject: rejects missing region", () => {
    assert.throws(
      () => validateS3GetObjectParams({ bucket: "my-bucket", key: "myfile.txt" }),
      /region/i
    );
  });

  await test("AWS s3.getObject: valid params pass", () => {
    const r = validateS3GetObjectParams({
      bucket: "my-bucket",
      key: "myfile.txt",
      region: "us-east-1",
    });
    assert.strictEqual(r.bucket, "my-bucket");
    assert.strictEqual(r.region, "us-east-1");
  });

  await test("AWS s3.putObject: rejects missing body", () => {
    assert.throws(
      () =>
        validateS3PutObjectParams({
          bucket: "my-bucket",
          key: "myfile.txt",
          region: "us-east-1",
        }),
      /body/i
    );
  });

  await test("AWS s3.putObject: valid params pass", () => {
    const r = validateS3PutObjectParams({
      bucket: "my-bucket",
      key: "myfile.txt",
      region: "us-east-1",
      body: "file content",
    });
    assert.strictEqual(r.body, "file content");
  });

  await test("AWS: sanitizeParams strips secret", () => {
    const result = sanitizeAWSParams({
      bucket: "my-bucket",
      region: "us-east-1",
      secret_access_key: "wJalrXUtnFEMI",
    });
    assert.ok(!("secret_access_key" in result), "secret_access_key should be stripped");
    assert.ok("bucket" in result, "bucket should be kept");
  });
}

// ---------------------------------------------------------------------------
// GCP proxy tests
// ---------------------------------------------------------------------------

async function runGCPProxyTests(): Promise<void> {
  console.log("\n[GCP Proxy]");

  await test("GCP storage.getObject: rejects missing bucket", () => {
    assert.throws(
      () => validateStorageGetObjectParams({ object: "myfile.txt" }),
      /bucket/i
    );
  });

  await test("GCP storage.getObject: rejects missing object", () => {
    assert.throws(
      () => validateStorageGetObjectParams({ bucket: "my-bucket" }),
      /object/i
    );
  });

  await test("GCP storage.getObject: valid params pass", () => {
    const r = validateStorageGetObjectParams({
      bucket: "my-bucket",
      object: "myfile.txt",
    });
    assert.strictEqual(r.bucket, "my-bucket");
    assert.strictEqual(r.object, "myfile.txt");
  });

  await test("GCP storage.listObjects: rejects missing bucket", () => {
    assert.throws(
      () => validateStorageListObjectsParams({}),
      /bucket/i
    );
  });

  await test("GCP storage.listObjects: valid params pass", () => {
    const r = validateStorageListObjectsParams({
      bucket: "my-bucket",
      prefix: "data/",
      maxResults: 100,
    });
    assert.strictEqual(r.prefix, "data/");
    assert.strictEqual(r.maxResults, 100);
  });

  await test("GCP: sanitizeParams strips token", () => {
    const result = sanitizeGCPParams({
      bucket: "my-bucket",
      object: "file.txt",
      token: "ya29.secret",
    });
    assert.ok(!("token" in result), "token should be stripped");
    assert.ok("bucket" in result, "bucket should be kept");
  });
}

// ---------------------------------------------------------------------------
// TtlStore tests
// ---------------------------------------------------------------------------

async function runTtlStoreTests(): Promise<void> {
  console.log("\n[TtlStore]");

  await test("TtlStore: no grant returns active=false", () => {
    const store = new TtlStore();
    const result = store.check("user", "stripe", "paymentIntents.create");
    assert.strictEqual(result.active, false);
  });

  await test("TtlStore: grant returns active=true before expiry", () => {
    const store = new TtlStore();
    store.grant("user", "stripe", "paymentIntents.create", 300);
    const result = store.check("user", "stripe", "paymentIntents.create");
    assert.strictEqual(result.active, true);
    if (result.active) {
      assert.ok(result.remainingMs > 0, "remainingMs should be positive");
    }
  });

  await test("TtlStore: expired grant returns active=false", () => {
    const store = new TtlStore();
    // Set expiry in the past
    store.setExpiry("user", "stripe", "paymentIntents.create", Date.now() - 1000);
    const result = store.check("user", "stripe", "paymentIntents.create");
    assert.strictEqual(result.active, false);
  });

  await test("TtlStore: tracks (identity, service, action) tuples independently", () => {
    const store = new TtlStore();
    store.grant("user-a", "stripe", "paymentIntents.create", 300);
    assert.strictEqual(store.check("user-a", "stripe", "paymentIntents.create").active, true);
    assert.strictEqual(store.check("user-b", "stripe", "paymentIntents.create").active, false);
    assert.strictEqual(store.check("user-a", "slack", "chat.postMessage").active, false);
  });

  await test("TtlStore: expire() removes grant", () => {
    const store = new TtlStore();
    store.grant("user", "stripe", "paymentIntents.create", 300);
    store.expire("user", "stripe", "paymentIntents.create");
    assert.strictEqual(store.check("user", "stripe", "paymentIntents.create").active, false);
  });

  await test("TtlStore: grant after expiry allows again", async () => {
    const store = new TtlStore();
    // Set to expire 50ms from now
    store.setExpiry("user", "stripe", "paymentIntents.create", Date.now() + 50);
    assert.strictEqual(store.check("user", "stripe", "paymentIntents.create").active, true);
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.strictEqual(store.check("user", "stripe", "paymentIntents.create").active, false);
  });
}

// ---------------------------------------------------------------------------
// Main runner
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("Axis Test Suite");
  console.log("==============");

  await runKeystoreTests();
  await runPolicyTests();
  await runAnthropicProxyTests();
  await runGitHubProxyTests();
  await runRateLimiterTests();
  await runCliTests();
  await runStripeProxyTests();
  await runSlackProxyTests();
  await runSendGridProxyTests();
  await runNotionProxyTests();
  await runLinearProxyTests();
  await runTwilioProxyTests();
  await runAWSProxyTests();
  await runGCPProxyTests();
  await runTtlStoreTests();

  console.log(`\n${"=".repeat(40)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);

  if (failed > 0) {
    process.exit(1);
  } else {
    console.log("All tests passed.");
  }
}

main().catch((err) => {
  console.error("Test runner error:", err);
  process.exit(1);
});
