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
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "asv-test-"));
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
      const kPath = path.join(tmpDir, ".asv", "keystore.json");
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
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "asv-policy-test-"));
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
    assert.strictEqual(pe.isAllowed("local-dev", "openai", "responses.create"), true);
  });

  await test("Allows second action in list", () => {
    assert.strictEqual(pe.isAllowed("local-dev", "openai", "embeddings.create"), true);
  });

  await test("Denies action not in list for identity", () => {
    assert.strictEqual(pe.isAllowed("local-dev", "openai", "fine-tune.create"), false);
  });

  await test("Denies unknown identity", () => {
    assert.strictEqual(
      pe.isAllowed("unknown-identity", "openai", "responses.create"),
      false
    );
  });

  await test("Denies wrong service for valid identity", () => {
    assert.strictEqual(pe.isAllowed("local-dev", "anthropic", "messages.create"), false);
  });

  await test("Wildcard action (*) allows any action for ci-runner", () => {
    assert.strictEqual(pe.isAllowed("ci-runner", "openai", "anything.at.all"), true);
  });

  await test("Wildcard service (*) allows any service for wildcard-identity", () => {
    assert.strictEqual(pe.isAllowed("wildcard-identity", "someservice", "read"), true);
  });

  await test("Wildcard action only covers allowed service", () => {
    assert.strictEqual(pe.isAllowed("ci-runner", "someother-service", "blah"), false);
  });

  await test("Wildcard identity (*) applies to any identity", () => {
    assert.strictEqual(
      pe.isAllowed("totally-new-identity", "public-service", "public.action"),
      true
    );
  });

  await test("Wildcard identity does not expand allowed actions", () => {
    assert.strictEqual(
      pe.isAllowed("totally-new-identity", "public-service", "private.action"),
      false
    );
  });

  await test("Deny-by-default: empty identity returns false", () => {
    assert.strictEqual(pe.isAllowed("", "openai", "responses.create"), false);
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

  // Clean up
  fs.rmSync(tmpDir, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// Main runner
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("ASV Test Suite");
  console.log("==============");

  await runKeystoreTests();
  await runPolicyTests();

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
