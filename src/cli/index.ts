#!/usr/bin/env node
/**
 * cli/index.ts
 *
 * Axis CLI — binary name: axis
 *
 * Commands:
 *   axis init           Create config dirs, default policy.yaml
 *   axis add <service>  Prompt for secret, encrypt and store
 *   axis list           List stored services (names only, no secrets)
 *   axis revoke <svc>   Delete stored secret
 *   axis doctor         Health-check: config, policy, crypto, proxy construction
 *   axis mcp            Start MCP server (delegates to mcp/server.ts)
 *   axis logs           View audit log entries (--tail to watch, --last <n> for count)
 *   axis rotate <svc>   Re-encrypt a service secret under a new master password
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as crypto from "crypto";
import * as readline from "readline";
import { execFileSync, execSync } from "child_process";
import { Keystore, axisHome, keystorePath } from "../vault/keystore.js";
import { PolicyEngine, defaultPolicyPath } from "../policy/policy.js";
import { AuditLogger, auditLogPath, AuditEntry } from "../audit/audit.js";
import { keychainSet, keychainDelete, keychainExists, keychainGet } from "../keychain/keychain.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function print(msg: string): void {
  process.stdout.write(msg + "\n");
}

function printErr(msg: string): void {
  process.stderr.write(msg + "\n");
}

function die(msg: string, code = 1): never {
  printErr(`Error: ${msg}`);
  process.exit(code);
}

/** Prompt for a value. Uses raw-mode stdin when hidden=true to suppress echo. */
async function prompt(question: string, hidden = false): Promise<string> {
  if (!process.stdin.isTTY) {
    throw new Error("stdin is not a TTY — cannot prompt interactively.");
  }

  if (hidden) {
    // Read password character-by-character in raw mode — no echo, no reliance on
    // undocumented readline internals that break across Node versions.
    return new Promise((resolve) => {
      process.stdout.write(question);
      const buf: string[] = [];
      process.stdin.setRawMode(true);
      process.stdin.resume();
      process.stdin.setEncoding("utf8");

      const onData = (ch: string): void => {
        // Enter / Return
        if (ch === "\r" || ch === "\n") {
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stdin.removeListener("data", onData);
          process.stdout.write("\n");
          resolve(buf.join(""));
          return;
        }
        // Ctrl-C
        if (ch === "\x03") {
          process.stdin.setRawMode(false);
          process.stdout.write("\n");
          process.exit(130);
        }
        // Backspace / Delete
        if (ch === "\x7f" || ch === "\b") {
          buf.pop();
          return;
        }
        buf.push(ch);
      };

      process.stdin.on("data", onData);
    });
  }

  // Non-hidden: normal readline prompt
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

async function promptMasterPassword(confirmLabel = "", enforceMinLength = false): Promise<string> {
  const label = confirmLabel || "Master password";
  const pw = await prompt(`${label}: `, true);
  if (!pw || pw.trim().length === 0) {
    die("Master password must not be empty.");
  }
  if (enforceMinLength && pw.length < 8) {
    die("Master password must be at least 8 characters.");
  }
  return pw;
}

// ---------------------------------------------------------------------------
// Default policy YAML content
// ---------------------------------------------------------------------------

const DEFAULT_POLICY_YAML = `# Axis Policy File
# Deny-by-default: requests not matching an allow rule are rejected.
#
# Identity is read from the AXIS_IDENTITY environment variable.
# Use "*" to match any identity, service, or action.

policies:
  - identity: local-dev
    allow:
      - service: openai
        actions:
          - responses.create

  # Uncomment to allow all actions for a service:
  # - identity: local-dev
  #   allow:
  #     - service: openai
  #       actions:
  #         - "*"
`;

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/** axis init */
async function cmdInit(): Promise<void> {
  const home = axisHome();
  const configDir = path.resolve(process.cwd(), "config");
  const dataDir = path.resolve(process.cwd(), "data");
  const policyFile = defaultPolicyPath();

  // Create ~/.axis with restricted permissions
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  print(`  ✓ Created ${home}`);

  // Create config/ and data/ in cwd
  fs.mkdirSync(configDir, { recursive: true });
  print(`  ✓ Created ${configDir}`);

  fs.mkdirSync(dataDir, { recursive: true });
  print(`  ✓ Created ${dataDir}`);

  // Write default policy only if it doesn't exist
  if (!fs.existsSync(policyFile)) {
    fs.writeFileSync(policyFile, DEFAULT_POLICY_YAML, { mode: 0o644 });
    print(`  ✓ Created ${policyFile}`);
  } else {
    print(`  · Skipped ${policyFile} (already exists)`);
  }

  // Create .gitignore entry for data/
  const gitignoreInDataDir = path.join(dataDir, ".gitkeep");
  if (!fs.existsSync(gitignoreInDataDir)) {
    fs.writeFileSync(gitignoreInDataDir, "");
  }

  print("");
  print("Axis initialised. Next steps:");
  print("  axis add openai    — store your OpenAI API key");
  print("  axis mcp           — start the MCP server");
}

/** axis setup — interactive first-run wizard */
async function cmdSetup(): Promise<void> {
  print("");
  print("┌─────────────────────────────────────────┐");
  print("│          Axis — First-Time Setup         │");
  print("└─────────────────────────────────────────┘");
  print("");

  // ── Step 1: Init ──────────────────────────────────────────────
  print("Step 1/4 — Initializing Axis\n");
  const home = axisHome();
  const configDir = path.resolve(process.cwd(), "config");
  const dataDir = path.resolve(process.cwd(), "data");
  const policyFile = defaultPolicyPath();

  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  fs.mkdirSync(configDir, { recursive: true });
  fs.mkdirSync(dataDir, { recursive: true });

  if (!fs.existsSync(policyFile)) {
    fs.writeFileSync(policyFile, DEFAULT_POLICY_YAML, { mode: 0o644 });
  }

  const gitkeep = path.join(dataDir, ".gitkeep");
  if (!fs.existsSync(gitkeep)) {
    fs.writeFileSync(gitkeep, "");
  }
  print("  ✓ Config directories created\n");

  // ── Step 2: Master password ───────────────────────────────────
  print("Step 2/4 — Set your master password\n");
  print("  This encrypts all your secrets locally with AES-256-GCM.");
  print("  Minimum 8 characters. You'll need this to start the MCP server.\n");

  const masterPw = await promptMasterPassword("  Master password", true);
  const confirmPw = await promptMasterPassword("  Confirm password");
  if (masterPw !== confirmPw) {
    die("Passwords do not match. Run axis setup again.");
  }
  print("");

  // Store in keychain if possible
  try {
    await keychainSet(masterPw);
    print("  ✓ Master password stored in OS keychain");
  } catch {
    print("  · OS keychain not available — you'll need AXIS_MASTER_PASSWORD env var");
  }
  print("");

  // ── Step 3: First credential ──────────────────────────────────
  print("Step 3/4 — Store your first API key\n");
  print("  Which service do you want to add? Common choices:");
  print("    openai, anthropic, github, stripe, slack, sendgrid,");
  print("    notion, linear, twilio, aws, gcp\n");

  const service = await prompt("  Service name: ");
  if (!service || service.trim().length === 0) {
    die("Service name required. Run axis setup again.");
  }

  const serviceName = service.trim().toLowerCase();
  let secretValue: string;
  if (serviceName === "openai") {
    secretValue = await prompt("  OpenAI API key (sk-...): ", true);
  } else if (serviceName === "anthropic") {
    secretValue = await prompt("  Anthropic API key (sk-ant-...): ", true);
  } else if (serviceName === "github") {
    secretValue = await prompt("  GitHub personal access token (ghp_...): ", true);
  } else {
    secretValue = await prompt(`  Secret value for ${serviceName}: `, true);
  }

  if (!secretValue || secretValue.trim().length === 0) {
    die("Secret must not be empty.");
  }

  const ks = new Keystore(masterPw);
  ks.setSecret(serviceName, secretValue);
  secretValue = "";
  print(`\n  ✓ ${serviceName} credential encrypted and stored\n`);

  // Update policy to allow this service
  try {
    const identity = process.env["AXIS_IDENTITY"] ?? "local-dev";
    const policy = new PolicyEngine();
    policy.addAllowRule(identity, serviceName, ["*"]);
    print(`  ✓ Policy updated: ${identity} → ${serviceName}/*\n`);
  } catch {
    print("  · Could not update policy — add rules manually to config/policy.yaml\n");
  }

  // ── Step 4: MCP auto-registration ─────────────────────────────
  print("Step 4/4 — Registering MCP server\n");

  const manualConfigJson = JSON.stringify({
    axis: {
      command: "axis",
      args: ["mcp"],
      env: { AXIS_IDENTITY: "claude-code" },
    },
  }, null, 2);

  const printManualConfig = (): void => {
    print('\n  Add this to your ~/.claude.json under "mcpServers":\n');
    print(manualConfigJson);
  };

  try {
    // -- Claude Code auto-registration --
    let claudeRegistered = false;
    try {
      execSync("command -v claude", { stdio: "ignore" });
      // claude CLI is available — register via official command
      execSync("claude mcp add axis -- axis mcp", { stdio: "ignore" });
      print("  ✓ Registered Axis MCP server with Claude Code");
      claudeRegistered = true;
    } catch {
      // claude CLI not found or command failed — will show manual config below
    }

    // -- Cursor auto-registration --
    const cursorConfigPath = path.join(os.homedir(), ".cursor", "mcp.json");
    try {
      if (fs.existsSync(cursorConfigPath)) {
        let cursorConfig: Record<string, unknown> = {};
        try {
          cursorConfig = JSON.parse(fs.readFileSync(cursorConfigPath, "utf8"));
        } catch {
          cursorConfig = {};
        }
        const servers = (cursorConfig["mcpServers"] ?? {}) as Record<string, unknown>;
        servers["axis"] = {
          command: "axis",
          args: ["mcp"],
          env: { AXIS_IDENTITY: "claude-code" },
        };
        cursorConfig["mcpServers"] = servers;
        fs.writeFileSync(cursorConfigPath, JSON.stringify(cursorConfig, null, 2) + "\n");
        print("  ✓ Registered Axis MCP server with Cursor");
      }
    } catch {
      // Cursor config not writable — skip silently
    }

    if (!claudeRegistered) {
      printManualConfig();
    }
  } catch {
    // Catch-all: never crash the wizard
    printManualConfig();
  }
  print("");

  // ── Done ──────────────────────────────────────────────────────
  print("┌─────────────────────────────────────────┐");
  print("│            Setup complete ✓              │");
  print("└─────────────────────────────────────────┘");
  print("");
  print("  Your agent can now call:");
  print(`    execute_action({ service: "${serviceName}", action: "...", ... })`);
  print("");
  print("  Useful commands:");
  print("    axis add <service>   — add more credentials");
  print("    axis doctor          — verify everything works");
  print("    axis logs --tail     — watch requests in real time");
  print("    axis dashboard       — open the local web dashboard");
  print("");
}

/** axis add <service> [--stdin] */
async function cmdAdd(service: string, args: string[] = []): Promise<void> {
  if (!service) die("Usage: axis add <service>  (e.g. axis add openai)");

  const useStdin = args.includes("--stdin");
  print(`Adding secret for service: ${service}`);

  // Enforce minimum password length when creating a new keystore (first secret)
  const ksExists = fs.existsSync(keystorePath());
  let isFirstSecret = !ksExists;
  if (ksExists) {
    try {
      const raw = JSON.parse(fs.readFileSync(keystorePath(), "utf8"));
      isFirstSecret = Object.keys(raw.entries || {}).length === 0;
    } catch {
      isFirstSecret = false;
    }
  }

  let masterPw: string;
  if (useStdin && process.env["AXIS_MASTER_PASSWORD"]) {
    masterPw = process.env["AXIS_MASTER_PASSWORD"];
  } else {
    masterPw = await promptMasterPassword("", isFirstSecret);
  }

  let secretValue: string;
  if (useStdin) {
    // Read secret from stdin (piped input)
    secretValue = await new Promise<string>((resolve, reject) => {
      let data = "";
      process.stdin.setEncoding("utf8");
      process.stdin.on("data", (chunk) => { data += chunk; });
      process.stdin.on("end", () => resolve(data.trim()));
      process.stdin.on("error", reject);
    });
  } else {
    if (service === "openai") {
      secretValue = await prompt("OpenAI API key (sk-...): ", true);
    } else {
      secretValue = await prompt(`Secret value for ${service}: `, true);
    }
  }

  if (!secretValue || secretValue.trim().length === 0) {
    die("Secret must not be empty.");
  }

  const ks = new Keystore(masterPw);
  const existing = ks.listServices();
  if (existing.length > 0 && !ks.verifyPassword()) {
    secretValue = "";
    die("Wrong master password.");
  }

  // Free tier: 3 credentials max
  if (existing.length >= 3) {
    print("You've reached the free tier limit of 3 credentials.");
    print("Upgrade to Pro for unlimited credentials: https://axisproxy.com/pro");
    process.exit(0);
  }

  ks.setSecret(service, secretValue);
  secretValue = "";
  print(`  ✓ Secret for "${service}" stored and encrypted.`);
  print(`    Keystore: ${keystorePath()}`);
}

/** axis list */
async function cmdList(): Promise<void> {
  if (!fs.existsSync(keystorePath())) {
    print("No secrets stored. Run: axis add <service>");
    return;
  }

  const masterPw = await promptMasterPassword();
  const ks = new Keystore(masterPw);

  if (!ks.verifyPassword()) {
    die("Wrong master password.");
  }

  const services = ks.listServices();

  if (services.length === 0) {
    print("No secrets stored. Run: axis add <service>");
    return;
  }

  print(`Stored services (${services.length}) — local keystore:`);
  print("");
  for (const svc of services) {
    print(`  ${svc.service.padEnd(20)}  created: ${svc.createdAt}  updated: ${svc.updatedAt}`);
  }
  print("");
}

/** axis revoke <service> */
async function cmdRevoke(service: string): Promise<void> {
  if (!service) die("Usage: axis revoke <service>  (e.g. axis revoke openai)");

  const masterPw = await promptMasterPassword();
  const ks = new Keystore(masterPw);

  if (!ks.verifyPassword()) {
    die("Wrong master password.");
  }

  const deleted = ks.deleteSecret(service);
  if (deleted) {
    print(`  ✓ Secret for "${service}" revoked.`);
  } else {
    print(`  · No secret found for "${service}" — nothing to revoke.`);
  }
}

/** axis doctor */
async function cmdDoctor(): Promise<void> {
  print("Axis Doctor — running health checks\n");
  let ok = true;

  const check = (label: string, pass: boolean, detail?: string): void => {
    const icon = pass ? "✓" : "✗";
    const status = pass ? "OK" : "FAIL";
    print(`  ${icon} ${label.padEnd(40)} ${status}${detail ? `  (${detail})` : ""}`);
    if (!pass) ok = false;
  };

  // 1. ~/.axis directory
  const home = axisHome();
  check("~/.axis directory exists", fs.existsSync(home), home);

  // 2. Keystore file (may not exist yet)
  const kPath = keystorePath();
  const kExists = fs.existsSync(kPath);
  check("Keystore file exists", kExists, kPath);
  if (kExists) {
    try {
      const stat = fs.statSync(kPath);
      const mode = (stat.mode & 0o777).toString(8);
      check("Keystore file permissions (600)", mode === "600", `mode=${mode}`);
    } catch (err) {
      check("Keystore file readable", false, (err as Error).message);
    }
  }

  // 3. Policy file
  const policyPath = defaultPolicyPath();
  const policyExists = fs.existsSync(policyPath);
  check("Policy file exists", policyExists, policyPath);
  if (policyExists) {
    try {
      const pe = new PolicyEngine(policyPath);
      const policies = pe.getPolicies();
      check("Policy file parses OK", true, `${policies.length} rule(s)`);
      // Check a sample allow
      const sampleAllow = pe.isAllowed("local-dev", "openai", "responses.create");
      check(
        'Policy allows local-dev→openai→responses.create',
        sampleAllow.allowed
      );
    } catch (err) {
      check("Policy file parses OK", false, (err as Error).message);
    }
  }

  // 4. Audit log directory
  const auditPath = auditLogPath();
  const auditDir = path.dirname(auditPath);
  check("Audit log directory exists", fs.existsSync(auditDir), auditDir);

  // 5. Crypto self-test
  let masterPw: string;
  if (!kExists) {
    // No keystore yet — use a random key just to prove AES-256-GCM works
    masterPw = crypto.randomBytes(16).toString("hex");
  } else {
    // Try keychain first, fall back to interactive prompt
    let keychainPw: string | null = null;
    try {
      keychainPw = await keychainGet();
    } catch {
      // keychain unavailable — fall through to prompt
    }
    masterPw = keychainPw ?? await promptMasterPassword("Master password (for crypto test)");
  }
  try {
    Keystore.selfTest(masterPw);
    check("AES-256-GCM crypto self-test", true);
  } catch (err) {
    check("AES-256-GCM crypto self-test", false, (err as Error).message);
  }

  // 6. Keystore password verification
  const ks = new Keystore(masterPw);
  const services = ks.listServices();
  if (services.length > 0) {
    const pwOk = ks.verifyPassword();
    check("Master password decrypts keystore", pwOk);
  } else {
    check("Master password check (skipped — no secrets yet)", true, "no entries");
  }

  // 7. OpenAI proxy request construction (no live call)
  if (services.find((s) => s.service === "openai")) {
    try {
      // Verify we can at least retrieve the secret
      const secret = ks.getSecret("openai");
      const hasPrefix = secret.startsWith("sk-") || secret.startsWith("Bearer ");
      // Overwrite immediately
      const redacted = secret.replace(/./g, "*");
      void redacted; // reference to avoid optimizer removing it
      check(
        "OpenAI key retrievable from keystore",
        true,
        `key starts with "sk-": ${hasPrefix}`
      );
    } catch (err) {
      check("OpenAI key retrievable from keystore", false, (err as Error).message);
    }
  } else {
    check("OpenAI key check (skipped — not stored)", true, 'run "axis add openai"');
  }

  print("");
  if (ok) {
    print("All checks passed.");
  } else {
    print("Some checks failed. Review the output above.");
    process.exit(1);
  }
}

/** axis mcp — delegates to built dist/mcp/server.js */
function cmdMcp(): void {
  const serverPath = path.resolve(__dirname, "../mcp/server.js");
  if (!fs.existsSync(serverPath)) {
    die(
      `MCP server not built: ${serverPath}\nRun "npm run build" first.`
    );
  }

  // Exec the server — replaces current process
  try {
    execFileSync(process.execPath, [serverPath], {
      stdio: "inherit",
      env: process.env,
    });
  } catch (err) {
    // execFileSync throws on non-zero exit; that's fine for MCP shutdown
    const code = (err as NodeJS.ErrnoException & { status?: number }).status ?? 1;
    // Exit code 130 = SIGINT (Ctrl-C) — not a real error, suppress exit
    if (code !== 130) process.exit(code);
  }
}

// ---------------------------------------------------------------------------
// Logs helpers + command
// ---------------------------------------------------------------------------

/** Format a single audit log entry as a human-readable line. */
function formatLogEntry(entry: AuditEntry): string {
  // Convert ISO-8601 to "YYYY-MM-DD HH:MM:SS"
  const ts = entry.timestamp.replace("T", " ").replace(/\.\d+Z$/, "");
  const decision = entry.decision.toUpperCase().padEnd(5);
  const latency = `${entry.latency_ms ?? 0}ms`;
  const reqId = entry.request_id.slice(0, 8);
  const errorSuffix = entry.error ? `  (${entry.error})` : "";
  return `[${ts}] ${decision}  ${entry.identity} → ${entry.service}/${entry.action}  ${latency}  req:${reqId}${errorSuffix}`;
}

/** Parse a named flag value from args (e.g. --service openai → "openai") */
function parseFlag(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx === -1 || idx + 1 >= args.length) return undefined;
  return args[idx + 1];
}

/** Check if an audit entry matches the active filters. */
function matchesFilters(entry: AuditEntry, serviceFilter?: string, decisionFilter?: string): boolean {
  if (serviceFilter && entry.service !== serviceFilter) return false;
  if (decisionFilter && entry.decision !== decisionFilter) return false;
  return true;
}

/** axis logs [--tail] [--last <n>] [--service <name>] [--decision <allow|deny|error>] */
async function cmdLogs(args: string[]): Promise<void> {
  const logPath = auditLogPath();
  const tail = args.includes("--tail");

  let lastN = 50;
  const lastIdx = args.indexOf("--last");
  if (lastIdx !== -1) {
    const n = parseInt(args[lastIdx + 1] ?? "", 10);
    if (isNaN(n) || n < 1) die("--last requires a positive integer");
    lastN = n;
  }

  const serviceFilter = parseFlag(args, "--service");
  const decisionFilter = parseFlag(args, "--decision");

  if (!fs.existsSync(logPath)) {
    print(`No audit log found at ${logPath}. Run axis mcp to start logging.`);
    return;
  }

  const content = fs.readFileSync(logPath, "utf8");
  const lines = content.split("\n").filter((l) => l.trim().length > 0);

  // Parse all, filter, then take last N
  const entries: AuditEntry[] = [];
  for (const line of lines) {
    try {
      const entry = JSON.parse(line) as AuditEntry;
      if (matchesFilters(entry, serviceFilter, decisionFilter)) {
        entries.push(entry);
      }
    } catch {
      // Skip malformed lines
    }
  }

  for (const entry of entries.slice(-lastN)) {
    print(formatLogEntry(entry));
  }

  if (tail) {
    print("");
    print("Watching for new entries (Ctrl-C to stop)...");
    let offset = fs.statSync(logPath).size;

    fs.watch(logPath, () => {
      try {
        const stat = fs.statSync(logPath);
        if (stat.size <= offset) return;
        const fd = fs.openSync(logPath, "r");
        const buffer = Buffer.alloc(stat.size - offset);
        fs.readSync(fd, buffer, 0, buffer.length, offset);
        fs.closeSync(fd);
        offset = stat.size;
        const newLines = buffer.toString("utf8").split("\n").filter((l) => l.trim().length > 0);
        for (const newLine of newLines) {
          try {
            const entry = JSON.parse(newLine) as AuditEntry;
            if (matchesFilters(entry, serviceFilter, decisionFilter)) {
              print(formatLogEntry(entry));
            }
          } catch {
            // Skip malformed lines
          }
        }
      } catch {
        // Ignore transient watch errors
      }
    });
  }
}

// ---------------------------------------------------------------------------
// Keychain command
// ---------------------------------------------------------------------------

/** axis keychain <set|delete|status> */
async function cmdKeychain(subcommand: string): Promise<void> {
  switch (subcommand) {
    case "set": {
      const pw = await promptMasterPassword("Master password to store in keychain", true);
      const confirm = await promptMasterPassword("Confirm");
      if (pw !== confirm) {
        die("Passwords do not match.");
      }
      try {
        await keychainSet(pw);
      } catch (err) {
        die((err as Error).message);
      }
      print("  ✓ Master password stored in OS keychain.");
      print("    You can now remove AXIS_MASTER_PASSWORD from your MCP config.");
      break;
    }
    case "delete": {
      let deleted = false;
      try {
        deleted = await keychainDelete();
      } catch (err) {
        die((err as Error).message);
      }
      if (deleted) {
        print("  ✓ Master password removed from OS keychain.");
      } else {
        print("  · No master password found in keychain.");
      }
      break;
    }
    case "status": {
      let exists = false;
      try {
        exists = await keychainExists();
      } catch (err) {
        die((err as Error).message);
      }
      if (exists) {
        print("Keychain: master password is stored");
      } else {
        print("Keychain: no master password stored");
      }
      break;
    }
    default:
      die(
        `Unknown keychain subcommand: "${subcommand}"\n` +
          "Usage: axis keychain <set|delete|status>"
      );
  }
}

// ---------------------------------------------------------------------------
// Rotate command
// ---------------------------------------------------------------------------

/** axis rotate <service> or axis rotate --all */
async function cmdRotate(service: string): Promise<void> {
  if (!service) die("Usage: axis rotate <service>  (e.g. axis rotate openai)");

  // 1. Prompt for current master password
  const currentPw = await promptMasterPassword("Current master password");

  // 2. Verify current password
  const ks = new Keystore(currentPw);
  if (!ks.verifyPassword()) {
    die("Wrong master password.");
  }

  if (service === "--all") {
    const services = ks.listServices();
    if (services.length === 0) {
      print("No secrets stored — nothing to rotate.");
      return;
    }

    // Prompt for new master password once
    const newPw = await promptMasterPassword("New master password", true);
    const confirmPw = await promptMasterPassword("Confirm new master password");
    if (newPw !== confirmPw) die("Passwords do not match.");

    const newKs = new Keystore(newPw);
    for (const svc of services) {
      let secret = ks.getSecret(svc.service);
      newKs.setSecret(svc.service, secret);
      secret = "";
      print(`  ✓ ${svc.service} re-encrypted`);
    }
    print(`\n  All ${services.length} secret(s) re-encrypted with new master password.`);
    return;
  }

  // Single service rotation
  let secret: string;
  try {
    secret = ks.getSecret(service);
  } catch (err) {
    die((err as Error).message);
  }

  const newPw = await promptMasterPassword("New master password");
  const confirmPw = await promptMasterPassword("Confirm new master password");
  if (newPw !== confirmPw) {
    secret = "";
    die("Passwords do not match.");
  }

  const newKs = new Keystore(newPw);
  newKs.setSecret(service, secret);
  secret = "";

  print(`  ✓ Secret for "${service}" re-encrypted with new master password.`);
  print(`    Note: other services remain encrypted with the old password.`);
  print(`    Run axis rotate --all to rotate all services at once.`);
}

// ---------------------------------------------------------------------------
// Allow / Deny commands
// ---------------------------------------------------------------------------

/** axis allow <service> [action] */
async function cmdAllow(args: string[]): Promise<void> {
  const service = args[0];
  if (!service) die("Usage: axis allow <service> [action]  (e.g. axis allow github issues.create)");

  const action = args[1]; // optional
  const identity = process.env["AXIS_IDENTITY"] ?? "local-dev";
  const actions = action ? [action] : ["*"];

  const policy = new PolicyEngine();
  policy.addAllowRule(identity, service, actions);

  const actionLabel = action ?? "*";
  print(`  ✓ Policy updated: ${identity} can now access ${service}/${actionLabel}`);
}

/** axis deny <service> */
async function cmdDeny(args: string[]): Promise<void> {
  const service = args[0];
  if (!service) die("Usage: axis deny <service>  (e.g. axis deny github)");

  const identity = process.env["AXIS_IDENTITY"] ?? "local-dev";
  const policy = new PolicyEngine();
  const removed = policy.removeAllowRule(identity, service);

  if (removed) {
    print(`  ✓ Policy updated: removed ${service} access for ${identity}`);
  } else {
    print(`  · No ${service} rule found for ${identity} — nothing to remove.`);
  }
}

/** axis dashboard — start the local web dashboard */
async function cmdDashboard(): Promise<void> {
  // Resolve master password (same logic as MCP server)
  const envPassword = process.env["AXIS_MASTER_PASSWORD"];
  let masterPw: string;

  if (envPassword && envPassword.trim().length > 0) {
    masterPw = envPassword;
  } else {
    // Try keychain
    let keychainPw: string | null = null;
    try {
      keychainPw = await keychainGet();
    } catch {
      // keychain unavailable
    }

    if (keychainPw) {
      masterPw = keychainPw;
    } else {
      masterPw = await promptMasterPassword();
    }
  }

  // Dynamically import to avoid loading express for non-dashboard commands
  const { startDashboard } = await import("../dashboard/server.js");
  await startDashboard(masterPw);
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

function printHelp(): void {
  print(`
Axis v0.7.0

Usage:
  axis <command> [args]

Commands:
  setup             Interactive first-run wizard (init + add + keychain + MCP config)
  init              Create config directories and default policy.yaml
  add <service>     Store an encrypted secret for a service (e.g. openai)
                      --stdin             Read secret from stdin (for CI/scripts)
  list              List stored service names and metadata (no secrets)
  revoke <service>  Delete the stored secret for a service
  doctor            Run health checks on config, crypto, and keystore
  dashboard         Open the local web dashboard (http://localhost:3847)
  mcp               Start the MCP server (reads master password from keychain or AXIS_MASTER_PASSWORD)
  logs              Show audit log entries (newest last, default 50)
                      --last <n>          Show last N entries
                      --tail              Watch for new entries in real time
                      --service <name>    Filter by service
                      --decision <type>   Filter by decision (allow|deny|error)
  rotate <service>  Re-encrypt a service secret under a new master password
  rotate --all      Re-encrypt all secrets under a new master password
  allow <svc> [act] Add a policy rule allowing a service (or specific action)
                      Uses AXIS_IDENTITY (default: local-dev)
  deny <service>    Remove all allow rules for a service
  keychain set      Store master password in OS keychain (eliminates plaintext in config)
  keychain delete   Remove master password from OS keychain
  keychain status   Check whether master password is in keychain
  help              Show this help message

Environment variables (for MCP server):
  AXIS_MASTER_PASSWORD    Master password (optional if stored in OS keychain via "axis keychain set")
  AXIS_IDENTITY           Identity for policy checks (default: "unknown")
  AXIS_POLICY_PATH        Override path to policy.yaml

Examples:
  axis add openai
  axis list
  axis mcp                              # uses OS keychain for master password
  AXIS_MASTER_PASSWORD=secret axis mcp  # or pass explicitly via env
`);
}

// ---------------------------------------------------------------------------
// First-run welcome
// ---------------------------------------------------------------------------

function firstRunMarkerPath(): string {
  return path.join(os.homedir(), ".axis", ".welcomed");
}

function showFirstRunMessageIfNeeded(command: string): void {
  // Skip for mcp (non-interactive stdio process)
  if (command === "mcp") return;

  const marker = firstRunMarkerPath();
  if (fs.existsSync(marker)) return;

  // Show once, then mark as seen
  print("");
  print("👋 First time using Axis? Run:");
  print("   axis setup");
  print("");
  print("   This wizard walks you through init, credential storage,");
  print("   keychain setup, and MCP configuration in under 90 seconds.");
  print("");

  try {
    fs.mkdirSync(path.join(os.homedir(), ".axis"), { recursive: true, mode: 0o700 });
    fs.writeFileSync(marker, new Date().toISOString() + "\n", { mode: 0o600 });
  } catch {
    // Non-fatal — if we can't write the marker, we just show it again next time
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const [, , command, ...rest] = process.argv;

  showFirstRunMessageIfNeeded(command ?? "");

  switch (command) {
    case "setup":
      await cmdSetup();
      break;
    case "init":
      await cmdInit();
      break;
    case "add":
      await cmdAdd(rest[0] ?? "", rest.slice(1));
      break;
    case "list":
      await cmdList();
      break;
    case "revoke":
      await cmdRevoke(rest[0] ?? "");
      break;
    case "doctor":
      await cmdDoctor();
      break;
    case "dashboard":
      await cmdDashboard();
      break;
    case "mcp":
      cmdMcp();
      break;
    case "logs":
      await cmdLogs(rest);
      break;
    case "rotate":
      await cmdRotate(rest[0] ?? "");
      break;
    case "keychain":
      await cmdKeychain(rest[0] ?? "");
      break;
    case "allow":
      await cmdAllow(rest);
      break;
    case "deny":
      await cmdDeny(rest);
      break;
    case "help":
    case "--help":
    case "-h":
      printHelp();
      break;
    default:
      if (command) {
        printErr(`Unknown command: ${command}`);
      }
      printHelp();
      process.exit(command ? 1 : 0);
  }
}

main().catch((err) => {
  printErr(`Error: ${(err as Error).message}`);
  process.exit(1);
});
