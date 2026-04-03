/**
 * dashboard/server.ts
 *
 * Local-only HTTP dashboard for Axis.
 * Serves at http://localhost:3847 — never exposed to the network.
 *
 * Security: binds to 127.0.0.1 only. No auth needed (local machine).
 * The master password is required at startup to read the keystore.
 */

import express from "express";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { Keystore, keystorePath } from "../vault/keystore.js";
import { PolicyEngine, defaultPolicyPath } from "../policy/policy.js";
import { auditLogPath, AuditEntry } from "../audit/audit.js";

const DEFAULT_PORT = 3847;
const HOST = "127.0.0.1"; // Local only — never 0.0.0.0

export async function startDashboard(masterPassword: string, port = DEFAULT_PORT): Promise<ReturnType<ReturnType<typeof express>["listen"]>> {
  const app = express();

  // ── Keystore (read-only) ──────────────────────────────────────
  const ks = new Keystore(masterPassword);
  if (!ks.verifyPassword()) {
    process.stderr.write("Error: Wrong master password.\n");
    process.exit(1);
  }

  // ── Policy engine ─────────────────────────────────────────────
  let policy: PolicyEngine | null;
  try {
    policy = new PolicyEngine();
  } catch {
    policy = null;
  }

  // ── API routes ────────────────────────────────────────────────

  // Health check
  app.get("/api/health", (_req, res) => {
    const checks: Array<{ name: string; ok: boolean; detail?: string }> = [];

    // ~/.axis directory
    const home = path.join(os.homedir(), ".axis");
    checks.push({ name: "Axis home directory", ok: fs.existsSync(home), detail: home });

    // Keystore
    const kPath = keystorePath();
    const kExists = fs.existsSync(kPath);
    checks.push({ name: "Keystore file", ok: kExists, detail: kPath });
    if (kExists) {
      const mode = (fs.statSync(kPath).mode & 0o777).toString(8);
      checks.push({ name: "Keystore permissions (600)", ok: mode === "600", detail: `mode=${mode}` });
    }

    // Policy
    const policyPath = defaultPolicyPath();
    checks.push({ name: "Policy file", ok: fs.existsSync(policyPath), detail: policyPath });

    // Crypto self-test
    try {
      Keystore.selfTest(masterPassword);
      checks.push({ name: "AES-256-GCM self-test", ok: true });
    } catch (err) {
      checks.push({ name: "AES-256-GCM self-test", ok: false, detail: (err as Error).message });
    }

    // Password verification
    checks.push({ name: "Master password valid", ok: ks.verifyPassword() });

    const allOk = checks.every((c) => c.ok);
    res.json({ ok: allOk, checks });
  });

  // List services (metadata only — never secrets)
  app.get("/api/services", (_req, res) => {
    const services = ks.listServices();
    res.json({ services, count: services.length, limit: 3 });
  });

  // Audit logs
  app.get("/api/logs", (req, res) => {
    const logPath = auditLogPath();
    if (!fs.existsSync(logPath)) {
      res.json({ entries: [], total: 0 });
      return;
    }

    const lastN = parseInt(req.query.last as string) || 100;
    const serviceFilter = req.query.service as string | undefined;
    const decisionFilter = req.query.decision as string | undefined;

    const content = fs.readFileSync(logPath, "utf8");
    const lines = content.split("\n").filter((l) => l.trim().length > 0);

    const entries: AuditEntry[] = [];
    for (const line of lines) {
      try {
        const entry = JSON.parse(line) as AuditEntry;
        if (serviceFilter && entry.service !== serviceFilter) continue;
        if (decisionFilter && entry.decision !== decisionFilter) continue;
        entries.push(entry);
      } catch {
        // Skip malformed lines
      }
    }

    const sliced = entries.slice(-lastN);
    res.json({ entries: sliced, total: entries.length });
  });

  // Policy rules
  app.get("/api/policy", (_req, res) => {
    if (!policy) {
      res.json({ error: "No policy file found", rules: [] });
      return;
    }
    const rules = policy.getPolicies();
    res.json({ rules, path: policy.getPath() });
  });

  // Aggregate stats
  app.get("/api/stats", (_req, res) => {
    const logPath = auditLogPath();
    if (!fs.existsSync(logPath)) {
      res.json({ total: 0, allowed: 0, denied: 0, errors: 0, byService: {} });
      return;
    }

    const content = fs.readFileSync(logPath, "utf8");
    const lines = content.split("\n").filter((l) => l.trim().length > 0);

    let total = 0;
    let allowed = 0;
    let denied = 0;
    let errors = 0;
    const byService: Record<string, number> = {};

    for (const line of lines) {
      try {
        const entry = JSON.parse(line) as AuditEntry;
        total++;
        if (entry.decision === "allow") allowed++;
        else if (entry.decision === "deny") denied++;
        else if (entry.decision === "error") errors++;
        byService[entry.service] = (byService[entry.service] || 0) + 1;
      } catch {
        // Skip
      }
    }

    res.json({ total, allowed, denied, errors, byService });
  });

  // ── Serve static dashboard ────────────────────────────────────
  const dashboardHtml = path.resolve(__dirname, "index.html");
  app.get("/", (_req, res) => {
    res.sendFile(dashboardHtml);
  });

  // ── Start server ──────────────────────────────────────────────
  return new Promise((resolve) => {
    const server = app.listen(port, HOST, () => {
      console.log(`\n  Axis Dashboard running at http://${HOST}:${port}\n`);
      console.log("  Press Ctrl+C to stop.\n");

      // Try to open browser (only on default port, skip in tests)
      if (port === DEFAULT_PORT) {
        const { exec } = require("child_process");
        const openCmd =
          process.platform === "darwin" ? "open" :
          process.platform === "win32" ? "start" : "xdg-open";
        exec(`${openCmd} http://${HOST}:${port}`);
      }

      resolve(server);
    });
  });
}
