/**
 * cloud/client.ts
 *
 * Axis Cloud Client — Supabase auth + HTTP calls to the Axis Cloud API.
 *
 * Session is stored at ~/.axis/config.json (mode 600).
 * The anon key is intentionally public (restricted by Supabase RLS).
 */

import { createClient } from "@supabase/supabase-js";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { decryptSecret, SecretStore } from "../vault/keystore.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SUPABASE_URL = "https://wjiqxmkqseatnruwuoir.supabase.co";
const SUPABASE_ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6IndqaXF4bWtxc2VhdG5ydXd1b2lyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzQ4MTQzNzcsImV4cCI6MjA5MDM5MDM3N30.xzDY-SwnR44JofzGv386uCM1EkE18UcwGL3iCKb9MdA";
const API_BASE = "https://axis-webhook.vercel.app";

const CONFIG_PATH = path.join(os.homedir(), ".axis", "config.json");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CloudSession {
  accessToken: string;
  refreshToken: string;
  email: string;
}

export interface CredentialMeta {
  id: string;
  service: string;
  created_at: string;
  updated_at: string;
}

interface CredentialWithCiphertext {
  id: string;
  service: string;
  ciphertext: string;
  salt: string;
  iv: string;
  auth_tag: string;
}

// ---------------------------------------------------------------------------
// Session file helpers
// ---------------------------------------------------------------------------

function loadSession(): CloudSession | null {
  try {
    if (!fs.existsSync(CONFIG_PATH)) return null;
    const raw = fs.readFileSync(CONFIG_PATH, "utf-8");
    const parsed = JSON.parse(raw) as Partial<CloudSession>;
    if (!parsed.accessToken || !parsed.email) return null;
    return parsed as CloudSession;
  } catch {
    return null;
  }
}

function saveSession(session: CloudSession): void {
  const dir = path.dirname(CONFIG_PATH);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(session, null, 2), { mode: 0o600 });
}

function clearSession(): void {
  if (fs.existsSync(CONFIG_PATH)) {
    fs.unlinkSync(CONFIG_PATH);
  }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

async function apiRequest<T>(
  method: string,
  endpoint: string,
  accessToken: string,
  body?: unknown
): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  const headers: Record<string, string> = {
    Authorization: `Bearer ${accessToken}`,
    "Content-Type": "application/json",
  };
  const res = await fetch(url, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    let detail = text;
    try {
      const json = JSON.parse(text) as { error?: string };
      if (json.error) detail = json.error;
    } catch {
      // use raw text
    }
    throw new Error(`${detail} (HTTP ${res.status})`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// CloudClient
// ---------------------------------------------------------------------------

export class CloudClient {
  /** Create a new Supabase account. */
  static async signup(email: string, password: string): Promise<void> {
    const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
    const { data, error } = await supabase.auth.signUp({ email, password });
    if (error) throw new Error(error.message);

    if (!data.session) {
      // Supabase requires email confirmation
      throw new Error(
        "Account created — check your email and click the confirmation link, then run: axis login"
      );
    }

    saveSession({
      accessToken: data.session.access_token,
      refreshToken: data.session.refresh_token,
      email: data.user?.email ?? email,
    });
  }

  /** Sign in with email + password. */
  static async login(email: string, password: string): Promise<void> {
    const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) throw new Error(error.message);

    saveSession({
      accessToken: data.session.access_token,
      refreshToken: data.session.refresh_token,
      email: data.user.email ?? email,
    });
  }

  /** Sign out and delete local session. */
  static async logout(): Promise<void> {
    clearSession();
  }

  /** Returns the stored session, or null if not logged in. */
  static getSession(): CloudSession | null {
    return loadSession();
  }

  // -------------------------------------------------------------------------
  // Credentials API
  // -------------------------------------------------------------------------

  /** List all credentials (metadata only — no ciphertext). */
  static async listCredentials(): Promise<CredentialMeta[]> {
    const session = loadSession();
    if (!session) throw new Error("Not logged in. Run: axis login");
    return apiRequest<CredentialMeta[]>("GET", "/api/credentials", session.accessToken);
  }

  /** Store an encrypted credential. Returns the new credential id. */
  static async addCredential(
    service: string,
    ciphertext: string,
    salt: string,
    iv: string,
    authTag: string
  ): Promise<string> {
    const session = loadSession();
    if (!session) throw new Error("Not logged in. Run: axis login");
    const result = await apiRequest<{ id: string }>(
      "POST",
      "/api/credentials",
      session.accessToken,
      { service, ciphertext, salt, iv, auth_tag: authTag }
    );
    return result.id;
  }

  /** Fetch a single credential with its ciphertext (for decryption). */
  static async getCredential(id: string): Promise<CredentialWithCiphertext> {
    const session = loadSession();
    if (!session) throw new Error("Not logged in. Run: axis login");
    return apiRequest<CredentialWithCiphertext>(
      "GET",
      `/api/credentials/${id}`,
      session.accessToken
    );
  }

  /** Delete a credential by id. */
  static async deleteCredential(id: string): Promise<void> {
    const session = loadSession();
    if (!session) throw new Error("Not logged in. Run: axis login");
    await apiRequest<void>("DELETE", `/api/credentials/${id}`, session.accessToken);
  }
}

// ---------------------------------------------------------------------------
// CloudKeystore — in-memory SecretStore backed by cloud credentials
// ---------------------------------------------------------------------------

/**
 * Implements SecretStore so it can be passed to proxyRequest.
 * Secrets are fetched from cloud and decrypted locally on demand.
 * An index of service → id is pre-loaded; ciphertext is fetched per-call.
 */
export class CloudKeystore implements SecretStore {
  /** Decrypted secrets pre-loaded at startup — never written to disk. */
  private secrets: Map<string, string>; // service → plaintext secret
  private meta: CredentialMeta[];

  private constructor(secrets: Map<string, string>, meta: CredentialMeta[]) {
    this.secrets = secrets;
    this.meta = meta;
  }

  /**
   * Build a CloudKeystore by fetching all credentials from cloud and decrypting them locally.
   * This pre-loads all secrets into memory so getSecret() can be synchronous.
   * Call once at MCP server startup.
   */
  static async build(masterPassword: string): Promise<CloudKeystore> {
    const metas = await CloudClient.listCredentials();
    const secrets = new Map<string, string>();

    for (const m of metas) {
      const cred = await CloudClient.getCredential(m.id);
      const plaintext = decryptSecret(
        { ciphertext: cred.ciphertext, salt: cred.salt, iv: cred.iv, tag: cred.auth_tag },
        masterPassword
      );
      secrets.set(m.service, plaintext);
    }

    return new CloudKeystore(secrets, metas);
  }

  /** Returns the decrypted secret for a service. Synchronous — pre-loaded at build time. */
  getSecret(service: string): string {
    const secret = this.secrets.get(service);
    if (!secret) {
      throw new Error(`No secret stored for service: "${service}"`);
    }
    return secret;
  }

  /** Returns metadata list (same shape as Keystore.listServices). */
  listServices(): Array<{ service: string; createdAt: string; updatedAt: string }> {
    return this.meta.map((m) => ({
      service: m.service,
      createdAt: m.created_at,
      updatedAt: m.updated_at,
    }));
  }
}
