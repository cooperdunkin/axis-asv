/**
 * vault/keystore.ts
 *
 * AES-256-GCM encrypted keystore backed by ~/.axis/keystore.json.
 * Master password is used to derive per-service encryption keys via PBKDF2.
 * No plaintext secret is ever written to disk.
 *
 * Security design:
 *   - Each secret gets a unique random 32-byte salt and 12-byte IV.
 *   - Key derivation: PBKDF2-SHA-512, 210 000 iterations (OWASP 2023 min).
 *   - Authenticated encryption: AES-256-GCM (256-bit key, 128-bit auth tag).
 *   - Keystore file stores: salt (hex), iv (hex), ciphertext (hex), tag (hex), metadata.
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ServiceEntry {
  /** PBKDF2 salt, hex-encoded, unique per entry */
  salt: string;
  /** AES-GCM initialisation vector, hex-encoded, 12 bytes */
  iv: string;
  /** Encrypted secret, hex-encoded */
  ciphertext: string;
  /** AES-GCM authentication tag, hex-encoded, 16 bytes */
  tag: string;
  /** Human-readable metadata — never contains the secret */
  metadata: {
    service: string;
    createdAt: string;
    updatedAt: string;
  };
}

export interface KeystoreData {
  version: number;
  entries: Record<string, ServiceEntry>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PBKDF2_ITERATIONS = 210_000;
const PBKDF2_KEYLEN = 32; // 256 bits for AES-256
const PBKDF2_DIGEST = "sha512";
const SALT_BYTES = 32;
const IV_BYTES = 12; // 96-bit nonce, optimal for AES-GCM
const AUTH_TAG_LENGTH = 16; // 128-bit tag

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

export function axisHome(): string {
  return path.join(os.homedir(), ".axis");
}

export function keystorePath(): string {
  return path.join(axisHome(), "keystore.json");
}

// ---------------------------------------------------------------------------
// Keystore I/O
// ---------------------------------------------------------------------------

function loadKeystoreRaw(): KeystoreData {
  const kPath = keystorePath();
  if (!fs.existsSync(kPath)) {
    return { version: 1, entries: {} };
  }
  const raw = fs.readFileSync(kPath, "utf-8");
  const parsed = JSON.parse(raw) as KeystoreData;
  if (typeof parsed.version !== "number" || typeof parsed.entries !== "object") {
    throw new Error("Keystore file is corrupt or in an unexpected format.");
  }
  return parsed;
}

function saveKeystore(data: KeystoreData): void {
  const kPath = keystorePath();
  fs.mkdirSync(path.dirname(kPath), { recursive: true, mode: 0o700 });
  // Write atomically via temp file to avoid partial writes
  const tmp = kPath + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, kPath);
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

function deriveKey(password: string, salt: Buffer): Buffer {
  return crypto.pbkdf2Sync(
    password,
    salt,
    PBKDF2_ITERATIONS,
    PBKDF2_KEYLEN,
    PBKDF2_DIGEST
  );
}

// ---------------------------------------------------------------------------
// Encrypt / Decrypt
// ---------------------------------------------------------------------------

function encrypt(
  plaintext: string,
  password: string
): { salt: string; iv: string; ciphertext: string; tag: string } {
  const salt = crypto.randomBytes(SALT_BYTES);
  const iv = crypto.randomBytes(IV_BYTES);
  const key = deriveKey(password, salt);

  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });

  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return {
    salt: salt.toString("hex"),
    iv: iv.toString("hex"),
    ciphertext: encrypted.toString("hex"),
    tag: tag.toString("hex"),
  };
}

function decrypt(entry: ServiceEntry, password: string): string {
  const salt = Buffer.from(entry.salt, "hex");
  const iv = Buffer.from(entry.iv, "hex");
  const ciphertext = Buffer.from(entry.ciphertext, "hex");
  const tag = Buffer.from(entry.tag, "hex");

  const key = deriveKey(password, salt);

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv, {
    authTagLength: AUTH_TAG_LENGTH,
  });
  decipher.setAuthTag(tag);

  try {
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString("utf8");
  } catch {
    throw new Error(
      "Decryption failed — wrong master password or tampered keystore entry."
    );
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export class Keystore {
  private masterPassword: string;

  constructor(masterPassword: string) {
    if (!masterPassword || masterPassword.length === 0) {
      throw new Error("Master password must not be empty.");
    }
    this.masterPassword = masterPassword;
  }

  /** Store (or overwrite) an encrypted secret for a service. */
  setSecret(service: string, secret: string): void {
    if (!service || service.trim().length === 0) {
      throw new Error("Service name must not be empty.");
    }
    if (!secret || secret.length === 0) {
      throw new Error("Secret must not be empty.");
    }

    const data = loadKeystoreRaw();
    const { salt, iv, ciphertext, tag } = encrypt(secret, this.masterPassword);
    const now = new Date().toISOString();

    data.entries[service] = {
      salt,
      iv,
      ciphertext,
      tag,
      metadata: {
        service,
        createdAt: data.entries[service]?.metadata.createdAt ?? now,
        updatedAt: now,
      },
    };

    saveKeystore(data);
  }

  /** Retrieve and decrypt a secret. Throws if service not found or decryption fails. */
  getSecret(service: string): string {
    const data = loadKeystoreRaw();
    const entry = data.entries[service];
    if (!entry) {
      throw new Error(`No secret stored for service: "${service}"`);
    }
    return decrypt(entry, this.masterPassword);
  }

  /** Delete a stored secret. Returns true if it existed, false otherwise. */
  deleteSecret(service: string): boolean {
    const data = loadKeystoreRaw();
    if (!data.entries[service]) return false;
    delete data.entries[service];
    saveKeystore(data);
    return true;
  }

  /** List service names and their metadata. Never returns secrets. */
  listServices(): Array<{ service: string; createdAt: string; updatedAt: string }> {
    const data = loadKeystoreRaw();
    return Object.values(data.entries).map((e) => ({
      service: e.metadata.service,
      createdAt: e.metadata.createdAt,
      updatedAt: e.metadata.updatedAt,
    }));
  }

  /**
   * Verify the master password is correct by attempting to decrypt any stored entry.
   * Returns true if password is valid (or if keystore is empty — nothing to validate against).
   */
  verifyPassword(): boolean {
    const data = loadKeystoreRaw();
    const entries = Object.values(data.entries);
    if (entries.length === 0) return true;
    try {
      decrypt(entries[0], this.masterPassword);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Self-test: encrypt then decrypt a known value to confirm crypto pipeline works.
   * Returns true on success, throws on failure.
   */
  static selfTest(password: string): boolean {
    const testValue = "axis-self-test-" + crypto.randomBytes(8).toString("hex");
    const { salt, iv, ciphertext, tag } = encrypt(testValue, password);
    const entry: ServiceEntry = {
      salt,
      iv,
      ciphertext,
      tag,
      metadata: {
        service: "__test__",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
    };
    const result = decrypt(entry, password);
    if (result !== testValue) {
      throw new Error("Keystore self-test: decrypted value mismatch.");
    }
    return true;
  }
}
