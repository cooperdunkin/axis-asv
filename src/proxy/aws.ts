/**
 * proxy/aws.ts
 *
 * AWS S3 proxy using Signature Version 4 (SigV4).
 * Axis retrieves the stored credential and injects it — the agent never sees it.
 *
 * Supported actions:
 *   service: "aws"
 *   action:  "s3.getObject" | "s3.putObject"
 *
 * Security invariants:
 *   - Credentials are retrieved from the keystore and used only to compute
 *     the Authorization header; they are never returned to the caller.
 *   - Error messages never include credentials.
 *
 * Credential format: Store as "accessKeyId:secretAccessKey".
 * The proxy splits on first ":" at call time.
 * Use "axis add aws" and enter your credential in "accessKeyId:secretAccessKey" format.
 */

import * as crypto from "crypto";
import { SecretStore } from "../vault/keystore.js";
import { fetchWithTimeout } from "./fetchWithTimeout.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface S3GetObjectParams {
  bucket: string;
  key: string;
  region: string;
  [key: string]: unknown;
}

export interface S3PutObjectParams {
  bucket: string;
  key: string;
  region: string;
  body: string;
  [key: string]: unknown;
}

interface ProxyResult {
  ok: true;
  data: unknown;
}

interface ProxyError {
  ok: false;
  error: string;
  status?: number;
}

type ProxyResponse = ProxyResult | ProxyError;

// ---------------------------------------------------------------------------
// Sanitization
// ---------------------------------------------------------------------------

export function sanitizeParams(
  params: Record<string, unknown>
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(params).filter(([k]) => {
      const lower = k.toLowerCase();
      return (
        !lower.includes("key") &&
        !lower.includes("secret") &&
        !lower.includes("token") &&
        !lower.includes("password") &&
        !lower.includes("auth")
      );
    })
  );
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

function requireString(params: Record<string, unknown>, key: string): string {
  const val = params[key];
  if (!val || typeof val !== "string" || val.trim().length === 0) {
    throw new Error(`Required param "${key}" must be a non-empty string.`);
  }
  return val;
}

function requireBaseObject(params: unknown): Record<string, unknown> {
  if (!params || typeof params !== "object" || Array.isArray(params)) {
    throw new Error("Params must be a non-null object.");
  }
  return params as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Per-action validation
// ---------------------------------------------------------------------------

export function validateS3GetObjectParams(params: unknown): S3GetObjectParams {
  const p = requireBaseObject(params);
  requireString(p, "bucket");
  requireString(p, "key");
  requireString(p, "region");
  return p as S3GetObjectParams;
}

export function validateS3PutObjectParams(params: unknown): S3PutObjectParams {
  const p = requireBaseObject(params);
  requireString(p, "bucket");
  requireString(p, "key");
  requireString(p, "region");
  requireString(p, "body");
  return p as S3PutObjectParams;
}

// ---------------------------------------------------------------------------
// SigV4 signing
// ---------------------------------------------------------------------------

function hmacSha256(key: Buffer | string, data: string): Buffer {
  return crypto.createHmac("sha256", key).update(data, "utf8").digest();
}

function sha256Hex(data: string | Buffer): string {
  return crypto
    .createHash("sha256")
    .update(typeof data === "string" ? data : data)
    .digest("hex");
}

function getSigningKey(
  secretAccessKey: string,
  dateStamp: string,
  region: string,
  service: string
): Buffer {
  const kDate = hmacSha256(`AWS4${secretAccessKey}`, dateStamp);
  const kRegion = hmacSha256(kDate, region);
  const kService = hmacSha256(kRegion, service);
  const kSigning = hmacSha256(kService, "aws4_request");
  return kSigning;
}

interface SigV4Options {
  method: string;
  host: string;
  path: string;
  region: string;
  service: string;
  accessKeyId: string;
  secretAccessKey: string;
  body: string;
  extraHeaders?: Record<string, string>;
}

function signRequest(opts: SigV4Options): Record<string, string> {
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "").slice(0, 15) + "Z";
  const dateStamp = amzDate.slice(0, 8);

  const payloadHash = sha256Hex(opts.body);

  const headers: Record<string, string> = {
    host: opts.host,
    "x-amz-date": amzDate,
    "x-amz-content-sha256": payloadHash,
    ...opts.extraHeaders,
  };

  // Canonical headers (sorted)
  const sortedHeaderKeys = Object.keys(headers).sort();
  const canonicalHeaders = sortedHeaderKeys
    .map((k) => `${k}:${headers[k]!.trim()}\n`)
    .join("");
  const signedHeaders = sortedHeaderKeys.join(";");

  // Canonical request
  const canonicalRequest = [
    opts.method,
    opts.path,
    "", // query string (none for s3 get/put basic ops)
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const credentialScope = `${dateStamp}/${opts.region}/${opts.service}/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join("\n");

  const signingKey = getSigningKey(
    opts.secretAccessKey,
    dateStamp,
    opts.region,
    opts.service
  );
  const signature = crypto
    .createHmac("sha256", signingKey)
    .update(stringToSign, "utf8")
    .digest("hex");

  const authorization = `AWS4-HMAC-SHA256 Credential=${opts.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return {
    ...headers,
    Authorization: authorization,
  };
}

// ---------------------------------------------------------------------------
// Shared fetch helper
// ---------------------------------------------------------------------------

async function awsS3Fetch(
  method: string,
  bucket: string,
  objectKey: string,
  region: string,
  accessKeyId: string,
  secretAccessKey: string,
  bodyContent: string
): Promise<ProxyResponse> {
  const host = `${bucket}.s3.${region}.amazonaws.com`;
  const path = '/' + objectKey.split('/').map(encodeURIComponent).join('/');
  const url = `https://${host}${path}`;

  const signedHeaders = signRequest({
    method,
    host,
    path,
    region,
    service: "s3",
    accessKeyId,
    secretAccessKey,
    body: bodyContent,
    ...(method === "PUT" ? { extraHeaders: { "content-type": "application/octet-stream" } } : {}),
  });

  let response: Response;
  try {
    response = await fetchWithTimeout(url, {
      method,
      headers: {
        ...signedHeaders,
        "User-Agent": "axis/0.1.0",
        ...(method === "PUT" ? { "Content-Type": "application/octet-stream" } : {}),
      },
      body: method === "PUT" ? bodyContent : undefined,
    });
  } catch (err: any) {
    if (err?.name === "AbortError") {
      return { ok: false, error: "Request timed out after 30 seconds" };
    }
    const msg = (err as Error).message
      .replace(accessKeyId, "[REDACTED]")
      .replace(secretAccessKey, "[REDACTED]");
    return { ok: false, error: `Network error calling AWS S3: ${msg}` };
  }

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    return {
      ok: false,
      error: `AWS S3 error: HTTP ${response.status}${text ? ` — ${text.slice(0, 200)}` : ""}`,
      status: response.status,
    };
  }

  if (method === "PUT") {
    return { ok: true, data: { uploaded: true, status: response.status } };
  }

  const data = await response.text().catch(() => "");
  return { ok: true, data };
}

// ---------------------------------------------------------------------------
// Action proxy functions
// ---------------------------------------------------------------------------

async function proxyS3GetObject(
  params: unknown,
  keystore: SecretStore
): Promise<ProxyResponse> {
  let validated: S3GetObjectParams;
  try {
    validated = validateS3GetObjectParams(params);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }

  let credential: string;
  try {
    credential = keystore.getSecret("aws");
  } catch (err) {
    return {
      ok: false,
      error: `Could not retrieve AWS secret from keystore: ${(err as Error).message}`,
    };
  }

  const colonIndex = credential.indexOf(":");
  if (colonIndex === -1) {
    credential = "";
    return {
      ok: false,
      error: `AWS credential must be in "accessKeyId:secretAccessKey" format.`,
    };
  }
  const accessKeyId = credential.substring(0, colonIndex);
  let secretAccessKey = credential.substring(colonIndex + 1);
  credential = "";

  try {
    return await awsS3Fetch(
      "GET",
      validated.bucket,
      validated.key,
      validated.region,
      accessKeyId,
      secretAccessKey,
      ""
    );
  } finally {
    secretAccessKey = "";
  }
}

async function proxyS3PutObject(
  params: unknown,
  keystore: SecretStore
): Promise<ProxyResponse> {
  let validated: S3PutObjectParams;
  try {
    validated = validateS3PutObjectParams(params);
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }

  let credential: string;
  try {
    credential = keystore.getSecret("aws");
  } catch (err) {
    return {
      ok: false,
      error: `Could not retrieve AWS secret from keystore: ${(err as Error).message}`,
    };
  }

  const colonIndex = credential.indexOf(":");
  if (colonIndex === -1) {
    credential = "";
    return {
      ok: false,
      error: `AWS credential must be in "accessKeyId:secretAccessKey" format.`,
    };
  }
  const accessKeyId = credential.substring(0, colonIndex);
  let secretAccessKey = credential.substring(colonIndex + 1);
  credential = "";

  try {
    return await awsS3Fetch(
      "PUT",
      validated.bucket,
      validated.key,
      validated.region,
      accessKeyId,
      secretAccessKey,
      validated.body
    );
  } finally {
    secretAccessKey = "";
  }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

export async function proxyAWSAction(
  action: string,
  params: unknown,
  keystore: SecretStore
): Promise<ProxyResponse> {
  switch (action) {
    case "s3.getObject":
      return proxyS3GetObject(params, keystore);
    case "s3.putObject":
      return proxyS3PutObject(params, keystore);
    default:
      return { ok: false, error: `Unsupported AWS action: "${action}".` };
  }
}
