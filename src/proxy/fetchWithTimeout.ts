export async function fetchWithTimeout(
  url: string | URL | Request,
  init?: RequestInit & { timeoutMs?: number },
): Promise<Response> {
  const ms = init?.timeoutMs ?? 30_000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}
