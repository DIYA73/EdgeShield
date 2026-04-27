import type { RateLimitResult } from "../types.js";

export class RateLimiter implements DurableObject {
  private state: DurableObjectState;
  private counts: Map<string, { count: number; windowStart: number }> = new Map();

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const key = url.searchParams.get("key") ?? "default";
    const max = parseInt(url.searchParams.get("max") ?? "100", 10);
    const windowSeconds = parseInt(url.searchParams.get("window") ?? "60", 10);

    const result = await this.checkLimit(key, max, windowSeconds);
    return new Response(JSON.stringify(result), {
      headers: { "Content-Type": "application/json" },
    });
  }

  private async checkLimit(key: string, max: number, windowSeconds: number): Promise<RateLimitResult> {
    const now = Date.now();
    const windowMs = windowSeconds * 1000;

    let entry = this.counts.get(key);
    if (!entry || now - entry.windowStart >= windowMs) {
      entry = { count: 0, windowStart: now };
    }

    entry.count++;
    this.counts.set(key, entry);

    const resetAt = entry.windowStart + windowMs;
    const remaining = Math.max(0, max - entry.count);

    if (entry.count > max) {
      return {
        allowed: false,
        remaining: 0,
        resetAt,
        retryAfter: Math.ceil((resetAt - now) / 1000),
      };
    }

    return { allowed: true, remaining, resetAt };
  }
}

export async function checkRateLimit(
  namespace: DurableObjectNamespace,
  ip: string,
  path: string,
  max: number,
  windowSeconds: number
): Promise<RateLimitResult> {
  // Use IP + path prefix as the rate limit key
  const pathPrefix = path.split("/").slice(0, 3).join("/");
  const key = `${ip}:${pathPrefix}`;

  const id = namespace.idFromName(key);
  const stub = namespace.get(id);

  const params = new URLSearchParams({ key, max: String(max), window: String(windowSeconds) });
  const res = await stub.fetch(`http://internal/check?${params}`);
  return res.json<RateLimitResult>();
}
