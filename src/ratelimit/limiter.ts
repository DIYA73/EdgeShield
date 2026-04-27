import type { RateLimitResult } from "../types.js";

// Per-route request limits (requests per window)
const ROUTE_LIMITS: { prefix: string; max: number }[] = [
  { prefix: "/admin",   max: 20  },
  { prefix: "/login",   max: 10  },
  { prefix: "/api",     max: 200 },
  { prefix: "/ws",      max: 5   },
];

function routeMax(path: string, defaultMax: number): number {
  const match = ROUTE_LIMITS.find((r) => path.startsWith(r.prefix));
  return match?.max ?? defaultMax;
}

// High-threat IPs get tighter limits: threat score 0→1 maps to multiplier 1→0.1
function adaptiveMultiplier(threatScore: number): number {
  return Math.max(0.1, 1 - threatScore * 0.9);
}

export class RateLimiter implements DurableObject {
  private state: DurableObjectState;
  private counts: Map<string, { count: number; windowStart: number }> = new Map();

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const key = url.searchParams.get("key") ?? "default";
    const defaultMax = parseInt(url.searchParams.get("max") ?? "100", 10);
    const windowSeconds = parseInt(url.searchParams.get("window") ?? "60", 10);
    const path = url.searchParams.get("path") ?? "/";
    const threatScore = parseFloat(url.searchParams.get("threat") ?? "0");

    const effectiveMax = Math.floor(
      routeMax(path, defaultMax) * adaptiveMultiplier(threatScore)
    );

    const result = await this.checkLimit(key, effectiveMax, windowSeconds);
    return new Response(JSON.stringify({ ...result, effectiveMax }), {
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
      return { allowed: false, remaining: 0, resetAt, retryAfter: Math.ceil((resetAt - now) / 1000) };
    }

    return { allowed: true, remaining, resetAt };
  }
}

export async function checkRateLimit(
  namespace: DurableObjectNamespace,
  ip: string,
  path: string,
  defaultMax: number,
  windowSeconds: number,
  threatScore = 0
): Promise<RateLimitResult> {
  const pathPrefix = path.split("/").slice(0, 3).join("/");
  const key = `${ip}:${pathPrefix}`;

  const id = namespace.idFromName(key);
  const stub = namespace.get(id);

  const params = new URLSearchParams({
    key,
    max: String(defaultMax),
    window: String(windowSeconds),
    path,
    threat: threatScore.toFixed(3),
  });

  const res = await stub.fetch(`http://internal/check?${params}`);
  return res.json<RateLimitResult>();
}
