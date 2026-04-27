import { Hono } from "hono";
import type { Env, ThreatContext } from "./types.js";
import { RulesEngine } from "./rules/engine.js";
import { analyzeBotSignals, botScore } from "./fingerprint/bot.js";
import { getIpReputation } from "./fingerprint/reputation.js";
import { checkRateLimit } from "./ratelimit/limiter.js";
import { mlScore, loadWeights } from "./ml/scorer.js";
import { buildThreatEvent, publishThreatEvent } from "./pipeline/threat.js";
import { adminRoutes } from "./admin/routes.js";
import owaspRules from "../rules/owasp-core.json" assert { type: "json" };

export { RateLimiter } from "./ratelimit/limiter.js";
export { ThreatEventBus } from "./pipeline/threat.js";

const app = new Hono<{ Bindings: Env }>();
const engine = new RulesEngine();
engine.load(owaspRules as any);

// ── Health check ──────────────────────────────────────────────────────────────
app.get("/health", (c) => c.json({ status: "ok", version: "1.1.0" }));

// ── Dashboard ─────────────────────────────────────────────────────────────────
app.get("/dashboard", async (c) => {
  const asset = await c.env.ASSETS.fetch(new Request("http://assets/dashboard.html"));
  return new Response(asset.body, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
});

// ── Threat map WebSocket ───────────────────────────────────────────────────────
app.get("/ws/threats", async (c) => {
  if (c.req.header("Upgrade") !== "websocket") {
    return c.text("Expected WebSocket upgrade", 426);
  }
  const id = c.env.THREAT_EVENTS.idFromName("global");
  const stub = c.env.THREAT_EVENTS.get(id);
  return stub.fetch(new Request("http://internal/subscribe", c.req.raw));
});

// ── Admin API (key-protected) ─────────────────────────────────────────────────
app.route("/admin", adminRoutes);

// ── WAF middleware (runs on every request) ────────────────────────────────────
app.use("/*", async (c, next) => {
  // Load model weights from KV on first warm request (cached per isolate)
  await loadWeights(c.env.WAF_RULES);
  const req = c.req.raw;
  const cf = (req as any).cf as IncomingRequestCfProperties | undefined;
  const url = new URL(req.url);

  const ip = c.req.header("cf-connecting-ip") ?? c.req.header("x-forwarded-for") ?? "0.0.0.0";
  const country = cf?.country ?? c.req.header("cf-ipcountry") ?? "XX";
  const requestId = crypto.randomUUID();

  // 1. IP reputation (runs in parallel with other checks)
  const [ipRep, ruleMatches] = await Promise.all([
    getIpReputation(ip, cf, c.env.WAF_RULES),
    engine.evaluate(req),
  ]);

  // Hard-block explicitly blocklisted IPs before doing any further work
  if (ipRep.isBlocklisted) {
    return c.json({ error: "Forbidden", requestId, reason: "IP blocklisted" }, 403);
  }

  // 2. Bot fingerprinting
  const botSignals = analyzeBotSignals(req, cf);
  const botThreatScore = botScore(botSignals);

  // 3. ML scoring (MLP with 12 features)
  const score = mlScore(
    botSignals,
    ruleMatches,
    url,
    ipRep.score,
    ipRep.cfThreatScore,
    req.method
  );

  // 4. Rate limit — adaptive: high-threat IPs get tighter windows
  const rl = await checkRateLimit(
    c.env.RATE_LIMITER,
    ip,
    url.pathname,
    parseInt(c.env.RATE_LIMIT_MAX_REQUESTS, 10),
    parseInt(c.env.RATE_LIMIT_WINDOW_SECONDS, 10),
    score
  );

  if (!rl.allowed) {
    c.header("Retry-After", String(rl.retryAfter ?? 60));
    c.header("X-RateLimit-Remaining", "0");
    return c.text("Too Many Requests", 429);
  }

  c.header("X-RateLimit-Remaining", String(rl.remaining));

  // 5. Resolve decision
  const { action: ruleAction, totalScore: ruleScore } = engine.resolveAction(ruleMatches);
  const blockThreshold = parseFloat(c.env.THREAT_SCORE_BLOCK_THRESHOLD);
  const challengeThreshold = parseFloat(c.env.THREAT_SCORE_CHALLENGE_THRESHOLD);

  let decision: ThreatContext["decision"] = "allow";
  if (ruleAction === "block" || score >= blockThreshold) decision = "block";
  else if (ruleAction === "challenge" || score >= challengeThreshold) decision = "challenge";
  else if (ruleAction === "log") decision = "log";

  const ctx: ThreatContext = {
    ip, country,
    userAgent: c.req.header("user-agent") ?? "",
    path: url.pathname,
    method: req.method,
    timestamp: Date.now(),
    ruleMatches,
    botSignals,
    mlScore: score,
    totalScore: ruleScore,
    decision,
    requestId,
  };

  // 6. Publish to threat bus + increment stats (fire-and-forget)
  if (decision !== "allow" || ruleMatches.length > 0 || botThreatScore > 0.6) {
    const event = buildThreatEvent(ctx, cf);
    Promise.all([
      publishThreatEvent(c.env.THREAT_EVENTS, event),
      incrementStat(c.env.WAF_RULES, decision),
    ]).catch(() => {});
  }
  incrementStat(c.env.WAF_RULES, "total").catch(() => {});

  // 7. Enforce decision
  c.header("X-EdgeShield-Score", score.toFixed(3));
  c.header("X-EdgeShield-Decision", decision);
  c.header("X-Request-Id", requestId);

  if (decision === "block") {
    return c.json(
      { error: "Forbidden", requestId, reason: ruleMatches[0]?.ruleName ?? "Threat score exceeded" },
      403
    );
  }
  if (decision === "challenge") {
    return c.json({ error: "Challenge required", requestId }, 403);
  }

  await next();
});

// ── Catch-all proxy placeholder ────────────────────────────────────────────────
app.all("/*", (c) => c.text("EdgeShield: request passed", 200));

async function incrementStat(kv: KVNamespace, key: string): Promise<void> {
  const statKey = key === "total" ? "stats:total"
    : key === "block" ? "stats:blocked"
    : key === "challenge" ? "stats:challenged"
    : null;
  if (!statKey) return;
  const current = parseInt((await kv.get(statKey)) ?? "0", 10);
  await kv.put(statKey, String(current + 1));
}

export default app;
