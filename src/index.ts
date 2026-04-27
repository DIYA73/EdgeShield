import { Hono } from "hono";
import type { Env, ThreatContext } from "./types.js";
import { RulesEngine } from "./rules/engine.js";
import { analyzeBotSignals, botScore } from "./fingerprint/bot.js";
import { checkRateLimit } from "./ratelimit/limiter.js";
import { mlScore } from "./ml/scorer.js";
import { buildThreatEvent, publishThreatEvent } from "./pipeline/threat.js";
import owaspRules from "../rules/owasp-core.json" assert { type: "json" };

export { RateLimiter } from "./ratelimit/limiter.js";
export { ThreatEventBus } from "./pipeline/threat.js";

const app = new Hono<{ Bindings: Env }>();
const engine = new RulesEngine();
engine.load(owaspRules as any);

// ── Health check ─────────────────────────────────────────────────────────────
app.get("/health", (c) => c.json({ status: "ok", version: "1.0.0" }));

// ── Threat map WebSocket subscription ────────────────────────────────────────
app.get("/ws/threats", async (c) => {
  const upgradeHeader = c.req.header("Upgrade");
  if (upgradeHeader !== "websocket") {
    return c.text("Expected WebSocket upgrade", 426);
  }
  const id = c.env.THREAT_EVENTS.idFromName("global");
  const stub = c.env.THREAT_EVENTS.get(id);
  return stub.fetch(c.req.raw);
});

// ── Admin: reload rules from KV ───────────────────────────────────────────────
app.post("/admin/rules/reload", async (c) => {
  const rulesJson = await c.env.WAF_RULES.get("owasp-core");
  if (rulesJson) {
    engine.load(JSON.parse(rulesJson));
    return c.json({ reloaded: true });
  }
  return c.json({ reloaded: false, reason: "No rules in KV" }, 404);
});

// ── WAF middleware (runs on every proxied request) ────────────────────────────
app.use("/*", async (c, next) => {
  const req = c.req.raw;
  const cf = (req as any).cf as IncomingRequestCfProperties | undefined;
  const url = new URL(req.url);

  const ip = c.req.header("cf-connecting-ip") ?? c.req.header("x-forwarded-for") ?? "0.0.0.0";
  const country = cf?.country ?? c.req.header("cf-ipcountry") ?? "XX";
  const requestId = crypto.randomUUID();

  // 1. Rate limit check
  const rl = await checkRateLimit(
    c.env.RATE_LIMITER,
    ip,
    url.pathname,
    parseInt(c.env.RATE_LIMIT_MAX_REQUESTS, 10),
    parseInt(c.env.RATE_LIMIT_WINDOW_SECONDS, 10)
  );

  if (!rl.allowed) {
    c.header("Retry-After", String(rl.retryAfter ?? 60));
    c.header("X-RateLimit-Remaining", "0");
    c.header("X-RateLimit-Reset", String(Math.floor(rl.resetAt / 1000)));
    return c.text("Too Many Requests", 429);
  }

  c.header("X-RateLimit-Remaining", String(rl.remaining));

  // 2. WAF rules evaluation
  const ruleMatches = await engine.evaluate(req);
  const { action: ruleAction, totalScore: ruleScore } = engine.resolveAction(ruleMatches);

  // 3. Bot fingerprinting
  const botSignals = analyzeBotSignals(req, cf);
  const botThreatScore = botScore(botSignals);

  // 4. ML scoring
  const score = mlScore(botSignals, ruleMatches, url);

  const blockThreshold = parseFloat(c.env.THREAT_SCORE_BLOCK_THRESHOLD);
  const challengeThreshold = parseFloat(c.env.THREAT_SCORE_CHALLENGE_THRESHOLD);

  let decision: ThreatContext["decision"] = "allow";
  if (ruleAction === "block" || score >= blockThreshold) {
    decision = "block";
  } else if (ruleAction === "challenge" || score >= challengeThreshold) {
    decision = "challenge";
  } else if (ruleAction === "log") {
    decision = "log";
  }

  const ctx: ThreatContext = {
    ip,
    country,
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

  // 5. Publish threat events for non-clean requests (fire-and-forget)
  if (decision !== "allow" || ruleMatches.length > 0 || botThreatScore > 0.6) {
    const event = buildThreatEvent(ctx, cf);
    publishThreatEvent(c.env.THREAT_EVENTS, event).catch(() => {});
  }

  // 6. Enforce decision
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
    // In production, redirect to a CAPTCHA or JS challenge page
    return c.json({ error: "Challenge required", requestId }, 403);
  }

  await next();
});

// ── Catch-all proxy ───────────────────────────────────────────────────────────
app.all("/*", (c) => c.text("EdgeShield: request passed", 200));

export default app;
