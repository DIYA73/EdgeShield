import { Hono } from "hono";
import type { Env } from "../types.js";

const admin = new Hono<{ Bindings: Env }>();

// API key auth on all /admin routes
admin.use("/*", async (c, next) => {
  const key = c.req.header("x-admin-key");
  if (!key || key !== c.env.ADMIN_API_KEY) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  await next();
});

// GET /admin/stats
admin.get("/stats", async (c) => {
  const [blocked, challenged, totalRequests] = await Promise.all([
    c.env.WAF_RULES.get("stats:blocked").then((v) => parseInt(v ?? "0", 10)),
    c.env.WAF_RULES.get("stats:challenged").then((v) => parseInt(v ?? "0", 10)),
    c.env.WAF_RULES.get("stats:total").then((v) => parseInt(v ?? "0", 10)),
  ]);
  return c.json({ blocked, challenged, totalRequests, blockRate: totalRequests ? blocked / totalRequests : 0 });
});

// GET /admin/rules
admin.get("/rules", async (c) => {
  const rules = await c.env.WAF_RULES.get("owasp-core");
  if (!rules) return c.json({ error: "No rules found" }, 404);
  return c.json(JSON.parse(rules));
});

// POST /admin/rules/reload — hot-swap rules without redeploy
admin.post("/rules/reload", async (c) => {
  const body = await c.req.json().catch(() => null);
  if (body) {
    await c.env.WAF_RULES.put("owasp-core", JSON.stringify(body));
    return c.json({ reloaded: true, ruleCount: body.length });
  }
  return c.json({ error: "Invalid JSON body" }, 400);
});

// GET /admin/blocklist
admin.get("/blocklist", async (c) => {
  const list = await c.env.WAF_RULES.list({ prefix: "blocklist:" });
  const ips = list.keys.map((k) => k.name.replace("blocklist:", ""));
  return c.json({ ips, count: ips.length });
});

// POST /admin/blocklist  { "ip": "1.2.3.4", "reason": "manual" }
admin.post("/blocklist", async (c) => {
  const { ip, reason } = await c.req.json<{ ip: string; reason?: string }>();
  if (!ip) return c.json({ error: "ip required" }, 400);
  await c.env.WAF_RULES.put(`blocklist:${ip}`, reason ?? "manual", {
    expirationTtl: 86400 * 7, // 7 days
  });
  return c.json({ blocked: ip });
});

// DELETE /admin/blocklist/:ip
admin.delete("/blocklist/:ip", async (c) => {
  const ip = c.req.param("ip");
  await c.env.WAF_RULES.delete(`blocklist:${ip}`);
  return c.json({ unblocked: ip });
});

export { admin as adminRoutes };
