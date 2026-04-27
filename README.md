# EdgeShield

Distributed Web Application Firewall and bot detection system running at the network edge on Cloudflare Workers. Evaluates every request through a layered pipeline — WAF rules, bot fingerprinting, IP reputation, and ML scoring — in under 5ms before it reaches your origin.

## Architecture

```
Client Request
      │
      ▼
┌─────────────────────────────────────────────────┐
│              EdgeShield Edge Layer               │
│          (Cloudflare Worker ~300 PoPs)           │
│                                                  │
│  ┌──────────┐  ┌────────────┐  ┌─────────────┐  │
│  │ IP Rep   │  │ WAF Rules  │  │    Bot      │  │
│  │ + KV     │  │ Engine     │  │ Fingerprint │  │
│  │ Blocklist│  │ (12 rules) │  │ (UA/ASN/hdr)│  │
│  └────┬─────┘  └─────┬──────┘  └──────┬──────┘  │
│       └──────────────┼─────────────────┘         │
│                      ▼                           │
│              ┌───────────────┐                   │
│              │  MLP Scorer   │                   │
│              │  12→4→1 net   │                   │
│              │  KV-loadable  │                   │
│              └───────┬───────┘                   │
│                      ▼                           │
│           ┌─────────────────────┐                │
│           │  Adaptive Rate      │                │
│           │  Guardian (DO)      │                │
│           │  per-route + threat │                │
│           └──────────┬──────────┘                │
└──────────────────────┼──────────────────────────┘
                       │ allow / block / challenge
                       ▼
                 Origin Server
                       │
                       ▼
            ┌──────────────────┐
            │  Threat Event    │
            │  Bus (DO + WS)   │──► Real-Time Threat Map
            └──────────────────┘
```

## Features

| Layer | What it does |
|---|---|
| **WAF Rules Engine** | 12 OWASP CRS-style regex rules: SQLi, XSS, path traversal, SSRF, RFI, command injection, web shells. Rules are hot-reloadable from KV without redeploy. |
| **Bot Fingerprinter** | Detects scanners, headless browsers, missing browser headers, and datacenter ASNs. Produces a 0–1 UA score. |
| **IP Reputation** | Checks Cloudflare's `cf.threatScore`, a KV-managed blocklist, malicious ASNs, and known bad IP prefixes. |
| **MLP Threat Scorer** | 12-feature → 4 hidden (ReLU) → 1 output (sigmoid) neural network. Weights are stored in KV and hot-swappable without redeployment. |
| **Adaptive Rate Guardian** | Sliding-window rate limiter with per-route limits and threat-adaptive tightening. A 0.9-score IP gets 10% of the normal limit. Backed by Durable Objects for strong consistency. |
| **Threat Event Bus** | Durable Object WebSocket fan-out that streams live threat events to all connected dashboard clients. |
| **Real-Time Threat Map** | Leaflet dashboard at `/dashboard` showing live attack markers, live feed, and stats. Includes an admin panel for blocklist and rule management. |

## Request Pipeline

Every request is processed in this order:

1. **IP Reputation** — hard-block KV-listed IPs instantly; score the rest
2. **WAF Rules** — evaluate against 12 OWASP regex rules, accumulate score
3. **Bot Fingerprinting** — UA analysis, header anomalies, ASN classification
4. **ML Scoring** — forward pass through the MLP with all signals combined
5. **Rate Limiting** — adaptive window check, per-route limits applied
6. **Decision** — `block` → 403, `challenge` → 403 (CAPTCHA in production), `log` → pass with header, `allow` → pass
7. **Threat Bus** — publish event to WebSocket subscribers (fire-and-forget)

Total added latency at the edge: **~2–5ms** (p99).

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `GET` | `/dashboard` | Real-time threat map + admin panel |
| `GET` | `/ws/threats` | WebSocket threat event stream |
| `GET` | `/admin/stats` | Block/challenge/total counts |
| `GET` | `/admin/rules` | Current WAF ruleset |
| `POST` | `/admin/rules/reload` | Hot-swap rules (send new ruleset as JSON body) |
| `GET` | `/admin/blocklist` | List blocked IPs |
| `POST` | `/admin/blocklist` | Block an IP `{"ip":"1.2.3.4","reason":"..."}` |
| `DELETE` | `/admin/blocklist/:ip` | Unblock an IP |

All `/admin/*` routes require `X-Admin-Key` header.

Response headers on every request:

```
X-EdgeShield-Score: 0.043
X-EdgeShield-Decision: allow
X-Request-Id: <uuid>
X-RateLimit-Remaining: 97
```

## Local Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Local dev server (uses Miniflare)
npm run dev
```

## Deployment

### Prerequisites

- [Cloudflare account](https://dash.cloudflare.com) (free tier works)
- Node.js 18+
- Wrangler CLI (installed via `npm install`)

### Steps

**1. Authenticate**
```bash
npx wrangler login
```

**2. Create KV namespace**
```bash
npx wrangler kv namespace create WAF_RULES
npx wrangler kv namespace create WAF_RULES --preview
```
Copy the IDs into `wrangler.toml`.

**3. Upload rules and model weights**
```bash
npx wrangler kv key put --remote "owasp-core" --path=rules/owasp-core.json \
  --namespace-id=<YOUR_KV_ID>

npx wrangler kv key put --remote "model:mlp-v1" --path=model/weights.json \
  --namespace-id=<YOUR_KV_ID>
```

**4. Set your admin key**

Edit `wrangler.toml`:
```toml
[vars]
ADMIN_API_KEY = "your-secret-key-here"
```

Or use a Wrangler secret (recommended for production):
```bash
npx wrangler secret put ADMIN_API_KEY
```

**5. Deploy**
```bash
npm run deploy
```

Your Worker is live at `https://edgeshield.<your-subdomain>.workers.dev`.

### Updating the ML Model

```bash
# Train a new model (requires Python + scikit-learn)
pip install scikit-learn numpy
python scripts/train_model.py

# Upload new weights — takes effect on the next Worker cold start
npx wrangler kv key put --remote "model:mlp-v1" --path=model/weights.json \
  --namespace-id=<YOUR_KV_ID>
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `THREAT_SCORE_BLOCK_THRESHOLD` | `0.8` | ML score above which requests are blocked |
| `THREAT_SCORE_CHALLENGE_THRESHOLD` | `0.5` | ML score above which requests are challenged |
| `RATE_LIMIT_MAX_REQUESTS` | `100` | Default requests per window |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate limit window duration |
| `ADMIN_API_KEY` | — | Required. Key for all `/admin/*` routes |

## Per-Route Rate Limits

| Route prefix | Limit (req/window) |
|---|---|
| `/login` | 10 |
| `/admin` | 20 |
| `/ws` | 5 |
| `/api` | 200 |
| `/*` (default) | env var |

High-threat IPs are automatically throttled: a request with ML score `s` gets `max × (1 − 0.9s)` of the normal limit.

## WAF Rules

| ID | Attack Type | Score | Action |
|---|---|---|---|
| `sqli-001` | SQL Injection — UNION SELECT | 70 | block |
| `sqli-002` | SQL Injection — Boolean Blind | 60 | block |
| `sqli-003` | SQL Injection — DDL Keywords | 80 | block |
| `xss-001` | XSS — Script Tag | 65 | block |
| `xss-002` | XSS — Event Handler | 55 | block |
| `xss-003` | XSS — javascript: Protocol | 60 | block |
| `traversal-001` | Path Traversal | 70 | block |
| `rfi-001` | Remote File Inclusion | 75 | block |
| `cmd-001` | Command Injection | 80 | block |
| `scanner-001` | Security Scanner UA | 50 | log |
| `shell-001` | Web Shell Signature | 90 | block |
| `ssrf-001` | SSRF — Internal Addresses | 65 | block |

Rules scoring ≥ 100 cumulative are always blocked regardless of individual actions.

## Tech Stack

- **Runtime**: Cloudflare Workers (V8 isolates)
- **Router**: Hono.js
- **Storage**: Cloudflare KV (rules, blocklist, model weights, stats)
- **State**: Durable Objects (rate limiter counters, WebSocket bus)
- **ML**: Hand-forward MLP (no framework — pure TypeScript)
- **Dashboard**: Vanilla JS + Leaflet + Tailwind CDN
- **Tests**: Vitest (24 unit tests)
- **Deploy**: Wrangler CLI
